//! DS-032 organization-scoped Audit query contract through the real Gateway
//! and an isolated PostgreSQL database.

mod support;

use atf_core::Timestamp;
use atf_gateway::build_router;
use atf_store::{OperatorRole, OperatorStatus};
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use std::error::Error;
use tower::ServiceExt;

use support::{
    body_json, error_json, operator_authorization, post_intent_request, test_state, TestDatabase,
};

#[tokio::test]
async fn filters_and_snapshot_cursor_return_a_stable_verified_organization_page(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("audit_query_page").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    let first_intent = "01J0000000000000000000AQ01";
    let second_intent = "01J0000000000000000000AQ02";
    let later_intent = "01J0000000000000000000AQ03";

    assert_eq!(
        app.clone()
            .oneshot(post_intent_request(first_intent, "12.50"))
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(post_intent_request(second_intent, "12.50"))
            .await?
            .status(),
        StatusCode::OK
    );

    let default_page = successful_json(
        app.clone()
            .oneshot(audit_request(
                "/v1/audit/events?event_type=DecisionRecorded",
                "alpha-lab",
            ))
            .await?,
    )
    .await?;
    assert_eq!(default_page["pagination"]["limit"], 50);
    assert_eq!(default_page["events"].as_array().unwrap().len(), 2);

    let first_page = successful_json(
        app.clone()
            .oneshot(audit_request(
                "/v1/audit/events?event_type=DecisionRecorded&limit=1",
                "alpha-lab",
            ))
            .await?,
    )
    .await?;
    assert_eq!(first_page["schema_version"], 1);
    assert_eq!(first_page["organization_id"], "alpha-lab");
    assert_eq!(first_page["chain"]["status"], "VERIFIED");
    assert_eq!(first_page["pagination"]["order"], "SEQUENCE_ASC");
    assert_eq!(first_page["pagination"]["limit"], 1);
    let through_sequence = first_page["chain"]["through_sequence"]
        .as_i64()
        .expect("chain boundary is an integer");
    let through_hash = first_page["chain"]["through_event_hash"]
        .as_str()
        .expect("non-empty chain has a tail hash")
        .to_owned();
    let first_event = &first_page["events"][0];
    assert_eq!(first_event["event"]["intent_id"], first_intent);
    assert_eq!(first_event["event"]["event_type"], "DecisionRecorded");
    assert_eq!(first_event["event_hash"].as_str().unwrap().len(), 64);
    let cursor = first_page["pagination"]["next_cursor"]
        .as_str()
        .expect("another matching event exists")
        .to_owned();

    assert_eq!(
        app.clone()
            .oneshot(post_intent_request(later_intent, "12.50"))
            .await?
            .status(),
        StatusCode::OK
    );

    let second_page = successful_json(
        app.clone()
            .oneshot(audit_request(
                &format!("/v1/audit/events?event_type=DecisionRecorded&limit=1&cursor={cursor}"),
                "alpha-lab",
            ))
            .await?,
    )
    .await?;
    assert_eq!(second_page["chain"]["through_sequence"], through_sequence);
    assert_eq!(second_page["chain"]["through_event_hash"], through_hash);
    assert_eq!(
        second_page["events"][0]["event"]["intent_id"],
        second_intent
    );
    assert!(second_page["pagination"]["next_cursor"].is_null());

    let occurred_at = second_page["events"][0]["event"]["occurred_at"]
        .as_str()
        .expect("Audit event has a timestamp");
    let filtered = successful_json(
        app.clone()
            .oneshot(audit_request(
                &format!(
                    "/v1/audit/events?intent_id={second_intent}&agent_id=research-agent-01&event_type=DecisionRecorded&occurred_from={occurred_at}&occurred_to={occurred_at}&limit=10"
                ),
                "alpha-lab",
            ))
            .await?,
    )
    .await?;
    assert_eq!(filtered["events"].as_array().unwrap().len(), 1);
    assert_eq!(filtered["events"][0]["event"]["intent_id"], second_intent);

    let intent_route = successful_json(
        app.oneshot(audit_request(
            &format!("/v1/audit/intents/{second_intent}?event_type=DecisionRecorded&limit=10"),
            "alpha-lab",
        ))
        .await?,
    )
    .await?;
    assert_eq!(intent_route["events"].as_array().unwrap().len(), 1);
    assert_eq!(
        intent_route["events"][0]["event"]["intent_id"],
        second_intent
    );

    let chain = store.load_verified_audit_chain("alpha-lab").await?;
    let snapshot_tail = chain
        .iter()
        .find(|event| event.sequence == through_sequence)
        .expect("cursor snapshot tail remains in the verified chain");
    assert_eq!(snapshot_tail.event_hash, through_hash);

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn malformed_or_unbounded_queries_and_rebound_cursors_are_rejected(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("audit_query_invalid").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    for intent_id in ["01J0000000000000000000AQ11", "01J0000000000000000000AQ12"] {
        assert_eq!(
            app.clone()
                .oneshot(post_intent_request(intent_id, "12.50"))
                .await?
                .status(),
            StatusCode::OK
        );
    }

    for path in [
        "/v1/audit/events?limit=0",
        "/v1/audit/events?limit=101",
        "/v1/audit/events?event_type=UnknownEvent&limit=10",
        "/v1/audit/events?unknown_filter=value&limit=10",
        "/v1/audit/events?occurred_from=not-a-time&limit=10",
        "/v1/audit/events?occurred_from=2026-08-09T02:00:00.000Z&occurred_to=2026-08-09T01:00:00.000Z&limit=10",
        "/v1/audit/events?cursor=not-a-canonical-cursor&limit=10",
    ] {
        let response = app
            .clone()
            .oneshot(audit_request(path, "alpha-lab"))
            .await?;
        error_json(response, StatusCode::BAD_REQUEST, "AUDIT_QUERY_INVALID").await?;
    }

    let page = successful_json(
        app.clone()
            .oneshot(audit_request(
                "/v1/audit/events?event_type=DecisionRecorded&limit=1",
                "alpha-lab",
            ))
            .await?,
    )
    .await?;
    let cursor = page["pagination"]["next_cursor"]
        .as_str()
        .expect("two Decisions produce another page");
    let response = app
        .oneshot(audit_request(
            &format!("/v1/audit/events?event_type=RiskEvaluated&limit=1&cursor={cursor}"),
            "alpha-lab",
        ))
        .await?;
    error_json(response, StatusCode::BAD_REQUEST, "AUDIT_QUERY_INVALID").await?;

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn audit_queries_require_a_current_tenant_role_and_disjoint_operator_principal(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("audit_query_auth").await?;
    database.seed_organization("beta-lab").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/audit/events?limit=10")
                .header("x-atf-organization-id", "alpha-lab")
                .body(Body::empty())?,
        )
        .await?;
    error_json(
        response,
        StatusCode::UNAUTHORIZED,
        "AUTHENTICATION_REQUIRED",
    )
    .await?;

    let response = app
        .clone()
        .oneshot(audit_request("/v1/audit/events?limit=10", "beta-lab"))
        .await?;
    error_json(response, StatusCode::NOT_FOUND, "AUDIT_EVENTS_NOT_FOUND").await?;

    let mut agent_request = post_intent_request("01J0000000000000000000AQ21", "12.50");
    *agent_request.method_mut() = Method::GET;
    *agent_request.uri_mut() = "/v1/audit/events?limit=10".parse()?;
    agent_request
        .headers_mut()
        .insert("x-atf-organization-id", "alpha-lab".parse()?);
    let response = app.clone().oneshot(agent_request).await?;
    error_json(
        response,
        StatusCode::UNAUTHORIZED,
        "AUTHENTICATION_REQUIRED",
    )
    .await?;

    let changed_at: Timestamp = Timestamp::now_millis();
    store
        .revoke_operator_role(
            "operator-1",
            "alpha-lab",
            OperatorRole::Auditor,
            "test-db-admin",
            "ACCESS_REMOVED",
            changed_at,
        )
        .await?;
    store
        .grant_operator_role(
            "operator-1",
            "alpha-lab",
            OperatorRole::Approver,
            "test-db-admin",
            "APPROVAL_ONLY",
            changed_at,
        )
        .await?;
    let response = app
        .clone()
        .oneshot(audit_request("/v1/audit/events?limit=10", "alpha-lab"))
        .await?;
    error_json(response, StatusCode::NOT_FOUND, "AUDIT_EVENTS_NOT_FOUND").await?;

    store
        .set_operator_status(
            "operator-1",
            OperatorStatus::Disabled,
            "test-db-admin",
            "INCIDENT_RESPONSE",
            changed_at,
        )
        .await?;
    let response = app
        .oneshot(audit_request("/v1/audit/events?limit=10", "alpha-lab"))
        .await?;
    error_json(
        response,
        StatusCode::UNAUTHORIZED,
        "AUTHENTICATION_REQUIRED",
    )
    .await?;

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn query_fails_closed_when_any_row_in_the_declared_chain_is_corrupt(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("audit_query_corrupt").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    let chain = store.load_verified_audit_chain("alpha-lab").await?;
    let sequence = chain
        .first()
        .expect("provisioning creates Audit evidence")
        .sequence;
    database
        .corrupt_audit_event_for_test("alpha-lab", sequence)
        .await?;

    let response = app
        .oneshot(audit_request("/v1/audit/events?limit=10", "alpha-lab"))
        .await?;
    error_json(
        response,
        StatusCode::INTERNAL_SERVER_ERROR,
        "DURABLE_STATE_INTEGRITY_ERROR",
    )
    .await?;

    store.close().await;
    database.destroy().await?;
    Ok(())
}

fn audit_request(path_and_query: &str, organization_id: &str) -> Request<Body> {
    Request::builder()
        .uri(path_and_query)
        .header("x-atf-organization-id", organization_id)
        .header("authorization", operator_authorization())
        .body(Body::empty())
        .expect("Audit query request is valid")
}

async fn successful_json(
    response: axum::response::Response,
) -> Result<serde_json::Value, Box<dyn Error>> {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/json"
    );
    body_json(response).await
}

async fn provisioned_database(label: &str) -> Result<TestDatabase, Box<dyn Error>> {
    let database = TestDatabase::create(label).await?;
    database.seed_organization("alpha-lab").await?;
    Ok(database)
}
