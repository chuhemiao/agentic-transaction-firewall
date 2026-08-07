//! End-to-end tests of the Gateway HTTP surface through a real, isolated
//! PostgreSQL database and `tower::ServiceExt::oneshot`.

mod common;

use atf_audit::EventType;
use atf_core::IntentLifecycleState;
use atf_gateway::build_router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::error::Error;
use tower::ServiceExt;

use common::{
    body_json, error_json, get_decision_request, post_intent_request, sample_intent_json,
    test_state, TestDatabase,
};

#[tokio::test]
async fn healthz_and_readyz_report_ok() -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("health").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .clone()
        .oneshot(Request::builder().uri("/healthz").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("x-atf-request-id"));

    let response = app
        .oneshot(Request::builder().uri("/readyz").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("x-atf-request-id"));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn every_response_uses_a_server_generated_request_id() -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("request_id").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    let mut request = post_intent_request("01J0000000000000000000R100", "12.50");
    request
        .headers_mut()
        .insert("x-atf-request-id", "caller-controlled".parse()?);

    let response = app.oneshot(request).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let request_id = response
        .headers()
        .get("x-atf-request-id")
        .expect("success responses carry the server request ID")
        .to_str()?;
    assert_ne!(request_id, "caller-controlled");
    assert_eq!(request_id.len(), 26);

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn router_level_failures_use_the_same_error_contract() -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("router_errors").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .clone()
        .oneshot(Request::builder().uri("/v1/unknown").body(Body::empty())?)
        .await?;
    error_json(response, StatusCode::NOT_FOUND, "ROUTE_NOT_FOUND").await?;

    let response = app
        .oneshot(
            Request::builder()
                .method("DELETE")
                .uri("/v1/intents")
                .body(Body::empty())?,
        )
        .await?;
    error_json(
        response,
        StatusCode::METHOD_NOT_ALLOWED,
        "METHOD_NOT_ALLOWED",
    )
    .await?;

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn posting_an_in_budget_intent_persists_decision_audit_and_evidence(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("permit").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .oneshot(post_intent_request("01J0000000000000000000G100", "12.50"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let decision = body_json(response).await?;
    assert_eq!(decision["decision"], "PERMIT");
    assert_eq!(decision["intent_id"], "01J0000000000000000000G100");

    let chain = store.load_verified_audit_chain("alpha-lab").await?;
    let event_types: Vec<EventType> = chain.iter().map(|stored| stored.event.event_type).collect();
    assert_eq!(
        event_types,
        vec![
            EventType::IntentReceived,
            EventType::IdentityVerificationSkipped,
            EventType::PolicyEvaluated,
            EventType::RiskEvaluated,
            EventType::SimulationCompleted,
            EventType::DecisionRecorded,
        ]
    );
    let recorded = &chain.last().unwrap().event;
    assert_eq!(recorded.data["decision"], "PERMIT");
    assert_eq!(recorded.data["organization_id"], "alpha-lab");
    assert_eq!(recorded.data["agent_id"], "research-agent-01");
    assert_eq!(recorded.data["resource_id"], "btc-orderbook-2026-07-01");
    assert_eq!(recorded.data["intent_hash"].as_str().unwrap().len(), 64);

    let finalized = store
        .load_finalized_decision("alpha-lab", "01J0000000000000000000G100")
        .await?
        .expect("Decision must be durably readable");
    assert_eq!(
        finalized.evaluation.evidence["identity"]["reason_code"],
        "IDENTITY_GATEWAY_NOT_WIRED"
    );
    assert_eq!(
        finalized.evaluation.evidence["policy"]["outcome"]["status"],
        "SUCCEEDED"
    );
    assert_eq!(
        finalized.evaluation.evidence["risk"]["outcome"]["status"],
        "SUCCEEDED"
    );
    assert_eq!(
        finalized.evaluation.evidence["simulation"]["outcome"]["status"],
        "NOT_RUN"
    );
    assert_eq!(
        finalized.lifecycle.state,
        IntentLifecycleState::DecidedPermit
    );
    assert_eq!(finalized.lifecycle.version, 6);

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn posting_an_over_budget_intent_denies_and_records_risk_as_not_run(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("deny").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .oneshot(post_intent_request("01J0000000000000000000G200", "999.00"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await?["decision"], "DENY");
    let finalized = store
        .load_finalized_decision("alpha-lab", "01J0000000000000000000G200")
        .await?
        .expect("denial must be durable");
    assert_eq!(
        finalized.evaluation.evidence["risk"]["outcome"]["status"],
        "NOT_RUN"
    );
    assert_eq!(
        finalized.evaluation.evidence["risk"]["outcome"]["reason_code"],
        "POLICY_FORBID"
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn policy_evaluation_failure_commits_an_explicit_fail_closed_terminal_state(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("policy_error").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .oneshot(post_intent_request(
            "01J0000000000000000000PE00",
            "12.123456",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let decision = body_json(response).await?;
    assert_eq!(decision["decision"], "ERROR");
    assert_eq!(
        decision["reasons"][0]["message"],
        "Policy evaluation failed safely."
    );
    assert!(!serde_json::to_string(&decision)?.contains("decimal"));
    let finalized = store
        .load_finalized_decision("alpha-lab", "01J0000000000000000000PE00")
        .await?
        .expect("fail-closed Decision must be durable when PostgreSQL is healthy");
    assert_eq!(
        finalized.lifecycle.state,
        IntentLifecycleState::DecidedError
    );
    assert_eq!(
        finalized.evaluation.evidence["policy"]["outcome"]["status"],
        "ERROR"
    );
    assert_eq!(
        finalized.evaluation.evidence["policy"]["outcome"]["error_code"],
        "POLICY_EVALUATION_ERROR"
    );
    assert_eq!(
        finalized.evaluation.evidence["risk"]["outcome"]["reason_code"],
        "POLICY_ERROR"
    );
    assert_eq!(store.load_verified_audit_chain("alpha-lab").await?.len(), 6);

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn posting_malformed_json_returns_bad_request_without_durable_state(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("malformed").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/intents")
                .header("content-type", "application/json")
                .body(Body::from("not json"))?,
        )
        .await?;

    let error = error_json(response, StatusCode::BAD_REQUEST, "INVALID_JSON").await?;
    assert_eq!(error["message"], "Request body must be valid JSON.");
    assert_eq!(error["details"], serde_json::json!([]));
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn schema_rejection_uses_the_stable_contract_before_any_durable_record(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("schema_contract").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    let mut intent = sample_intent_json("01J0000000000000000000SC00", "12.50");
    intent["unexpected_core_field"] = serde_json::json!("must fail closed");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/intents")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&intent)?))?,
        )
        .await?;

    let error = error_json(response, StatusCode::BAD_REQUEST, "INTENT_SCHEMA_INVALID").await?;
    assert_eq!(
        error["message"],
        "Intent does not match the supported schema."
    );
    assert_eq!(error["details"], serde_json::json!([]));
    assert!(!serde_json::to_string(&error)?.contains("must fail closed"));
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn invalid_utf8_uses_a_safe_error_without_touching_durable_state(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("invalid_utf8").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/intents")
                .header("content-type", "application/json")
                .body(Body::from(vec![0xff, 0xfe]))?,
        )
        .await?;

    error_json(response, StatusCode::BAD_REQUEST, "INVALID_UTF8").await?;
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn posting_a_semantically_invalid_intent_stops_before_durable_admission(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("semantic").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .oneshot(post_intent_request("01J0000000000000000000S100", "0"))
        .await?;

    let error = error_json(response, StatusCode::BAD_REQUEST, "INTENT_SEMANTIC_INVALID").await?;
    assert_eq!(
        error["details"],
        serde_json::json!([{
            "code": "AMOUNT_NOT_POSITIVE",
            "field": "transaction.amount"
        }])
    );
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn posting_an_unsupported_intent_profile_stops_before_durable_admission(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("unsupported_profile").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    let intent_id = "01J0000000000000000000S200";
    let mut intent = sample_intent_json(intent_id, "12.50");
    intent["action"] = serde_json::json!({
        "category": "transfer",
        "operation": "transfer_asset"
    });

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/intents")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&intent)?))?,
        )
        .await?;
    let error = error_json(response, StatusCode::BAD_REQUEST, "INTENT_SEMANTIC_INVALID").await?;
    let admitted = store.load_admitted_intent("alpha-lab", intent_id).await?;
    let chain = store.load_verified_audit_chain("alpha-lab").await?;

    store.close().await;
    database.destroy().await?;

    assert_eq!(
        error["details"],
        serde_json::json!([{
            "code": "UNSUPPORTED_INTENT_PROFILE",
            "field": "action"
        }])
    );
    assert!(admitted.is_none());
    assert!(chain.is_empty());
    Ok(())
}

#[tokio::test]
async fn decision_can_be_looked_up_by_organization_and_intent_id() -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("lookup").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    app.clone()
        .oneshot(post_intent_request("01J0000000000000000000G300", "12.50"))
        .await?;
    let response = app
        .oneshot(get_decision_request(
            "01J0000000000000000000G300",
            "alpha-lab",
        ))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await?["decision"], "PERMIT");

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn decision_lookup_requires_an_organization_header() -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("header").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/intents/unknown-id/decision")
                .body(Body::empty())?,
        )
        .await?;

    let error = error_json(
        response,
        StatusCode::BAD_REQUEST,
        "ORGANIZATION_HEADER_INVALID",
    )
    .await?;
    assert_eq!(error["details"], serde_json::json!([]));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn looking_up_an_unknown_intent_id_returns_not_found() -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("missing").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .oneshot(get_decision_request("unknown-id", "alpha-lab"))
        .await?;

    let error = error_json(response, StatusCode::NOT_FOUND, "DECISION_NOT_FOUND").await?;
    assert_eq!(error["message"], "No decision was found.");

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn organization_scope_prevents_cross_tenant_decision_reads() -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("tenant_read").await?;
    database.seed_organization("beta-lab").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    app.clone()
        .oneshot(post_intent_request("01J0000000000000000000T100", "12.50"))
        .await?;
    let response = app
        .oneshot(get_decision_request(
            "01J0000000000000000000T100",
            "beta-lab",
        ))
        .await?;

    error_json(response, StatusCode::NOT_FOUND, "DECISION_NOT_FOUND").await?;
    assert!(store
        .load_verified_audit_chain("beta-lab")
        .await?
        .is_empty());

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn a_second_process_uses_durable_history_to_flag_a_duplicate() -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("duplicate").await?;
    let first_store = database.connect().await?;
    let first = build_router(test_state(first_store.clone()));

    let response = first
        .oneshot(post_intent_request("01J0000000000000000000D100", "12.50"))
        .await?;
    assert_eq!(body_json(response).await?["decision"], "PERMIT");
    first_store.close().await;

    let second_store = database.connect().await?;
    let second = build_router(test_state(second_store.clone()));
    let response = second
        .oneshot(post_intent_request("01J0000000000000000000D200", "12.50"))
        .await?;

    let decision = body_json(response).await?;
    assert_eq!(decision["decision"], "REVIEW");
    assert!(decision["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason["code"] == "DUPLICATE_PURCHASE"));

    second_store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn a_denied_request_does_not_count_as_a_duplicate_purchase() -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("denied_history").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .clone()
        .oneshot(post_intent_request("01J0000000000000000000N100", "999.00"))
        .await?;
    assert_eq!(body_json(response).await?["decision"], "DENY");

    let response = app
        .oneshot(post_intent_request("01J0000000000000000000N200", "12.50"))
        .await?;
    let decision = body_json(response).await?;
    assert_eq!(decision["decision"], "PERMIT");
    assert!(!decision["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason["code"] == "DUPLICATE_PURCHASE"));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn an_unprovisioned_organization_is_rejected_without_database_details(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("organization").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    let intent = sample_intent_json("01J0000000000000000000Q100", "12.50");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/intents")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&intent)?))?,
        )
        .await?;

    let error = error_json(response, StatusCode::BAD_REQUEST, "ORGANIZATION_NOT_FOUND").await?;
    assert_eq!(
        error["message"],
        "The Intent organization is not available."
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn immutable_intent_conflicts_have_a_stable_safe_response() -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("intent_conflict").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    let intent_id = "01J0000000000000000000C100";

    let first = app
        .clone()
        .oneshot(post_intent_request(intent_id, "12.50"))
        .await?;
    assert_eq!(first.status(), StatusCode::OK);

    let response = app.oneshot(post_intent_request(intent_id, "13.50")).await?;
    let error = error_json(response, StatusCode::CONFLICT, "DURABLE_STATE_CONFLICT").await?;
    assert_eq!(
        error["message"],
        "The request conflicts with existing durable state."
    );
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 6));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

async fn provisioned_database(label: &str) -> Result<TestDatabase, Box<dyn Error>> {
    let database = TestDatabase::create(label).await?;
    database.seed_organization("alpha-lab").await?;
    Ok(database)
}
