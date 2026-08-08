//! End-to-end tests of the Gateway HTTP surface through a real, isolated
//! PostgreSQL database and `tower::ServiceExt::oneshot`.

mod common;

use atf_audit::EventType;
use atf_core::IntentLifecycleState;
use atf_gateway::build_router;
use atf_store::{OperatorRole, OperatorStatus};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::{error::Error, sync::Arc, time::Duration};
use tokio::sync::Barrier;
use tower::ServiceExt;

use common::{
    authenticated_admission_input, body_json, error_json, get_decision_request,
    operator_authorization, post_intent_request, sample_intent_json, test_state,
    test_state_with_forbid_all_policy, TestDatabase,
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
    let event_types: Vec<EventType> = chain
        .iter()
        .filter(|stored| stored.event.intent_id.is_some())
        .map(|stored| stored.event.event_type)
        .collect();
    assert_eq!(
        event_types,
        vec![
            EventType::IntentReceived,
            EventType::IdentityVerified,
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
        finalized.evaluation.evidence["identity"]["key_id"],
        "identity-key-01"
    );
    assert_eq!(
        finalized.evaluation.evidence["identity"]["envelope_hash"]
            .as_str()
            .expect("identity evidence has an envelope hash")
            .len(),
        64
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
    assert_eq!(
        store
            .load_verified_audit_chain("alpha-lab")
            .await?
            .iter()
            .filter(|stored| stored.event.intent_id.is_some())
            .count(),
        6
    );

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
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 0));

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
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 0));

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
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 0));

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
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 0));

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
    assert!(chain.iter().all(|stored| stored.event.intent_id.is_none()));
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
                .header("authorization", operator_authorization())
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
        .iter()
        .all(|stored| stored.event.intent_id.is_none()));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn decision_read_requires_one_operator_bearer_and_rejects_agent_credentials(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("operator_required").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/intents/unknown-id/decision")
                .header("x-atf-organization-id", "alpha-lab")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        response.headers().get("www-authenticate").unwrap(),
        "Bearer"
    );
    error_json(
        response,
        StatusCode::UNAUTHORIZED,
        "AUTHENTICATION_REQUIRED",
    )
    .await?;

    let raw_token = "sensitive.header.signature";
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/intents/unknown-id/decision")
                .header("x-atf-organization-id", "alpha-lab")
                .header("authorization", format!("Bearer {raw_token}"))
                .body(Body::empty())?,
        )
        .await?;
    let error = error_json(
        response,
        StatusCode::UNAUTHORIZED,
        "AUTHENTICATION_REQUIRED",
    )
    .await?;
    assert!(!serde_json::to_string(&error)?.contains(raw_token));

    let mut confused = get_decision_request("unknown-id", "alpha-lab");
    confused
        .headers_mut()
        .insert("x-atf-identity-envelope", "00".parse()?);
    let response = app.oneshot(confused).await?;
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
async fn revoked_role_wrong_role_and_disabled_subject_take_effect_on_the_next_read(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("operator_revocation").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    let intent_id = "01J0000000000000000000RB10";

    assert_eq!(
        app.clone()
            .oneshot(post_intent_request(intent_id, "12.50"))
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(get_decision_request(intent_id, "alpha-lab"))
            .await?
            .status(),
        StatusCode::OK
    );

    let changed_at = atf_core::Timestamp::now().to_string().parse()?;
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
        .oneshot(get_decision_request(intent_id, "alpha-lab"))
        .await?;
    error_json(response, StatusCode::NOT_FOUND, "DECISION_NOT_FOUND").await?;

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
        .oneshot(get_decision_request(intent_id, "alpha-lab"))
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
async fn operator_bearer_cannot_bypass_agent_admission() -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("operator_not_agent").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    let mut request = post_intent_request("01J0000000000000000000RB20", "12.50");
    request
        .headers_mut()
        .insert("authorization", operator_authorization().parse()?);

    let response = app.oneshot(request).await?;
    error_json(
        response,
        StatusCode::UNAUTHORIZED,
        "AUTHENTICATION_REQUIRED",
    )
    .await?;
    assert!(store
        .load_admitted_intent("alpha-lab", "01J0000000000000000000RB20")
        .await?
        .is_none());
    let intent_events: Vec<EventType> = store
        .load_verified_audit_chain("alpha-lab")
        .await?
        .into_iter()
        .filter(|stored| stored.event.intent_id.is_some())
        .map(|stored| stored.event.event_type)
        .collect();
    assert!(intent_events.is_empty());

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
    let error = error_json(response, StatusCode::CONFLICT, "IDEMPOTENCY_CONFLICT").await?;
    assert_eq!(
        error["message"],
        "The idempotency key is already bound to different request content."
    );
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 6));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn completed_same_hash_retry_returns_the_original_decision_without_new_evidence(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("completed_retry").await?;
    let first_store = database.connect().await?;
    let intent_id = "01J0000000000000000000J100";
    let first_gateway = build_router(test_state(first_store.clone()));

    let first_response = first_gateway
        .oneshot(post_intent_request(intent_id, "12.50"))
        .await?;
    assert_eq!(first_response.status(), StatusCode::OK);
    let original = body_json(first_response).await?;
    assert_eq!(original["decision"], "PERMIT");
    first_store.close().await;

    let restarted_store = database.connect().await?;
    let restarted_gateway =
        build_router(test_state_with_forbid_all_policy(restarted_store.clone()));
    let retry_response = restarted_gateway
        .oneshot(post_intent_request(intent_id, "12.50"))
        .await?;

    assert_eq!(retry_response.status(), StatusCode::OK);
    assert_eq!(body_json(retry_response).await?, original);
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 6));
    assert_eq!(
        restarted_store
            .load_verified_audit_chain("alpha-lab")
            .await?
            .iter()
            .filter(|stored| stored.event.intent_id.is_some())
            .count(),
        6
    );

    restarted_store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn concurrent_same_hash_posts_converge_on_one_decision_and_one_final_audit_transition(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("concurrent_retry").await?;
    let store = database.connect().await?;
    let gateway = build_router(test_state(store.clone()));
    let intent_id = "01J0000000000000000000K200";
    let barrier = Arc::new(Barrier::new(3));

    let first = {
        let barrier = barrier.clone();
        let gateway = gateway.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            gateway
                .oneshot(post_intent_request(intent_id, "12.50"))
                .await
        })
    };
    let second = {
        let barrier = barrier.clone();
        let gateway = gateway.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            gateway
                .oneshot(post_intent_request(intent_id, "12.50"))
                .await
        })
    };
    barrier.wait().await;
    let (first, second) = tokio::join!(first, second);
    let responses = [first??, second??];
    let mut observed_decisions = Vec::new();
    for response in responses {
        if response.status() == StatusCode::OK {
            observed_decisions.push(body_json(response).await?);
        } else {
            error_json(response, StatusCode::CONFLICT, "IDEMPOTENCY_IN_PROGRESS").await?;
        }
    }
    assert!(!observed_decisions.is_empty());

    let retry = gateway
        .oneshot(post_intent_request(intent_id, "12.50"))
        .await?;
    assert_eq!(retry.status(), StatusCode::OK);
    let durable = body_json(retry).await?;
    for observed in observed_decisions {
        assert_eq!(observed, durable);
    }
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 6));
    assert_eq!(
        store
            .load_verified_audit_chain("alpha-lab")
            .await?
            .iter()
            .filter(|stored| stored.event.intent_id.is_some())
            .count(),
        6
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn active_idempotency_lease_stops_a_second_request_before_evaluation(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("intent_in_progress").await?;
    let store = database.connect().await?;
    let intent_id = "01J0000000000000000000G100";
    let intent_json = sample_intent_json(intent_id, "12.50");
    let intent = atf_intent::validate(&serde_json::to_string(&intent_json)?)?;
    store
        .authenticate_and_admit(authenticated_admission_input(
            intent,
            Duration::from_secs(30),
        ))
        .await?;
    let app = build_router(test_state(store.clone()));

    let response = app.oneshot(post_intent_request(intent_id, "12.50")).await?;

    let error = error_json(response, StatusCode::CONFLICT, "IDEMPOTENCY_IN_PROGRESS").await?;
    assert_eq!(
        error["message"],
        "The idempotent request is in progress or awaiting recovery."
    );
    assert_eq!(database.business_record_counts().await?, (1, 1, 0, 0, 2));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn expired_admission_is_recovered_after_restart_as_one_fail_closed_decision(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("expired_recovery").await?;
    let first_store = database.connect().await?;
    let intent_id = "01J0000000000000000000K100";
    let intent_json = sample_intent_json(intent_id, "12.50");
    let intent = atf_intent::validate(&serde_json::to_string(&intent_json)?)?;
    let grant = first_store
        .authenticate_and_admit(authenticated_admission_input(
            intent,
            Duration::from_millis(1),
        ))
        .await?;
    assert_eq!(grant.evaluator_lease.generation(), 1);
    first_store.close().await;
    tokio::time::sleep(Duration::from_millis(10)).await;

    let restarted_store = database.connect().await?;
    let restarted_gateway =
        build_router(test_state_with_forbid_all_policy(restarted_store.clone()));
    let response = restarted_gateway
        .clone()
        .oneshot(post_intent_request(intent_id, "12.50"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let recovered = body_json(response).await?;
    assert_eq!(recovered["decision"], "ERROR");
    assert_eq!(
        recovered["reasons"][0]["code"],
        "RECOVERY_CONTEXT_UNAVAILABLE"
    );
    let finalized = restarted_store
        .load_finalized_decision("alpha-lab", intent_id)
        .await?
        .expect("recovery must produce one durable terminal Decision");
    assert_eq!(
        finalized.decision,
        serde_json::from_value(recovered.clone())?
    );
    assert_eq!(
        finalized.evaluation.evidence["policy"]["outcome"]["error_code"],
        "RECOVERY_CONTEXT_UNAVAILABLE"
    );
    assert_eq!(
        finalized.evaluation.evidence["risk"]["outcome"]["reason_code"],
        "POLICY_ERROR"
    );
    let reservation = restarted_store
        .load_idempotency_reservation("alpha-lab", &format!("idem-{intent_id}"))
        .await?
        .expect("the reclaimed reservation remains queryable");
    assert_eq!(reservation.lease_generation, 2);
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 6));

    let retry = restarted_gateway
        .oneshot(post_intent_request(intent_id, "12.50"))
        .await?;
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(body_json(retry).await?, recovered);
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 6));

    restarted_store.close().await;
    database.destroy().await?;
    Ok(())
}

async fn provisioned_database(label: &str) -> Result<TestDatabase, Box<dyn Error>> {
    let database = TestDatabase::create(label).await?;
    database.seed_organization("alpha-lab").await?;
    Ok(database)
}
