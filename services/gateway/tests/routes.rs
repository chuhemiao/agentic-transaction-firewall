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
    body_json, get_decision_request, post_intent_request, sample_intent_json, test_state,
    TestDatabase,
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

    let response = app
        .oneshot(Request::builder().uri("/readyz").body(Body::empty())?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);

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
        .oneshot(post_intent_request("01J0000000000000000000G1", "12.50"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    let decision = body_json(response).await?;
    assert_eq!(decision["decision"], "PERMIT");
    assert_eq!(decision["intent_id"], "01J0000000000000000000G1");

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
        .load_finalized_decision("alpha-lab", "01J0000000000000000000G1")
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
        .oneshot(post_intent_request("01J0000000000000000000G2", "999.00"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await?["decision"], "DENY");
    let finalized = store
        .load_finalized_decision("alpha-lab", "01J0000000000000000000G2")
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
        .oneshot(post_intent_request("01J0000000000000000000PE", "12.123456"))
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body_json(response).await?["decision"], "ERROR");
    let finalized = store
        .load_finalized_decision("alpha-lab", "01J0000000000000000000PE")
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

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(store
        .load_verified_audit_chain("alpha-lab")
        .await?
        .is_empty());

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn decision_can_be_looked_up_by_organization_and_intent_id() -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("lookup").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));

    app.clone()
        .oneshot(post_intent_request("01J0000000000000000000G3", "12.50"))
        .await?;
    let response = app
        .oneshot(get_decision_request(
            "01J0000000000000000000G3",
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

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

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

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

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
        .oneshot(post_intent_request("01J0000000000000000000T1", "12.50"))
        .await?;
    let response = app
        .oneshot(get_decision_request("01J0000000000000000000T1", "beta-lab"))
        .await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
        .oneshot(post_intent_request("01J0000000000000000000D1", "12.50"))
        .await?;
    assert_eq!(body_json(response).await?["decision"], "PERMIT");
    first_store.close().await;

    let second_store = database.connect().await?;
    let second = build_router(test_state(second_store.clone()));
    let response = second
        .oneshot(post_intent_request("01J0000000000000000000D2", "12.50"))
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
        .oneshot(post_intent_request("01J0000000000000000000N1", "999.00"))
        .await?;
    assert_eq!(body_json(response).await?["decision"], "DENY");

    let response = app
        .oneshot(post_intent_request("01J0000000000000000000N2", "12.50"))
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
    let intent = sample_intent_json("01J0000000000000000000O1", "12.50");

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/intents")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&intent)?))?,
        )
        .await?;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        body_json(response).await?["error"],
        "the Intent organization is not provisioned"
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}

async fn provisioned_database(label: &str) -> Result<TestDatabase, Box<dyn Error>> {
    let database = TestDatabase::create(label).await?;
    database.seed_organization("alpha-lab").await?;
    Ok(database)
}
