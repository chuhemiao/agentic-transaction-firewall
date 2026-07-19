//! End-to-end tests of the gateway's HTTP surface, driven through
//! `tower::ServiceExt::oneshot` (no real socket bound).

use atf_gateway::{build_router, AppState};
use atf_policy::PolicyBundle;
use atf_risk::RiskConfig;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

const POLICY: &str = r#"
    permit (
        principal,
        action == Action::"payment/purchase_api_resource",
        resource
    )
    when {
        context.organization_id == "alpha-lab" &&
        context.amount.lessThanOrEqual(decimal("20.0000"))
    };
"#;

fn test_state() -> AppState {
    let bundle: PolicyBundle = POLICY.parse().unwrap();
    AppState::new(bundle, RiskConfig::default())
}

fn sample_intent_json(intent_id: &str, amount: &str) -> serde_json::Value {
    serde_json::json!({
        "spec_version": "1.0",
        "intent_id": intent_id,
        "idempotency_key": format!("idem-{intent_id}"),
        "created_at": "2026-07-18T08:00:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
        "principal": { "organization_id": "alpha-lab", "agent_id": "research-agent-01" },
        "mandate": {
            "mandate_id": "mandate-001",
            "purpose": "test",
            "human_authorized": true
        },
        "action": { "category": "payment", "operation": "purchase_api_resource" },
        "resource": { "protocol": "x402", "resource_id": "btc-orderbook-2026-07-01" },
        "transaction": { "network": "base", "asset": "eip155:8453/erc20:0x0", "amount": amount }
    })
}

async fn body_json(response: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

#[tokio::test]
async fn healthz_and_readyz_report_ok() {
    let app = build_router(test_state());

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/readyz")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn posting_an_in_budget_intent_permits_and_records_audit_events() {
    let state = test_state();
    let app = build_router(state.clone());

    let intent = sample_intent_json("01J0000000000000000000G1", "12.50");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/intents")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&intent).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let decision = body_json(response).await;
    assert_eq!(decision["decision"], "PERMIT");
    assert_eq!(decision["intent_id"], "01J0000000000000000000G1");

    let ledger = state.audit_ledger.lock().unwrap();
    let event_types: Vec<String> = ledger
        .iter()
        .map(|e| format!("{:?}", e.event_type))
        .collect();
    assert_eq!(
        event_types,
        vec!["IntentReceived", "PolicyEvaluated", "RiskEvaluated"]
    );
    assert!(ledger.verify_chain().is_ok());
}

#[tokio::test]
async fn posting_an_over_budget_intent_denies_and_skips_risk_scoring() {
    let app = build_router(test_state());

    let intent = sample_intent_json("01J0000000000000000000G2", "999.00");
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/intents")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&intent).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let decision = body_json(response).await;
    assert_eq!(decision["decision"], "DENY");
}

#[tokio::test]
async fn posting_malformed_json_returns_bad_request() {
    let app = build_router(test_state());

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/intents")
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn decision_can_be_looked_up_by_intent_id_after_posting() {
    let app = build_router(test_state());

    let intent = sample_intent_json("01J0000000000000000000G3", "12.50");
    app.clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/intents")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_vec(&intent).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/intents/01J0000000000000000000G3/decision")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let decision = body_json(response).await;
    assert_eq!(decision["decision"], "PERMIT");
}

#[tokio::test]
async fn looking_up_an_unknown_intent_id_returns_not_found() {
    let app = build_router(test_state());

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/intents/unknown-id/decision")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
