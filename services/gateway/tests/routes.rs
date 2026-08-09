//! End-to-end tests of the Gateway HTTP surface through a real, isolated
//! PostgreSQL database and `tower::ServiceExt::oneshot`.

mod common;

use atf_audit::{AuditPayload, EventType};
use atf_core::{IntentLifecycleState, Timestamp};
use atf_gateway::build_router;
use atf_policy::{
    policy_bundle_signature_message, PolicyBundle, PolicyBundleLoadContext, PolicyBundleSignature,
};
use atf_risk::RiskRuleSet;
use atf_store::{OperatorRole, OperatorStatus};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use ed25519_dalek::{Signer, SigningKey};
use std::{error::Error, path::Path, sync::Arc, time::Duration};
use tokio::sync::Barrier;
use tower::ServiceExt;

use common::{
    authenticated_admission_input, body_json, error_json, get_decision_request,
    operator_authorization, post_intent_request, post_intent_value_request, sample_intent_json,
    test_durable_policy_state, test_risk_rule_set, test_state, test_state_with_default_risk,
    test_state_with_forbid_all_policy, test_state_with_risk, TestDatabase,
};

fn daily_spend_rule_set(max_amount: &str) -> RiskRuleSet {
    let mut document: serde_json::Value =
        serde_json::from_str(include_str!("../../../risk-rules/default.json")).unwrap();
    document["rule_set_version"] = serde_json::json!("risk-rules-daily-gateway-test-v1");
    document["rules"]["max_fee_ratio"]["enabled"] = serde_json::json!(false);
    document["rules"]["max_fee_ratio"]["missing_data"] = serde_json::json!("NOT_APPLICABLE");
    document["rules"]["vendor_price_deviation"]["enabled"] = serde_json::json!(false);
    document["rules"]["vendor_price_deviation"]["missing_data"] =
        serde_json::json!("NOT_APPLICABLE");
    document["rules"]["duplicate_purchase"]["enabled"] = serde_json::json!(false);
    document["rules"]["first_time_destination"]["enabled"] = serde_json::json!(false);
    document["rules"]["request_frequency"]["enabled"] = serde_json::json!(false);
    document["rules"]["daily_cumulative_spend"]["max_amount"] = serde_json::json!(max_amount);
    RiskRuleSet::from_json(&document.to_string()).unwrap()
}

fn first_destination_rule_set(enabled: bool) -> RiskRuleSet {
    let mut document: serde_json::Value =
        serde_json::from_str(include_str!("../../../risk-rules/default.json")).unwrap();
    document["rule_set_version"] = serde_json::json!(if enabled {
        "risk-rules-first-destination-enabled-v1"
    } else {
        "risk-rules-first-destination-disabled-v1"
    });
    document["rules"]["max_fee_ratio"]["enabled"] = serde_json::json!(false);
    document["rules"]["max_fee_ratio"]["missing_data"] = serde_json::json!("NOT_APPLICABLE");
    document["rules"]["vendor_price_deviation"]["enabled"] = serde_json::json!(false);
    document["rules"]["vendor_price_deviation"]["missing_data"] =
        serde_json::json!("NOT_APPLICABLE");
    document["rules"]["duplicate_purchase"]["enabled"] = serde_json::json!(false);
    document["rules"]["daily_cumulative_spend"]["enabled"] = serde_json::json!(false);
    document["rules"]["first_time_destination"]["enabled"] = serde_json::json!(enabled);
    document["rules"]["request_frequency"]["enabled"] = serde_json::json!(false);
    RiskRuleSet::from_json(&document.to_string()).unwrap()
}

fn request_frequency_rule_set(max_requests: u64) -> RiskRuleSet {
    let mut document: serde_json::Value =
        serde_json::from_str(include_str!("../../../risk-rules/default.json")).unwrap();
    document["rule_set_version"] =
        serde_json::json!("risk-rules-request-frequency-gateway-test-v1");
    document["rules"]["max_fee_ratio"]["enabled"] = serde_json::json!(false);
    document["rules"]["max_fee_ratio"]["missing_data"] = serde_json::json!("NOT_APPLICABLE");
    document["rules"]["vendor_price_deviation"]["enabled"] = serde_json::json!(false);
    document["rules"]["vendor_price_deviation"]["missing_data"] =
        serde_json::json!("NOT_APPLICABLE");
    document["rules"]["duplicate_purchase"]["enabled"] = serde_json::json!(false);
    document["rules"]["daily_cumulative_spend"]["enabled"] = serde_json::json!(false);
    document["rules"]["first_time_destination"]["enabled"] = serde_json::json!(false);
    document["rules"]["request_frequency"]["max_requests"] = serde_json::json!(max_requests);
    RiskRuleSet::from_json(&document.to_string()).unwrap()
}

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
    let expected_risk = test_risk_rule_set();
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
            EventType::ContextEnriched,
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
    let context = finalized
        .evaluation_context
        .as_ref()
        .expect("new Evaluations must retain their immutable context");
    assert_eq!(context.evaluation_id(), finalized.evaluation.evaluation_id);
    assert_eq!(context.intent_hash(), finalized.intent_hash);
    assert_eq!(context.evaluation_time(), finalized.evaluation.evaluated_at);
    assert_eq!(
        finalized.evaluation.evaluation_context_hash.as_deref(),
        Some(context.evaluation_context_hash())
    );
    assert_eq!(
        context.policy().available_parts(),
        Some((
            "atf-example-payments",
            "1.0.0",
            "87276dc9ae9b5cfd09bc664fc12a7a6d1bdc6cec3f847644239b27a368478373",
        ))
    );
    assert_eq!(
        context.risk().available_parts(),
        Some((
            expected_risk.engine_version(),
            expected_risk.version(),
            expected_risk.rule_set_hash(),
        ))
    );
    let identity_event = chain
        .iter()
        .find(|stored| {
            stored.event.intent_id.as_deref() == Some("01J0000000000000000000G100")
                && stored.event.event_type == EventType::IdentityVerified
        })
        .expect("Identity evidence precedes context capture");
    let context_event = chain
        .iter()
        .find(|stored| {
            stored.event.intent_id.as_deref() == Some("01J0000000000000000000G100")
                && stored.event.event_type == EventType::ContextEnriched
        })
        .expect("context capture is audited");
    assert_eq!(
        context.history().through_sequence(),
        u64::try_from(identity_event.sequence)?
    );
    assert_eq!(context.history().snapshot_hash(), identity_event.event_hash);
    assert_eq!(
        context_event.event.data["context_hash"],
        context.evaluation_context_hash()
    );
    assert!(context_event.sequence > identity_event.sequence);
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
        finalized.evaluation.evidence["risk"]["risk_rule_set_version"],
        expected_risk.version()
    );
    assert_eq!(
        finalized.evaluation.evidence["risk"]["risk_rule_set_hash"],
        expected_risk.rule_set_hash()
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
async fn agent_price_context_cannot_impersonate_trusted_gateway_evidence(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("agent_price_context").await?;
    let store = database.connect().await?;
    let app = build_router(test_state_with_default_risk(store.clone()));
    let mut intent = sample_intent_json("01J0000000000000000000PV00", "12.50");
    intent["context"]["historical_vendor_median"] = serde_json::json!("12.50");

    let response = app.oneshot(post_intent_value_request(intent)).await?;

    assert_eq!(response.status(), StatusCode::OK);
    let decision = body_json(response).await?;
    assert_eq!(decision["decision"], "REVIEW");
    assert!(decision["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason["code"] == "VENDOR_PRICE_DATA_MISSING"));
    let finalized = store
        .load_finalized_decision("alpha-lab", "01J0000000000000000000PV00")
        .await?
        .expect("restrictive Decision must be durable");
    assert_eq!(
        finalized.evaluation.evidence["risk"]["risk_rule_set_version"],
        "risk-rules-1.3.0"
    );
    assert!(finalized.evaluation.evidence["risk"]["outcome"]["result"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["code"] == "VENDOR_PRICE_DATA_MISSING"));

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
    assert_eq!(
        finalized.evaluation.evidence["risk"]["risk_rule_set_version"],
        common::TEST_RISK_RULE_SET_VERSION
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
        7
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
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 0, 0));

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
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 0, 0));

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
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 0, 0));

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
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 0, 0));

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
async fn policy_activation_api_requires_current_policy_role_and_records_exact_pointer(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("policy_activation_api").await?;
    let store = database.connect().await?;
    let now: Timestamp = Timestamp::now().to_string().parse()?;
    store
        .grant_operator_role(
            "operator-1",
            "alpha-lab",
            OperatorRole::PolicyAuthor,
            "test-db-admin",
            "TEST_POLICY_ACCESS",
            now,
        )
        .await?;
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies/examples");
    let bundle = PolicyBundle::from_dir(
        &directory,
        &PolicyBundleLoadContext {
            organization_id: "alpha-lab".into(),
            environment: "development".into(),
            evaluated_at: now,
        },
    )?;
    let signing_key = SigningKey::from_bytes(&[31; 32]);
    let message = policy_bundle_signature_message("gateway-test-publisher", bundle.bundle_hash())?;
    let proof = PolicyBundleSignature::from_parts(
        "gateway-test-publisher".into(),
        bundle.bundle_hash().into(),
        signing_key.sign(&message).to_bytes(),
    )?;
    store
        .install_policy_bundle(
            &bundle,
            &proof,
            &signing_key.verifying_key().to_bytes(),
            "operator-1",
            now,
        )
        .await?;
    store
        .revoke_operator_role(
            "operator-1",
            "alpha-lab",
            OperatorRole::PolicyAuthor,
            "test-db-admin",
            "TEST_POLICY_ACCESS_REMOVED",
            now,
        )
        .await?;

    let app = build_router(test_state(store.clone()));
    let request = || {
        Request::builder()
            .method("POST")
            .uri("/v1/policy-bundles/atf-example-payments/activate")
            .header("content-type", "application/json")
            .header("x-atf-organization-id", "alpha-lab")
            .header("authorization", operator_authorization())
            .body(Body::from(
                r#"{"environment":"development","policy_version":"1.0.0"}"#,
            ))
            .unwrap()
    };
    error_json(
        app.clone().oneshot(request()).await?,
        StatusCode::NOT_FOUND,
        "POLICY_BUNDLE_NOT_FOUND",
    )
    .await?;

    store
        .grant_operator_role(
            "operator-1",
            "alpha-lab",
            OperatorRole::PolicyAuthor,
            "test-db-admin",
            "TEST_POLICY_ACCESS_RESTORED",
            now,
        )
        .await?;

    let invalid_scope = Request::builder()
        .method("POST")
        .uri("/v1/policy-bundles/atf-example-payments/activate")
        .header("content-type", "application/json")
        .header("x-atf-organization-id", "alpha-lab")
        .header("authorization", operator_authorization())
        .body(Body::from(
            r#"{"environment":"development/other","policy_version":"1.0.0"}"#,
        ))
        .unwrap();
    error_json(
        app.clone().oneshot(invalid_scope).await?,
        StatusCode::BAD_REQUEST,
        "REQUEST_BODY_INVALID",
    )
    .await?;

    let response = app.oneshot(request()).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let body = body_json(response).await?;
    assert_eq!(body["policy_version"], "1.0.0");
    assert_eq!(body["bundle_hash"], bundle.bundle_hash());
    assert_eq!(body["lifecycle_version"], 1);
    assert!(body["audit_event_id"].as_str().is_some());

    let durable_gateway = build_router(test_durable_policy_state(store.clone()));
    let evaluated = durable_gateway
        .oneshot(post_intent_request("01J0000000000000000000P020", "12.50"))
        .await?;
    assert_eq!(evaluated.status(), StatusCode::OK);
    assert_eq!(body_json(evaluated).await?["decision"], "PERMIT");

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
    let finalized = second_store
        .load_finalized_decision("alpha-lab", "01J0000000000000000000D200")
        .await?
        .expect("the duplicate Decision is durable");
    let history = &finalized.evaluation.evidence["risk"]["history"];
    assert_eq!(
        history["duplicate_purchase"]["query"]["accounting_boundary"],
        "PERMITTED"
    );
    assert_eq!(
        history["duplicate_purchase"]["query"]["current_intent_id"],
        "01J0000000000000000000D200"
    );
    assert_eq!(
        history["duplicate_purchase"]["result"]["intent_id"],
        "01J0000000000000000000D100"
    );

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
async fn parallel_completed_permits_are_visible_to_the_next_daily_spend_snapshot(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("daily_spend_concurrent").await?;
    let store = database.connect().await?;
    let app = build_router(test_state_with_risk(
        store.clone(),
        daily_spend_rule_set("25.00"),
    ));

    let mut first = sample_intent_json("01J0000000000000000000C101", "10.00");
    first["resource"]["resource_id"] = serde_json::json!("daily-resource-a");
    let mut second = sample_intent_json("01J0000000000000000000C102", "10.00");
    second["resource"]["resource_id"] = serde_json::json!("daily-resource-b");
    let (first_response, second_response) = tokio::join!(
        app.clone().oneshot(post_intent_value_request(first)),
        app.clone().oneshot(post_intent_value_request(second)),
    );
    assert_eq!(body_json(first_response?).await?["decision"], "PERMIT");
    assert_eq!(body_json(second_response?).await?["decision"], "PERMIT");

    let mut third = sample_intent_json("01J0000000000000000000C103", "5.01");
    third["resource"]["resource_id"] = serde_json::json!("daily-resource-c");
    let decision = body_json(app.oneshot(post_intent_value_request(third)).await?).await?;
    assert_eq!(decision["decision"], "REVIEW");
    assert!(decision["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason["code"] == "DAILY_CUMULATIVE_SPEND_EXCEEDED"));

    let finalized = store
        .load_finalized_decision("alpha-lab", "01J0000000000000000000C103")
        .await?
        .expect("daily-spend Decision is durable");
    let daily = &finalized.evaluation.evidence["risk"]["history"]["daily_cumulative_spend"];
    assert_eq!(daily["query"]["organization_id"], "alpha-lab");
    assert_eq!(daily["query"]["agent_id"], "research-agent-01");
    assert_eq!(daily["query"]["accounting_boundary"], "PERMITTED");
    assert_eq!(daily["totals"][0]["amount"], "20.00");
    assert_eq!(daily["totals"][0]["decision_count"], 2);

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn concurrent_accepted_requests_cannot_bypass_the_requested_frequency_threshold(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("request_frequency_concurrent").await?;
    let store = database.connect().await?;
    let app = build_router(test_state_with_risk(
        store.clone(),
        request_frequency_rule_set(1),
    ));
    let mut first = sample_intent_json("01J0000000000000000000F101", "10.00");
    first["resource"]["resource_id"] = serde_json::json!("frequency-resource-a");
    let mut second = sample_intent_json("01J0000000000000000000F102", "10.00");
    second["resource"]["resource_id"] = serde_json::json!("frequency-resource-b");

    let (first_response, second_response) = tokio::join!(
        app.clone().oneshot(post_intent_value_request(first)),
        app.clone().oneshot(post_intent_value_request(second)),
    );
    let decisions = [
        body_json(first_response?).await?,
        body_json(second_response?).await?,
    ];
    let permit_count = decisions
        .iter()
        .filter(|decision| decision["decision"] == "PERMIT")
        .count();
    let review_count = decisions
        .iter()
        .filter(|decision| decision["decision"] == "REVIEW")
        .count();
    assert!(permit_count <= 1);
    assert!(review_count >= 1);
    assert!(decisions
        .iter()
        .filter(|decision| decision["decision"] == "REVIEW")
        .all(|decision| decision["reasons"]
            .as_array()
            .unwrap()
            .iter()
            .any(|reason| reason["code"] == "REQUEST_FREQUENCY_EXCEEDED")));

    let mut counts = Vec::new();
    for intent_id in ["01J0000000000000000000F101", "01J0000000000000000000F102"] {
        let finalized = store
            .load_finalized_decision("alpha-lab", intent_id)
            .await?
            .expect("both concurrent requests are durably finalized");
        counts.push(
            finalized.evaluation.evidence["risk"]["history"]["request_frequency"]["request_count"]
                .as_u64()
                .unwrap(),
        );
    }
    assert_eq!(counts.into_iter().max(), Some(2));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn completed_idempotent_retry_does_not_inflate_requested_frequency(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("request_frequency_idempotent").await?;
    let store = database.connect().await?;
    let app = build_router(test_state_with_risk(
        store.clone(),
        request_frequency_rule_set(1),
    ));
    let first_id = "01J0000000000000000000F201";
    let first = body_json(
        app.clone()
            .oneshot(post_intent_request(first_id, "10.00"))
            .await?,
    )
    .await?;
    assert_eq!(first["decision"], "PERMIT");

    let retry = body_json(
        app.clone()
            .oneshot(post_intent_request(first_id, "10.00"))
            .await?,
    )
    .await?;
    assert_eq!(retry, first);

    let mut second = sample_intent_json("01J0000000000000000000F202", "10.00");
    second["resource"]["resource_id"] = serde_json::json!("frequency-resource-second");
    let second = body_json(app.oneshot(post_intent_value_request(second)).await?).await?;
    assert_eq!(second["decision"], "REVIEW");
    assert!(second["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason["code"] == "REQUEST_FREQUENCY_EXCEEDED"));

    let finalized = store
        .load_finalized_decision("alpha-lab", "01J0000000000000000000F202")
        .await?
        .expect("the second request is durable");
    assert_eq!(
        finalized.evaluation.evidence["risk"]["history"]["request_frequency"]["request_count"],
        2
    );
    let chain = store.load_verified_audit_chain("alpha-lab").await?;
    let received: Vec<_> = chain
        .iter()
        .filter(|stored| stored.event.event_type == EventType::IntentReceived)
        .collect();
    assert_eq!(received.len(), 2);
    for stored in received {
        let AuditPayload::IntentReceived(payload) = stored.event.typed_payload()? else {
            panic!("IntentReceived must retain its typed payload");
        };
        let binding = payload
            .binding
            .expect("current admission always binds Profile/action scope");
        assert_eq!(binding.profile.id, "atf.agent-commerce.payment");
        assert_eq!(binding.profile.version, "1.0");
        assert_eq!(binding.action_category, "payment");
        assert_eq!(binding.action_operation, "purchase_api_resource");
    }

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn requested_frequency_window_is_inclusive_at_start_and_excludes_one_millisecond_before_it(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("request_frequency_window").await?;
    let store = database.connect().await?;
    let rule_set = request_frequency_rule_set(10);
    let app = build_router(test_state_with_risk(store.clone(), rule_set.clone()));
    let prior_id = "01J0000000000000000000F301";
    assert_eq!(
        body_json(app.oneshot(post_intent_request(prior_id, "10.00")).await?).await?["decision"],
        "PERMIT"
    );
    let prior = store
        .load_admitted_intent("alpha-lab", prior_id)
        .await?
        .expect("the accepted request is durable");
    let current: atf_intent::TransactionIntent =
        serde_json::from_value(sample_intent_json("01J0000000000000000000F302", "10.00"))?;
    let at_start =
        Timestamp::from_datetime(prior.received_at.as_datetime() + chrono::Duration::seconds(60));
    let included = store
        .capture_risk_history(&current, &rule_set, at_start)
        .await?;
    assert_eq!(
        included
            .request_frequency()
            .expect("frequency query is enabled")
            .request_count(),
        1
    );

    let just_outside =
        Timestamp::from_datetime(at_start.as_datetime() + chrono::Duration::milliseconds(1));
    let excluded = store
        .capture_risk_history(&current, &rule_set, just_outside)
        .await?;
    assert_eq!(
        excluded
            .request_frequency()
            .expect("frequency query is enabled")
            .request_count(),
        0
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn missing_cross_asset_quote_cannot_produce_a_gateway_permit() -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("daily_spend_quote").await?;
    let store = database.connect().await?;
    let app = build_router(test_state_with_risk(
        store.clone(),
        daily_spend_rule_set("25.00"),
    ));

    let mut prior = sample_intent_json("01J0000000000000000000Q101", "10.00");
    prior["resource"]["resource_id"] = serde_json::json!("quote-resource-a");
    let prior_decision = body_json(
        app.clone()
            .oneshot(post_intent_value_request(prior))
            .await?,
    )
    .await?;
    assert_eq!(prior_decision["decision"], "PERMIT");

    let mut current = sample_intent_json("01J0000000000000000000Q102", "1.00");
    current["resource"]["resource_id"] = serde_json::json!("quote-resource-b");
    current["transaction"]["asset"] = serde_json::json!("eip155:8453/slip44:60");
    let decision = body_json(app.oneshot(post_intent_value_request(current)).await?).await?;

    assert_eq!(decision["decision"], "REVIEW");
    assert!(decision["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason["code"] == "DAILY_SPEND_QUOTE_MISSING"));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn first_destination_uses_organization_scoped_normalized_permit_history(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("first_destination").await?;
    let store = database.connect().await?;
    let disabled = build_router(test_state_with_risk(
        store.clone(),
        first_destination_rule_set(false),
    ));

    let prior_id = "01J0000000000000000000F101";
    let mut prior = sample_intent_json(prior_id, "12.50");
    prior["resource"]["resource_id"] = serde_json::json!("first-destination-prior");
    prior["transaction"]["destination"] =
        serde_json::json!("eip155:8453:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    assert_eq!(
        body_json(disabled.oneshot(post_intent_value_request(prior)).await?).await?["decision"],
        "PERMIT"
    );

    let enabled_rule_set = first_destination_rule_set(true);
    let enabled = build_router(test_state_with_risk(
        store.clone(),
        enabled_rule_set.clone(),
    ));
    let familiar_id = "01J0000000000000000000F102";
    let mut familiar = sample_intent_json(familiar_id, "12.50");
    familiar["resource"]["resource_id"] = serde_json::json!("first-destination-familiar");
    familiar["transaction"]["destination"] =
        serde_json::json!("eip155:8453:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed");
    let familiar_decision = body_json(
        enabled
            .clone()
            .oneshot(post_intent_value_request(familiar))
            .await?,
    )
    .await?;
    assert_eq!(familiar_decision["decision"], "PERMIT");
    assert!(!familiar_decision["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason["code"] == "FIRST_TIME_DESTINATION"));

    let mut first = sample_intent_json("01J0000000000000000000F103", "12.50");
    first["resource"]["resource_id"] = serde_json::json!("first-destination-new");
    first["transaction"]["destination"] =
        serde_json::json!("eip155:8453:0x2222222222222222222222222222222222222222");
    let first_decision =
        body_json(enabled.oneshot(post_intent_value_request(first)).await?).await?;
    assert_eq!(first_decision["decision"], "REVIEW");
    assert!(first_decision["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason["code"] == "FIRST_TIME_DESTINATION"));

    let finalized = store
        .load_finalized_decision("alpha-lab", familiar_id)
        .await?
        .expect("familiar destination Decision is durable");
    let first_history = &finalized.evaluation.evidence["risk"]["history"]["first_destination"];
    assert_eq!(
        first_history["query"]["destination"]["value"],
        "eip155:8453:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"
    );
    assert_eq!(first_history["query"]["accounting_boundary"], "PERMITTED");
    assert_eq!(first_history["result"]["intent_id"], prior_id);

    database.seed_organization("beta-lab").await?;
    let mut beta: atf_intent::TransactionIntent =
        serde_json::from_value(sample_intent_json("01J0000000000000000000F104", "12.50"))?;
    beta.principal.organization_id = "beta-lab".into();
    beta.transaction.destination =
        Some("eip155:8453:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed".into());
    let beta_history = store
        .capture_risk_history(&beta, &enabled_rule_set, Timestamp::now_millis())
        .await?;
    let beta_first = beta_history.first_destination().unwrap();
    assert_eq!(beta_first.query().organization_id(), "beta-lab");
    assert!(beta_first.result().is_none());

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn denied_or_unnormalizable_destination_cannot_become_familiar_or_permit(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("first_destination_fail_closed").await?;
    let store = database.connect().await?;
    let denied = build_router(test_state_with_forbid_all_policy(store.clone()));
    let destination = "eip155:8453:0x3333333333333333333333333333333333333333";

    let mut denied_intent = sample_intent_json("01J0000000000000000000G101", "12.50");
    denied_intent["resource"]["resource_id"] = serde_json::json!("denied-destination-prior");
    denied_intent["transaction"]["destination"] = serde_json::json!(destination);
    assert_eq!(
        body_json(
            denied
                .oneshot(post_intent_value_request(denied_intent))
                .await?
        )
        .await?["decision"],
        "DENY"
    );

    let enabled = build_router(test_state_with_risk(
        store.clone(),
        first_destination_rule_set(true),
    ));
    let mut after_deny = sample_intent_json("01J0000000000000000000G102", "12.50");
    after_deny["resource"]["resource_id"] = serde_json::json!("denied-destination-current");
    after_deny["transaction"]["destination"] = serde_json::json!(destination);
    let after_deny = body_json(
        enabled
            .clone()
            .oneshot(post_intent_value_request(after_deny))
            .await?,
    )
    .await?;
    assert_eq!(after_deny["decision"], "REVIEW");
    assert!(after_deny["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason["code"] == "FIRST_TIME_DESTINATION"));

    let mut unsupported = sample_intent_json("01J0000000000000000000G103", "12.50");
    unsupported["resource"]["resource_id"] = serde_json::json!("unsupported-destination");
    unsupported["transaction"]["network"] = serde_json::json!("chainstd:1");
    unsupported["transaction"]["asset"] = serde_json::json!("chainstd:1/assetstd:coin");
    unsupported["transaction"]["destination"] = serde_json::json!("chainstd:1:account");
    let unsupported = body_json(
        enabled
            .oneshot(post_intent_value_request(unsupported))
            .await?,
    )
    .await?;
    assert_eq!(unsupported["decision"], "REVIEW");
    assert!(unsupported["reasons"]
        .as_array()
        .unwrap()
        .iter()
        .any(|reason| reason["code"] == "FIRST_DESTINATION_NORMALIZATION_FAILED"));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn bounded_history_excludes_future_and_other_organization_rows() -> Result<(), Box<dyn Error>>
{
    let database = provisioned_database("bounded_history").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    let prior_id = "01J0000000000000000000B100";
    let response = app.oneshot(post_intent_request(prior_id, "12.50")).await?;
    assert_eq!(body_json(response).await?["decision"], "PERMIT");
    let prior = store
        .load_finalized_decision("alpha-lab", prior_id)
        .await?
        .expect("the prior Decision is durable");
    let before_prior = Timestamp::from_datetime(
        prior.decided_at.as_datetime() - chrono::Duration::milliseconds(1),
    );
    let current: atf_intent::TransactionIntent =
        serde_json::from_value(sample_intent_json("01J0000000000000000000B200", "12.50"))?;
    let future_excluded = store
        .capture_risk_history(&current, &test_risk_rule_set(), before_prior)
        .await?;
    assert!(future_excluded
        .duplicate_purchase()
        .expect("the enabled query is recorded")
        .result()
        .is_none());
    assert!(future_excluded
        .daily_cumulative_spend()
        .expect("the enabled daily-spend query is recorded")
        .totals()
        .is_empty());

    database.seed_organization("beta-lab").await?;
    let mut other_organization = current;
    other_organization.principal.organization_id = "beta-lab".into();
    let tenant_excluded = store
        .capture_risk_history(
            &other_organization,
            &test_risk_rule_set(),
            Timestamp::now_millis(),
        )
        .await?;
    assert!(tenant_excluded
        .duplicate_purchase()
        .expect("the enabled query is recorded")
        .result()
        .is_none());
    let tenant_daily = tenant_excluded
        .daily_cumulative_spend()
        .expect("the enabled daily-spend query is recorded");
    assert_eq!(tenant_daily.query().organization_id(), "beta-lab");
    assert_eq!(tenant_daily.query().agent_id(), "research-agent-01");
    assert!(tenant_daily.totals().is_empty());

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
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 1, 7));

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
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 1, 7));
    assert_eq!(
        restarted_store
            .load_verified_audit_chain("alpha-lab")
            .await?
            .iter()
            .filter(|stored| stored.event.intent_id.is_some())
            .count(),
        7
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
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 1, 7));
    assert_eq!(
        store
            .load_verified_audit_chain("alpha-lab")
            .await?
            .iter()
            .filter(|stored| stored.event.intent_id.is_some())
            .count(),
        7
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
    assert_eq!(database.business_record_counts().await?, (1, 1, 0, 0, 0, 2));

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
        "RECOVERY_REPLAY_NOT_IMPLEMENTED"
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
        "RECOVERY_REPLAY_NOT_IMPLEMENTED"
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
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 1, 7));

    let retry = restarted_gateway
        .oneshot(post_intent_request(intent_id, "12.50"))
        .await?;
    assert_eq!(retry.status(), StatusCode::OK);
    assert_eq!(body_json(retry).await?, recovered);
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 1, 7));

    restarted_store.close().await;
    database.destroy().await?;
    Ok(())
}

async fn provisioned_database(label: &str) -> Result<TestDatabase, Box<dyn Error>> {
    let database = TestDatabase::create(label).await?;
    database.seed_organization("alpha-lab").await?;
    Ok(database)
}
