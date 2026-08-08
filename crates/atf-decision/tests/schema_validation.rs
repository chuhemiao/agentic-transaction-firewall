//! Confirms that real `atf_decision::Decision` output (not a hand-written
//! fixture) actually validates against `schemas/decision.schema.json`, so
//! the schema can't silently drift from the Rust type it's meant to
//! describe.

use std::path::Path;
use std::str::FromStr;

use atf_core::{Amount, Timestamp};
use atf_decision::{decide, DecisionKind};
use atf_intent::{Action, Mandate, Principal, Resource, Transaction, TransactionIntent};
use atf_policy::{PolicyBundle, PolicyBundleLoadContext};
use atf_risk::{RiskFinding, Severity};

const SCHEMA_STR: &str = include_str!("../../../schemas/decision.schema.json");

fn sample_intent(amount: &str) -> TransactionIntent {
    TransactionIntent {
        spec_version: "1.0".into(),
        intent_id: "01J00000000000000000000000".into(),
        idempotency_key: "idem-1".into(),
        created_at: Timestamp::from_str("2026-07-18T08:00:00Z").unwrap(),
        expires_at: Timestamp::from_str("2099-01-01T00:00:00Z").unwrap(),
        principal: Principal {
            organization_id: "alpha-lab".into(),
            user_id: None,
            agent_id: "research-agent-01".into(),
            agent_version: None,
            strategy_id: None,
        },
        mandate: Mandate {
            mandate_id: "mandate-001".into(),
            task_id: None,
            purpose: "test".into(),
            budget_id: None,
            human_authorized: true,
        },
        action: Action {
            category: "payment".into(),
            operation: "purchase_api_resource".into(),
        },
        resource: Resource {
            protocol: "x402".into(),
            venue: None,
            resource_id: "btc-orderbook-2026-07-01".into(),
            resource_type: None,
        },
        transaction: Transaction {
            network: "eip155:8453".into(),
            asset: "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".into(),
            amount: Amount::from_str(amount).unwrap(),
            destination: Some("eip155:8453:0x1111111111111111111111111111111111111111".into()),
            contract: None,
            calldata_hash: None,
            max_fee: None,
            slippage_bps: None,
            leverage: None,
        },
        context: serde_json::json!({}),
        metadata: serde_json::json!({}),
    }
}

fn assert_valid_against_schema(decision: &atf_decision::Decision) {
    let schema_value: serde_json::Value = serde_json::from_str(SCHEMA_STR).unwrap();
    let validator = jsonschema::validator_for(&schema_value).expect("schema itself is valid");
    let instance = serde_json::to_value(decision).unwrap();

    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "Decision {instance:#} failed schema validation: {errors:?}"
    );
}

#[test]
fn a_permit_decision_matches_the_schema() {
    let bundle = policy_bundle();
    let intent = sample_intent("12.50");
    let policy = bundle.evaluate_at(&intent, evaluation_time());
    let decision = decide(&intent, policy, &[]);
    assert_eq!(decision.decision, DecisionKind::Permit);
    assert_valid_against_schema(&decision);
}

#[test]
fn a_deny_decision_matches_the_schema() {
    let bundle = policy_bundle();
    let intent = sample_intent("999.00");
    let policy = bundle.evaluate_at(&intent, evaluation_time());
    let decision = decide(&intent, policy, &[]);
    assert_eq!(decision.decision, DecisionKind::Deny);
    assert_valid_against_schema(&decision);
}

#[test]
fn a_review_decision_matches_the_schema() {
    let bundle = policy_bundle();
    let intent = sample_intent("12.50");
    let policy = bundle.evaluate_at(&intent, evaluation_time());
    let finding = RiskFinding {
        code: "TEST_FINDING".to_string(),
        severity: Severity::High,
        message: "test".to_string(),
    };
    let decision = decide(&intent, policy, &[finding]);
    assert_eq!(decision.decision, DecisionKind::Review);
    assert_valid_against_schema(&decision);
}

#[test]
fn an_error_decision_matches_the_schema() {
    let bundle = policy_bundle();
    // Cedar's `decimal` extension supports at most 4 fractional digits.
    let intent = sample_intent("12.123456");
    let policy = bundle.evaluate_at(&intent, evaluation_time());
    let decision = decide(&intent, policy, &[]);
    assert_eq!(decision.decision, DecisionKind::Error);
    assert_valid_against_schema(&decision);
}

fn policy_bundle() -> PolicyBundle {
    let evaluated_at = evaluation_time();
    PolicyBundle::from_dir(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies/examples"),
        &PolicyBundleLoadContext {
            organization_id: "alpha-lab".into(),
            environment: "development".into(),
            evaluated_at,
        },
    )
    .unwrap()
}

fn evaluation_time() -> Timestamp {
    Timestamp::from_str("2026-08-08T12:00:00Z").unwrap()
}
