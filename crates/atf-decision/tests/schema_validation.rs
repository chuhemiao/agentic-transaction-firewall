//! Confirms that real `atf_decision::Decision` output validates against the
//! closed public Schema for all four outcomes.

use std::str::FromStr;

use atf_core::{
    Amount, EvaluationContext, EvaluationContextInput, EvidenceTrustPolicyReference,
    ExternalSnapshotReference, RepositorySnapshot, SimulationReference, Timestamp,
    VersionedArtifactReference,
};
use atf_decision::{
    decide, Decision, DecisionInput, DecisionKind, PolicyDecisionInput, RiskDecisionInput,
};
use atf_intent::{
    validate_profile, Action, Mandate, Principal, Resource, Transaction, TransactionIntent,
};
use atf_policy::{PolicyDecision, PolicyOutcome};
use atf_risk::{RiskEvaluation, RiskFinding, Severity};

const SCHEMA_STR: &str = include_str!("../../../schemas/decision.schema.json");

fn timestamp(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn sample_intent() -> TransactionIntent {
    TransactionIntent {
        spec_version: "1.0".into(),
        intent_id: "01J00000000000000000000000".into(),
        idempotency_key: "idem-1".into(),
        created_at: timestamp("2026-07-18T08:00:00Z"),
        expires_at: timestamp("2026-07-18T08:05:00Z"),
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
            resource_type: Some("dataset".into()),
        },
        transaction: Transaction {
            network: "eip155:8453".into(),
            asset: "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".into(),
            amount: Amount::from_str("12.50").unwrap(),
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

fn context(intent: &TransactionIntent) -> EvaluationContext {
    let profile = validate_profile(intent).unwrap();
    EvaluationContext::new(EvaluationContextInput {
        evaluation_id: "evaluation-1".into(),
        intent_id: intent.intent_id.clone(),
        intent_hash: intent.canonical_hash(),
        evaluation_time: timestamp("2026-07-18T08:00:01Z"),
        environment: "development".into(),
        profile_id: profile.id().into(),
        profile_version: profile.version().into(),
        policy: VersionedArtifactReference::available("bundle-1", "1.0.0", "a".repeat(64)).unwrap(),
        risk: VersionedArtifactReference::available("risk-v1", "1.0.0", "b".repeat(64)).unwrap(),
        context_snapshot_id: "snapshot-1".into(),
        agent_context: intent.context.clone(),
        evidence: Vec::new(),
        evidence_trust_policy: EvidenceTrustPolicyReference::not_configured("NO_EXTERNAL_EVIDENCE")
            .unwrap(),
        history: RepositorySnapshot::new("audit-chain:alpha-lab:1", 1, "c".repeat(64)).unwrap(),
        market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_NOT_CONFIGURED").unwrap(),
        simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED").unwrap(),
    })
    .unwrap()
}

fn policy(decision: PolicyDecision) -> PolicyOutcome {
    PolicyOutcome {
        decision,
        policy_ids: vec!["test-policy".into()],
        bundle_id: "bundle-1".into(),
        policy_version: "1.0.0".into(),
        bundle_hash: "a".repeat(64),
    }
}

fn risk(findings: Vec<RiskFinding>) -> RiskEvaluation {
    RiskEvaluation {
        rule_set_version: "1.0.0".into(),
        rule_set_hash: "b".repeat(64),
        findings,
    }
}

fn assert_valid_against_schema(decision: &Decision) {
    let schema_value: serde_json::Value = serde_json::from_str(SCHEMA_STR).unwrap();
    let validator = jsonschema::validator_for(&schema_value).expect("schema itself is valid");
    let instance = serde_json::to_value(decision).unwrap();
    let errors = validator
        .iter_errors(&instance)
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    assert!(
        errors.is_empty(),
        "Decision {instance:#} failed Schema validation: {errors:?}"
    );
}

fn evaluated_decision(policy_decision: PolicyDecision, findings: Vec<RiskFinding>) -> Decision {
    let intent = sample_intent();
    let context = context(&intent);
    let policy = policy(policy_decision);
    let risk = risk(findings);
    let risk_input = if policy_decision == PolicyDecision::Permit {
        RiskDecisionInput::Evaluated(&risk)
    } else {
        RiskDecisionInput::NotRun {
            reason_code: "POLICY_FORBID",
        }
    };
    decide(DecisionInput {
        decision_id: "decision-1".into(),
        intent: &intent,
        evaluation_context: &context,
        policy: PolicyDecisionInput::Evaluated(&policy),
        risk: risk_input,
    })
    .unwrap()
}

#[test]
fn all_four_outcomes_match_the_closed_schema() {
    let permit = evaluated_decision(PolicyDecision::Permit, Vec::new());
    let deny = evaluated_decision(PolicyDecision::Forbid, Vec::new());
    let review = evaluated_decision(
        PolicyDecision::Permit,
        vec![RiskFinding {
            code: "TEST_FINDING".into(),
            severity: Severity::High,
            message: "test".into(),
        }],
    );

    let intent = sample_intent();
    let context = context(&intent);
    let error = decide(DecisionInput {
        decision_id: "decision-error".into(),
        intent: &intent,
        evaluation_context: &context,
        policy: PolicyDecisionInput::Error {
            error_code: "POLICY_EVALUATION_ERROR",
        },
        risk: RiskDecisionInput::NotRun {
            reason_code: "POLICY_ERROR",
        },
    })
    .unwrap();

    for (decision, expected) in [
        (permit, DecisionKind::Permit),
        (deny, DecisionKind::Deny),
        (review, DecisionKind::Review),
        (error, DecisionKind::Error),
    ] {
        assert_eq!(decision.decision, expected);
        assert_valid_against_schema(&decision);
    }
}

#[test]
fn schema_rejects_unknown_core_fields() {
    let decision = evaluated_decision(PolicyDecision::Permit, Vec::new());
    let schema_value: serde_json::Value = serde_json::from_str(SCHEMA_STR).unwrap();
    let validator = jsonschema::validator_for(&schema_value).unwrap();
    let mut instance = serde_json::to_value(decision).unwrap();
    instance["unreviewed_extension"] = serde_json::json!(true);

    assert!(!validator.is_valid(&instance));
}
