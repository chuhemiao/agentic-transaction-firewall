use std::str::FromStr;

use atf_core::{
    Amount, EvaluationContext, EvaluationContextInput, EvidenceTrustPolicyReference,
    ExternalSnapshotReference, RepositorySnapshot, SimulationReference, Timestamp,
    VersionedArtifactReference,
};
use atf_decision::{decide, DecisionInput, PolicyDecisionInput, RiskDecisionInput};
use atf_intent::{
    validate_profile, Action, Mandate, Principal, Resource, Transaction, TransactionIntent,
};
use atf_policy::{PolicyDecision, PolicyOutcome};
use atf_risk::RiskEvaluation;

fn timestamp(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn intent() -> TransactionIntent {
    TransactionIntent {
        spec_version: "1.0".into(),
        intent_id: "01J00000000000000000000000".into(),
        idempotency_key: "idem-1".into(),
        created_at: timestamp("2026-08-08T12:00:00Z"),
        expires_at: timestamp("2026-08-08T12:05:00Z"),
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
            purpose: "purchase historical order-book data".into(),
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
        context: serde_json::json!({"hint": "untrusted"}),
        metadata: serde_json::json!({}),
    }
}

fn context(intent: &TransactionIntent) -> EvaluationContext {
    let profile = validate_profile(intent).unwrap();
    EvaluationContext::new(EvaluationContextInput {
        evaluation_id: "evaluation-1".into(),
        intent_id: intent.intent_id.clone(),
        intent_hash: intent.canonical_hash(),
        evaluation_time: timestamp("2026-08-08T12:00:01Z"),
        environment: "development".into(),
        profile_id: profile.id().into(),
        profile_version: profile.version().into(),
        policy: VersionedArtifactReference::available("payment-policy", "1.2.3", "a".repeat(64))
            .unwrap(),
        risk: VersionedArtifactReference::available("atf-risk-engine-v1", "2.3.4", "b".repeat(64))
            .unwrap(),
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

fn policy() -> PolicyOutcome {
    PolicyOutcome {
        decision: PolicyDecision::Permit,
        policy_ids: vec!["payment-under-cap".into()],
        bundle_id: "payment-policy".into(),
        policy_version: "1.2.3".into(),
        bundle_hash: "a".repeat(64),
    }
}

fn risk() -> RiskEvaluation {
    RiskEvaluation {
        rule_set_version: "2.3.4".into(),
        rule_set_hash: "b".repeat(64),
        findings: Vec::new(),
    }
}

fn decision() -> atf_decision::Decision {
    let intent = intent();
    let context = context(&intent);
    let policy = policy();
    let risk = risk();
    decide(DecisionInput {
        decision_id: "decision-1".into(),
        intent: &intent,
        evaluation_context: &context,
        policy: PolicyDecisionInput::Evaluated(&policy),
        risk: RiskDecisionInput::Evaluated(&risk),
    })
    .unwrap()
}

#[test]
fn one_snapshot_and_decision_id_produce_byte_equivalent_output() {
    let first = decision();
    let second = decision();

    assert_eq!(first.canonical_bytes(), second.canonical_bytes());
    assert_eq!(first.decision_hash, second.decision_hash);
    first.verify_hash().unwrap();
}

#[test]
fn every_bound_input_mutation_invalidates_the_decision_hash() {
    let baseline = decision();
    let mutations = [
        ("/intent_hash", serde_json::json!("d".repeat(64))),
        ("/profile/version", serde_json::json!("9.9")),
        ("/policy/hash", serde_json::json!("e".repeat(64))),
        ("/risk/hash", serde_json::json!("f".repeat(64))),
        (
            "/evaluation_context_hash",
            serde_json::json!("0".repeat(64)),
        ),
        ("/context_snapshot_hash", serde_json::json!("1".repeat(64))),
        (
            "/simulation/reason_code",
            serde_json::json!("DIFFERENT_REASON"),
        ),
        (
            "/evaluation_time",
            serde_json::json!("2026-08-08T12:00:02.000Z"),
        ),
        ("/expires_at", serde_json::json!("2026-08-08T12:04:59.000Z")),
        (
            "/execution_constraints/max_amount",
            serde_json::json!("12.49"),
        ),
    ];

    for (pointer, replacement) in mutations {
        let mut value = serde_json::to_value(&baseline).unwrap();
        *value.pointer_mut(pointer).unwrap() = replacement;
        let mutated: atf_decision::Decision = serde_json::from_value(value).unwrap();
        assert!(
            mutated.verify_hash().is_err(),
            "mutation at {pointer} retained a valid Decision hash"
        );
    }
}

#[test]
fn decision_binding_must_match_the_intent_and_context() {
    let intent = intent();
    let context = context(&intent);
    let policy = policy();
    let risk = risk();
    let decision = decide(DecisionInput {
        decision_id: "decision-1".into(),
        intent: &intent,
        evaluation_context: &context,
        policy: PolicyDecisionInput::Evaluated(&policy),
        risk: RiskDecisionInput::Evaluated(&risk),
    })
    .unwrap();

    decision.verify_binding(&intent, &context).unwrap();

    let mut different_intent = intent.clone();
    different_intent.transaction.amount = Amount::from_str("12.51").unwrap();
    assert!(decision
        .verify_binding(&different_intent, &context)
        .is_err());
}

#[test]
fn module_output_from_a_different_artifact_is_rejected() {
    let intent = intent();
    let context = context(&intent);
    let mut policy = policy();
    policy.bundle_hash = "9".repeat(64);
    let risk = risk();

    let error = decide(DecisionInput {
        decision_id: "decision-1".into(),
        intent: &intent,
        evaluation_context: &context,
        policy: PolicyDecisionInput::Evaluated(&policy),
        risk: RiskDecisionInput::Evaluated(&risk),
    })
    .unwrap_err();

    assert_eq!(error.code(), "DECISION_POLICY_BINDING_MISMATCH");
}
