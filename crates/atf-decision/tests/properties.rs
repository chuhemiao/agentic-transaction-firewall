use std::str::FromStr;

use atf_core::{
    sha256_hex, sort_json_keys, Amount, EvaluationContext, EvaluationContextInput,
    EvidenceTrustPolicyReference, ExternalSnapshotReference, RepositorySnapshot,
    RiskHistorySnapshot, SimulationReference, Timestamp, VersionedArtifactReference,
};
use atf_decision::{decide, Decision, DecisionInput, PolicyDecisionInput, RiskDecisionInput};
use atf_intent::{
    validate_profile, Action, Mandate, Principal, Resource, Transaction, TransactionIntent,
};
use atf_policy::{PolicyDecision, PolicyOutcome};
use atf_risk::RiskEvaluation;
use proptest::prelude::*;
use serde_json::{json, Value};

const DECISION_HASH_DOMAIN: &[u8] = b"ATF_DECISION_V1\0";

fn timestamp(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn intent() -> TransactionIntent {
    TransactionIntent {
        spec_version: "1.0".into(),
        intent_id: "01J00000000000000000000000".into(),
        idempotency_key: "idem-ds037-properties".into(),
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
            mandate_id: "mandate-ds037".into(),
            task_id: None,
            purpose: "exercise every Decision binding class".into(),
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
            resource_id: "dataset-ds037".into(),
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
        context: json!({"hint": "untrusted"}),
        metadata: json!({}),
    }
}

fn context(intent: &TransactionIntent) -> EvaluationContext {
    let profile = validate_profile(intent).unwrap();
    EvaluationContext::new(EvaluationContextInput {
        evaluation_id: "evaluation-ds037".into(),
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
        context_snapshot_id: "snapshot-ds037".into(),
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

fn decision(intent: &TransactionIntent, context: &EvaluationContext) -> Decision {
    let policy = PolicyOutcome {
        decision: PolicyDecision::Permit,
        policy_ids: vec!["payment-under-cap".into()],
        bundle_id: "payment-policy".into(),
        policy_version: "1.2.3".into(),
        bundle_hash: "a".repeat(64),
    };
    let risk = RiskEvaluation {
        rule_set_version: "2.3.4".into(),
        rule_set_hash: "b".repeat(64),
        findings: Vec::new(),
        history: RiskHistorySnapshot::new(
            RepositorySnapshot::new("audit-chain:alpha-lab:1", 1, "c".repeat(64)).unwrap(),
            None,
        )
        .unwrap(),
    };
    decide(DecisionInput {
        decision_id: "decision-ds037".into(),
        intent,
        evaluation_context: context,
        policy: PolicyDecisionInput::Evaluated(&policy),
        risk: RiskDecisionInput::Evaluated(&risk),
    })
    .unwrap()
}

fn mutated_hash(salt: u64, class: &str) -> String {
    sha256_hex(format!("DS-037:{class}:{salt}").as_bytes())
}

fn reseal(baseline: &Decision, pointer: &str, replacement: Value) -> Decision {
    let mut value = serde_json::to_value(baseline).unwrap();
    *value
        .pointer_mut(pointer)
        .unwrap_or_else(|| panic!("missing Decision pointer {pointer}")) = replacement;

    let mut payload = value.clone();
    payload.as_object_mut().unwrap().remove("decision_hash");
    let canonical = serde_json::to_vec(&sort_json_keys(payload)).unwrap();
    let mut input = Vec::with_capacity(DECISION_HASH_DOMAIN.len() + canonical.len());
    input.extend_from_slice(DECISION_HASH_DOMAIN);
    input.extend_from_slice(&canonical);
    value
        .as_object_mut()
        .unwrap()
        .insert("decision_hash".into(), Value::String(sha256_hex(&input)));

    serde_json::from_value(value).unwrap()
}

fn binding_rejects(
    baseline: &Decision,
    intent: &TransactionIntent,
    context: &EvaluationContext,
    pointer: &str,
    replacement: Value,
) -> bool {
    let mutated = reseal(baseline, pointer, replacement);
    mutated != *baseline
        && mutated.verify_hash().is_ok()
        && mutated.verify_binding(intent, context).is_err()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn amount_is_always_a_lossless_json_string(
        whole in 0_u64..1_000_000_000_000_u64,
        fraction in 0_u32..1_000_000_u32,
        scale in 0_usize..7_usize,
    ) {
        let decimal = if scale == 0 {
            whole.to_string()
        } else {
            let modulus = 10_u32.pow(scale as u32);
            format!("{whole}.{:0scale$}", fraction % modulus)
        };
        let amount = Amount::from_str(&decimal).unwrap();

        let encoded = serde_json::to_value(amount).unwrap();
        prop_assert_eq!(encoded.as_str(), Some(decimal.as_str()));
        prop_assert_eq!(serde_json::from_value::<Amount>(encoded).unwrap(), amount);
        prop_assert!(serde_json::from_str::<Amount>(&amount.to_string()).is_err());
    }

    #[test]
    fn intent_and_evaluation_bindings_reject_resealed_substitution(salt in any::<u64>()) {
        let intent = intent();
        let context = context(&intent);
        let baseline = decision(&intent, &context);
        let mutations = [
            ("/intent_id", json!(format!("mutated-intent-{salt}"))),
            ("/intent_hash", json!(mutated_hash(salt, "intent"))),
            ("/evaluation_id", json!(format!("mutated-evaluation-{salt}"))),
        ];

        for (pointer, replacement) in mutations {
            prop_assert!(binding_rejects(&baseline, &intent, &context, pointer, replacement),
                "resealed {pointer} substitution escaped binding verification");
        }
    }

    #[test]
    fn profile_binding_rejects_resealed_substitution(salt in any::<u64>()) {
        let intent = intent();
        let context = context(&intent);
        let baseline = decision(&intent, &context);
        let mutations = [
            ("/profile/id", json!(format!("mutated-profile-{salt}"))),
            ("/profile/version", json!(format!("9.{salt}"))),
        ];

        for (pointer, replacement) in mutations {
            prop_assert!(binding_rejects(&baseline, &intent, &context, pointer, replacement),
                "resealed {pointer} substitution escaped binding verification");
        }
    }

    #[test]
    fn policy_binding_rejects_every_resealed_reference_mutation(salt in any::<u64>()) {
        let intent = intent();
        let context = context(&intent);
        let baseline = decision(&intent, &context);
        let mutations = [
            ("/policy/artifact_id", json!(format!("mutated-policy-{salt}"))),
            ("/policy/version", json!(format!("9.{salt}"))),
            ("/policy/hash", json!(mutated_hash(salt, "policy"))),
        ];

        for (pointer, replacement) in mutations {
            prop_assert!(binding_rejects(&baseline, &intent, &context, pointer, replacement),
                "resealed {pointer} substitution escaped binding verification");
        }
    }

    #[test]
    fn risk_binding_rejects_every_resealed_reference_mutation(salt in any::<u64>()) {
        let intent = intent();
        let context = context(&intent);
        let baseline = decision(&intent, &context);
        let mutations = [
            ("/risk/artifact_id", json!(format!("mutated-risk-{salt}"))),
            ("/risk/version", json!(format!("9.{salt}"))),
            ("/risk/hash", json!(mutated_hash(salt, "risk"))),
        ];

        for (pointer, replacement) in mutations {
            prop_assert!(binding_rejects(&baseline, &intent, &context, pointer, replacement),
                "resealed {pointer} substitution escaped binding verification");
        }
    }

    #[test]
    fn context_and_snapshot_bindings_reject_resealed_substitution(salt in any::<u64>()) {
        let intent = intent();
        let context = context(&intent);
        let baseline = decision(&intent, &context);
        let mutations = [
            ("/evaluation_context_hash", json!(mutated_hash(salt, "context"))),
            ("/context_snapshot_hash", json!(mutated_hash(salt, "snapshot"))),
        ];

        for (pointer, replacement) in mutations {
            prop_assert!(binding_rejects(&baseline, &intent, &context, pointer, replacement),
                "resealed {pointer} substitution escaped binding verification");
        }
    }

    #[test]
    fn simulation_binding_rejects_resealed_substitution(salt in any::<u64>()) {
        let intent = intent();
        let context = context(&intent);
        let baseline = decision(&intent, &context);
        let replacement = json!(format!("MUTATED_SIMULATION_{salt}"));

        prop_assert!(binding_rejects(
            &baseline,
            &intent,
            &context,
            "/simulation/reason_code",
            replacement,
        ));
    }

    #[test]
    fn time_and_expiry_bindings_reject_resealed_substitution(second in 2_u8..60_u8) {
        let intent = intent();
        let context = context(&intent);
        let baseline = decision(&intent, &context);
        let mutations = [
            ("/evaluation_time", json!(format!("2026-08-08T12:00:{second:02}.000Z"))),
            ("/expires_at", json!(format!("2026-08-08T12:04:{second:02}.000Z"))),
        ];

        for (pointer, replacement) in mutations {
            prop_assert!(binding_rejects(&baseline, &intent, &context, pointer, replacement),
                "resealed {pointer} substitution escaped binding verification");
        }
    }

    #[test]
    fn execution_constraints_reject_every_resealed_mutation(salt in any::<u64>()) {
        let intent = intent();
        let context = context(&intent);
        let baseline = decision(&intent, &context);
        let mutations = [
            ("/execution_constraints/action_category", json!(format!("category-{salt}"))),
            ("/execution_constraints/action_operation", json!(format!("operation-{salt}"))),
            ("/execution_constraints/resource_id", json!(format!("resource-{salt}"))),
            ("/execution_constraints/resource_protocol", json!(format!("protocol-{salt}"))),
            ("/execution_constraints/network", json!(format!("network-{salt}"))),
            ("/execution_constraints/asset", json!(format!("asset-{salt}"))),
            ("/execution_constraints/max_amount", json!(format!("{}.{:02}", salt % 10_000 + 1, salt % 100))),
            ("/execution_constraints/destination", json!(format!("destination-{salt}"))),
            ("/execution_constraints/adapter_id", json!(format!("adapter-{salt}"))),
        ];

        for (pointer, replacement) in mutations {
            prop_assert!(binding_rejects(&baseline, &intent, &context, pointer, replacement),
                "resealed {pointer} substitution escaped binding verification");
        }
    }

    #[test]
    fn approval_and_obligation_bindings_reject_resealed_substitution(salt in any::<u64>()) {
        let intent = intent();
        let context = context(&intent);
        let baseline = decision(&intent, &context);
        let mutations = [
            ("/required_approvals", json!([{"role": format!("approver-{salt}"), "count": 1}])),
            ("/obligations", json!([{"type": format!("obligation-{salt}")}]))
        ];

        for (pointer, replacement) in mutations {
            prop_assert!(binding_rejects(&baseline, &intent, &context, pointer, replacement),
                "resealed {pointer} substitution escaped binding verification");
        }
    }
}
