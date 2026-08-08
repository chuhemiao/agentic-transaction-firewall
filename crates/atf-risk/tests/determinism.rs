use std::str::FromStr;

use atf_audit::{AuditEvent, EventType};
use atf_core::{
    EvaluationContext, EvaluationContextInput, EvidenceTrustPolicyReference,
    ExternalSnapshotReference, RepositorySnapshot, SimulationReference, Timestamp,
    VersionedArtifactReference,
};
use atf_intent::{validate_profile, TransactionIntent};
use atf_risk::{evaluate_context, RiskEvaluationError, RiskRuleSet};

fn timestamp(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn fixture() -> (
    TransactionIntent,
    RiskRuleSet,
    EvaluationContext,
    Vec<AuditEvent>,
) {
    let mut intent: TransactionIntent = serde_json::from_str(include_str!(
        "../../../examples/x402-research-agent/intent.json"
    ))
    .unwrap();
    intent.expires_at = timestamp("2099-01-01T00:00:00Z");
    let rule_set = RiskRuleSet::default();
    let history = vec![AuditEvent {
        event_id: "deterministic-history-anchor-v1".into(),
        event_type: EventType::IdentityVerified,
        occurred_at: timestamp("2026-08-08T11:59:00Z"),
        intent_id: Some(intent.intent_id.clone()),
        prev_event_hash: None,
        data: serde_json::json!({}),
    }];
    let profile = validate_profile(&intent).unwrap();
    let context = EvaluationContext::new(EvaluationContextInput {
        evaluation_id: "01J0000000000000000000EVAL".into(),
        intent_id: intent.intent_id.clone(),
        intent_hash: intent.canonical_hash(),
        evaluation_time: timestamp("2026-08-08T12:00:00Z"),
        environment: "development".into(),
        profile_id: profile.id().into(),
        profile_version: profile.version().into(),
        policy: VersionedArtifactReference::unavailable("POLICY_NOT_USED").unwrap(),
        risk: VersionedArtifactReference::available(
            rule_set.engine_version(),
            rule_set.version(),
            rule_set.rule_set_hash(),
        )
        .unwrap(),
        context_snapshot_id: "01J0000000000000000000SNAP".into(),
        agent_context: intent.context.clone(),
        evidence: Vec::new(),
        evidence_trust_policy: EvidenceTrustPolicyReference::not_configured(
            "TRUST_POLICY_NOT_CONFIGURED",
        )
        .unwrap(),
        history: RepositorySnapshot::new(
            format!("audit-chain:{}:1", intent.principal.organization_id),
            1,
            history[0].canonical_hash(),
        )
        .unwrap(),
        market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_UNAVAILABLE").unwrap(),
        simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED").unwrap(),
    })
    .unwrap();
    (intent, rule_set, context, history)
}

#[test]
fn repeated_evaluation_of_one_snapshot_is_byte_equivalent() {
    let (intent, rule_set, context, history) = fixture();

    let first = evaluate_context(&intent, &rule_set, &context, history.iter()).unwrap();
    let second = evaluate_context(&intent, &rule_set, &context, history.iter()).unwrap();

    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
}

#[test]
fn history_after_the_context_boundary_cannot_change_the_result() {
    let (intent, rule_set, context, mut history) = fixture();
    let previous_hash = history.last().unwrap().canonical_hash();
    history.push(AuditEvent {
        event_id: "later-event-v1".into(),
        event_type: EventType::DecisionRecorded,
        occurred_at: timestamp("2026-08-08T12:00:01Z"),
        intent_id: Some("01J0000000000000000000LATE".into()),
        prev_event_hash: Some(previous_hash),
        data: serde_json::json!({
            "decision": "PERMIT",
            "organization_id": intent.principal.organization_id,
            "agent_id": intent.principal.agent_id,
            "resource_id": intent.resource.resource_id
        }),
    });

    let error = evaluate_context(&intent, &rule_set, &context, history.iter()).unwrap_err();

    assert!(matches!(error, RiskEvaluationError::HistoryBinding(_)));
}

#[test]
fn a_different_rule_set_cannot_run_under_the_persisted_identity() {
    let (intent, _rule_set, context, history) = fixture();
    let mut document: serde_json::Value =
        serde_json::from_str(include_str!("../../../risk-rules/default.json")).unwrap();
    document["rule_set_version"] = serde_json::json!("risk-rules-other");
    let different = RiskRuleSet::from_json(&document.to_string()).unwrap();

    let error = evaluate_context(&intent, &different, &context, history.iter()).unwrap_err();

    assert_eq!(error, RiskEvaluationError::RuleSetMismatch);
}
