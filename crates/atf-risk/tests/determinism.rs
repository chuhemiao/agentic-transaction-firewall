use std::str::FromStr;

use atf_core::{
    AccountingBoundary, DuplicatePurchaseHistory, DuplicatePurchaseQuery, EvaluationContext,
    EvaluationContextInput, EvidenceTrustPolicyReference, ExternalSnapshotReference,
    RepositorySnapshot, RiskHistorySnapshot, SimulationReference, Timestamp,
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
    RiskHistorySnapshot,
) {
    let mut intent: TransactionIntent = serde_json::from_str(include_str!(
        "../../../examples/x402-research-agent/intent.json"
    ))
    .unwrap();
    intent.expires_at = timestamp("2099-01-01T00:00:00Z");
    let rule_set = RiskRuleSet::default();
    let repository = RepositorySnapshot::new(
        format!("audit-chain:{}:1", intent.principal.organization_id),
        1,
        "a".repeat(64),
    )
    .unwrap();
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
        history: repository.clone(),
        market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_UNAVAILABLE").unwrap(),
        simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED").unwrap(),
    })
    .unwrap();
    let duplicate_purchase = DuplicatePurchaseHistory::new(
        DuplicatePurchaseQuery::new(
            &intent.principal.organization_id,
            &intent.principal.agent_id,
            &intent.resource.resource_id,
            &intent.intent_id,
            context.evaluation_time(),
            86_400,
            AccountingBoundary::Permitted,
        )
        .unwrap(),
        None,
    )
    .unwrap();
    let history = RiskHistorySnapshot::new(repository, Some(duplicate_purchase)).unwrap();
    (intent, rule_set, context, history)
}

#[test]
fn repeated_evaluation_of_one_snapshot_is_byte_equivalent() {
    let (intent, rule_set, context, history) = fixture();

    let first = evaluate_context(&intent, &rule_set, &context, &history).unwrap();
    let second = evaluate_context(&intent, &rule_set, &context, &history).unwrap();

    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );
}

#[test]
fn history_after_the_context_boundary_cannot_change_the_result() {
    let (intent, rule_set, context, _) = fixture();
    let later_repository = RepositorySnapshot::new(
        format!("audit-chain:{}:2", intent.principal.organization_id),
        2,
        "b".repeat(64),
    )
    .unwrap();
    let history = RiskHistorySnapshot::new(later_repository, None).unwrap();

    let error = evaluate_context(&intent, &rule_set, &context, &history).unwrap_err();

    assert!(matches!(error, RiskEvaluationError::HistoryBinding(_)));
}

#[test]
fn a_different_rule_set_cannot_run_under_the_persisted_identity() {
    let (intent, _rule_set, context, history) = fixture();
    let mut document: serde_json::Value =
        serde_json::from_str(include_str!("../../../risk-rules/default.json")).unwrap();
    document["rule_set_version"] = serde_json::json!("risk-rules-other");
    let different = RiskRuleSet::from_json(&document.to_string()).unwrap();

    let error = evaluate_context(&intent, &different, &context, &history).unwrap_err();

    assert_eq!(error, RiskEvaluationError::RuleSetMismatch);
}
