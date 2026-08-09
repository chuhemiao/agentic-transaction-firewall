use atf_core::{
    DecisionKind, EvaluationContext, EvaluationContextInput, EvidenceTrustPolicyReference,
    ExternalSnapshotReference, RepositorySnapshot, RiskHistorySnapshot, SimulationReference,
    Timestamp, VersionedArtifactReference,
};
use atf_decision::{decide, DecisionInput, PolicyDecisionInput, RiskDecisionInput};
use atf_policy::{PolicyDecision, PolicyOutcome};
use atf_risk::{RiskEvaluation, RiskFinding};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplayVector {
    schema_version: u32,
    fixture_id: String,
    intent: serde_json::Value,
    context: ContextVector,
    original: DecisionVector,
    counterfactual: CounterfactualVector,
    lineage: LineageVector,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextVector {
    evaluation_time: Timestamp,
    environment: String,
    context_snapshot_id: String,
    history_snapshot_id: String,
    history_through_sequence: u64,
    history_snapshot_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionVector {
    evaluation_id: String,
    decision_id: String,
    policy: ArtifactVector,
    risk: ArtifactVector,
    policy_ids: Vec<String>,
    expected_decision: DecisionKind,
    expected_context_hash: String,
    expected_decision_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CounterfactualVector {
    evaluation_id: String,
    decision_id: String,
    policy: ArtifactVector,
    risk: ArtifactVector,
    policy_ids: Vec<String>,
    risk_finding: RiskFinding,
    expected_decision: DecisionKind,
    expected_context_hash: String,
    expected_decision_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactVector {
    artifact_id: String,
    version: String,
    hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LineageVector {
    authoritative: bool,
    same_intent: bool,
    same_snapshot: bool,
    different_evaluation_id: bool,
    different_decision_id: bool,
    outcome_changed: bool,
}

#[test]
fn original_and_counterfactual_vectors_lock_hashes_and_lineage() {
    let vector: ReplayVector = serde_json::from_str(include_str!(
        "../../../conformance/replay-tests/decision-hashes.json"
    ))
    .expect("DS-037 Replay vector must be closed valid JSON");
    assert_eq!(vector.schema_version, 1);
    assert_eq!(vector.fixture_id, "ds037-replay-decision-hashes-v1");
    assert!(!vector.lineage.authoritative);

    let intent = atf_intent::validate(&serde_json::to_string(&vector.intent).unwrap())
        .expect("Replay vector Intent must pass the public validator");
    let profile = atf_intent::validate_profile(&intent).unwrap();
    let history = RepositorySnapshot::new(
        vector.context.history_snapshot_id,
        vector.context.history_through_sequence,
        vector.context.history_snapshot_hash,
    )
    .unwrap();
    let original_policy = artifact(&vector.original.policy);
    let original_risk = artifact(&vector.original.risk);
    let original_context = EvaluationContext::new(EvaluationContextInput {
        evaluation_id: vector.original.evaluation_id.clone(),
        intent_id: intent.intent_id.clone(),
        intent_hash: intent.canonical_hash(),
        evaluation_time: vector.context.evaluation_time,
        environment: vector.context.environment,
        profile_id: profile.id().into(),
        profile_version: profile.version().into(),
        policy: original_policy.clone(),
        risk: original_risk.clone(),
        context_snapshot_id: vector.context.context_snapshot_id,
        agent_context: intent.context.clone(),
        evidence: Vec::new(),
        evidence_trust_policy: EvidenceTrustPolicyReference::not_configured(
            "TRUST_POLICY_NOT_CONFIGURED",
        )
        .unwrap(),
        history: history.clone(),
        market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_SNAPSHOT_UNAVAILABLE")
            .unwrap(),
        simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED").unwrap(),
    })
    .unwrap();
    let original_decision = decide_for(
        &intent,
        &original_context,
        &vector.original.decision_id,
        &vector.original.policy_ids,
        &vector.original.policy,
        &vector.original.risk,
        Vec::new(),
        &history,
    );

    let selected_policy = artifact(&vector.counterfactual.policy);
    let selected_risk = artifact(&vector.counterfactual.risk);
    let counterfactual_context = original_context
        .derive_counterfactual(
            vector.counterfactual.evaluation_id.clone(),
            selected_policy,
            selected_risk,
        )
        .unwrap();
    assert!(original_context.is_newly_constructed());
    assert_eq!(
        counterfactual_context.is_newly_constructed(),
        vector.lineage.authoritative,
        "a counterfactual Context must not become persistable authority"
    );
    let counterfactual_decision = decide_for(
        &intent,
        &counterfactual_context,
        &vector.counterfactual.decision_id,
        &vector.counterfactual.policy_ids,
        &vector.counterfactual.policy,
        &vector.counterfactual.risk,
        vec![vector.counterfactual.risk_finding],
        &history,
    );

    assert_eq!(
        (
            original_context.evaluation_context_hash(),
            original_decision.decision_hash.as_str(),
            counterfactual_context.evaluation_context_hash(),
            counterfactual_decision.decision_hash.as_str(),
        ),
        (
            vector.original.expected_context_hash.as_str(),
            vector.original.expected_decision_hash.as_str(),
            vector.counterfactual.expected_context_hash.as_str(),
            vector.counterfactual.expected_decision_hash.as_str(),
        ),
        "update only after reviewing an intentional canonical Replay contract change"
    );
    assert_eq!(
        original_decision.decision,
        vector.original.expected_decision
    );
    assert_eq!(
        counterfactual_decision.decision,
        vector.counterfactual.expected_decision
    );
    assert_eq!(
        counterfactual_context.intent_id() == original_context.intent_id(),
        vector.lineage.same_intent
    );
    assert_eq!(
        counterfactual_context.context_snapshot_hash() == original_context.context_snapshot_hash(),
        vector.lineage.same_snapshot
    );
    assert_eq!(
        counterfactual_context.evaluation_id() != original_context.evaluation_id(),
        vector.lineage.different_evaluation_id
    );
    assert_eq!(
        counterfactual_decision.decision_id != original_decision.decision_id,
        vector.lineage.different_decision_id
    );
    assert_eq!(
        counterfactual_decision.decision != original_decision.decision,
        vector.lineage.outcome_changed
    );
    original_decision
        .verify_binding(&intent, &original_context)
        .unwrap();
    counterfactual_decision
        .verify_binding(&intent, &counterfactual_context)
        .unwrap();
}

fn artifact(vector: &ArtifactVector) -> VersionedArtifactReference {
    VersionedArtifactReference::available(&vector.artifact_id, &vector.version, &vector.hash)
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
fn decide_for(
    intent: &atf_intent::TransactionIntent,
    context: &EvaluationContext,
    decision_id: &str,
    policy_ids: &[String],
    policy_artifact: &ArtifactVector,
    risk_artifact: &ArtifactVector,
    findings: Vec<RiskFinding>,
    history: &RepositorySnapshot,
) -> atf_decision::Decision {
    let policy = PolicyOutcome {
        decision: PolicyDecision::Permit,
        policy_ids: policy_ids.to_vec(),
        bundle_id: policy_artifact.artifact_id.clone(),
        policy_version: policy_artifact.version.clone(),
        bundle_hash: policy_artifact.hash.clone(),
    };
    let risk = RiskEvaluation {
        rule_set_version: risk_artifact.version.clone(),
        rule_set_hash: risk_artifact.hash.clone(),
        findings,
        history: RiskHistorySnapshot::new(history.clone(), None).unwrap(),
    };
    decide(DecisionInput {
        decision_id: decision_id.into(),
        intent,
        evaluation_context: context,
        policy: PolicyDecisionInput::Evaluated(&policy),
        risk: RiskDecisionInput::Evaluated(&risk),
    })
    .unwrap()
}
