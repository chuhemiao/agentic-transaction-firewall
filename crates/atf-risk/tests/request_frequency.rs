use std::str::FromStr;

use atf_core::{
    sha256_hex, AccountingBoundary, EvaluationContext, EvaluationContextInput,
    EvidenceTrustPolicyReference, ExternalSnapshotReference, RepositorySnapshot,
    RequestFrequencyActionScope, RequestFrequencyHistory, RequestFrequencyQuery,
    RequestFrequencySubject, RiskHistorySnapshot, SimulationReference, Timestamp,
    VersionedArtifactReference,
};
use atf_intent::{validate_profile, TransactionIntent};
use atf_risk::{evaluate_context, RiskRuleSet, Severity};

fn at(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn rule_set(max_requests: u64) -> RiskRuleSet {
    let mut document: serde_json::Value =
        serde_json::from_str(include_str!("../../../risk-rules/default.json")).unwrap();
    document["rule_set_version"] = serde_json::json!("risk-rules-frequency-test-v1");
    document["rules"]["max_fee_ratio"]["enabled"] = serde_json::json!(false);
    document["rules"]["max_fee_ratio"]["missing_data"] = serde_json::json!("NOT_APPLICABLE");
    document["rules"]["vendor_price_deviation"]["enabled"] = serde_json::json!(false);
    document["rules"]["vendor_price_deviation"]["missing_data"] =
        serde_json::json!("NOT_APPLICABLE");
    document["rules"]["duplicate_purchase"]["enabled"] = serde_json::json!(false);
    document["rules"]["daily_cumulative_spend"]["enabled"] = serde_json::json!(false);
    document["rules"]["first_time_destination"]["enabled"] = serde_json::json!(false);
    document["rules"]["request_frequency"] = serde_json::json!({
        "enabled": true,
        "severity": "high",
        "subject": "AGENT",
        "action_scope": "PROFILE",
        "max_requests": max_requests,
        "window_seconds": 60,
        "accounting_boundary": "REQUESTED",
        "missing_data": "FINDING"
    });
    RiskRuleSet::from_json(&document.to_string()).unwrap()
}

fn intent() -> TransactionIntent {
    let mut intent: TransactionIntent = serde_json::from_str(include_str!(
        "../../../examples/x402-research-agent/intent.json"
    ))
    .unwrap();
    intent.intent_id = "01J0000000000000000000NOW0".into();
    intent.idempotency_key = "idem-frequency-now".into();
    intent.created_at = at("2026-08-09T11:59:00Z");
    intent.expires_at = at("2026-08-09T12:30:00Z");
    intent.transaction.max_fee = None;
    intent
}

fn repository(intent: &TransactionIntent) -> RepositorySnapshot {
    RepositorySnapshot::new(
        format!("audit-chain:{}:10", intent.principal.organization_id),
        10,
        sha256_hex(format!("request-frequency:{}", intent.canonical_hash()).as_bytes()),
    )
    .unwrap()
}

fn context(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    repository: &RepositorySnapshot,
) -> EvaluationContext {
    let profile = validate_profile(intent).unwrap();
    EvaluationContext::new(EvaluationContextInput {
        evaluation_id: "01J0000000000000000000EVAL".into(),
        intent_id: intent.intent_id.clone(),
        intent_hash: intent.canonical_hash(),
        evaluation_time: at("2026-08-09T12:00:00Z"),
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
    .unwrap()
}

fn history(
    intent: &TransactionIntent,
    context: &EvaluationContext,
    rule_set: &RiskRuleSet,
    request_count: u64,
    unresolved_scope_request_count: u64,
    organization_id: &str,
) -> RiskHistorySnapshot {
    let frequency = RequestFrequencyHistory::new(
        RequestFrequencyQuery::new(
            organization_id,
            &intent.principal.agent_id,
            &intent.intent_id,
            context.profile_id(),
            context.profile_version(),
            &intent.action.category,
            &intent.action.operation,
            RequestFrequencySubject::Agent,
            RequestFrequencyActionScope::Profile,
            context.evaluation_time(),
            rule_set.request_frequency_window_seconds().unwrap(),
            rule_set.request_frequency_max_requests().unwrap(),
            AccountingBoundary::Requested,
        )
        .unwrap(),
        request_count,
        unresolved_scope_request_count,
    )
    .unwrap();
    RiskHistorySnapshot::with_request_frequency(
        context.history().clone(),
        None,
        None,
        None,
        Some(frequency),
    )
    .unwrap()
}

#[test]
fn threshold_is_inclusive_and_the_next_accepted_request_is_restrictive() {
    let intent = intent();
    let rule_set = rule_set(10);
    let repository = repository(&intent);
    let context = context(&intent, &rule_set, &repository);

    let at_limit = evaluate_context(
        &intent,
        &rule_set,
        &context,
        &history(&intent, &context, &rule_set, 10, 0, "alpha-lab"),
    )
    .unwrap();
    assert!(!at_limit
        .iter()
        .any(|finding| finding.code == "REQUEST_FREQUENCY_EXCEEDED"));

    let over = evaluate_context(
        &intent,
        &rule_set,
        &context,
        &history(&intent, &context, &rule_set, 11, 0, "alpha-lab"),
    )
    .unwrap();
    assert!(over.iter().any(|finding| {
        finding.code == "REQUEST_FREQUENCY_EXCEEDED" && finding.severity == Severity::High
    }));
}

#[test]
fn unresolved_legacy_requested_scope_is_restrictive() {
    let intent = intent();
    let rule_set = rule_set(10);
    let repository = repository(&intent);
    let context = context(&intent, &rule_set, &repository);
    let evaluation = evaluate_context(
        &intent,
        &rule_set,
        &context,
        &history(&intent, &context, &rule_set, 1, 2, "alpha-lab"),
    )
    .unwrap();

    assert!(evaluation.iter().any(|finding| {
        finding.code == "REQUEST_FREQUENCY_SCOPE_UNRESOLVED" && finding.severity == Severity::High
    }));
}

#[test]
fn request_frequency_history_tenant_binding_is_exact() {
    let intent = intent();
    let rule_set = rule_set(10);
    let repository = repository(&intent);
    let context = context(&intent, &rule_set, &repository);
    let wrong_tenant = history(&intent, &context, &rule_set, 1, 0, "beta-lab");

    assert!(evaluate_context(&intent, &rule_set, &context, &wrong_tenant).is_err());
}
