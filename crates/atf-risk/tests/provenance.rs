use std::str::FromStr;

use atf_core::{
    sha256_hex, DailySpendHistory, DailySpendQuery, DuplicatePurchaseHistory,
    DuplicatePurchaseQuery, EvaluationContext, EvaluationContextInput, EvidenceEnvelope,
    EvidenceKind, EvidenceSource, EvidenceTrustPolicy, EvidenceTrustPolicyReference,
    ExternalSnapshotReference, RepositorySnapshot, RiskHistorySnapshot, SimulationReference,
    Timestamp, TrustedEvidenceSource, VerifiedEvidence, VersionedArtifactReference,
};
use atf_intent::{validate_profile, TransactionIntent};
use atf_risk::{evaluate_context, RiskEvaluationError, RiskRuleSet};

fn timestamp(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn intent() -> TransactionIntent {
    let mut intent: TransactionIntent = serde_json::from_str(include_str!(
        "../../../examples/x402-research-agent/intent.json"
    ))
    .unwrap();
    intent.expires_at = timestamp("2099-01-01T00:00:00Z");
    intent
}

fn trust_policy() -> EvidenceTrustPolicy {
    EvidenceTrustPolicy::new([TrustedEvidenceSource::unsigned(
        EvidenceSource::AtfEnriched,
        "vendor-history-v1",
        [EvidenceKind::Price],
    )
    .unwrap()])
    .unwrap()
}

fn vendor_median(intent: &TransactionIntent, amount: &str) -> EvidenceEnvelope {
    EvidenceEnvelope::new(
        EvidenceKind::Price,
        EvidenceSource::AtfEnriched,
        "vendor-history-v1",
        timestamp("2026-08-08T11:59:00Z"),
        timestamp("2026-08-08T12:05:00Z"),
        serde_json::json!({
            "metric": "HISTORICAL_VENDOR_MEDIAN",
            "organization_id": intent.principal.organization_id,
            "resource_id": intent.resource.resource_id,
            "asset": intent.transaction.asset,
            "amount": amount
        }),
        Some(9_500),
    )
    .unwrap()
}

fn anchor(intent: &TransactionIntent) -> RepositorySnapshot {
    RepositorySnapshot::new(
        format!("audit-chain:{}:1", intent.principal.organization_id),
        1,
        sha256_hex(format!("test-history:{}", intent.canonical_hash()).as_bytes()),
    )
    .unwrap()
}

fn context(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    anchor: &RepositorySnapshot,
    evidence: Vec<VerifiedEvidence>,
    policy: Option<&EvidenceTrustPolicy>,
) -> EvaluationContext {
    let profile = validate_profile(intent).unwrap();
    let evidence_trust_policy = match policy {
        Some(policy) => EvidenceTrustPolicyReference::configured(
            "vendor-trust-v1",
            policy.policy_hash().unwrap(),
        )
        .unwrap(),
        None => {
            EvidenceTrustPolicyReference::not_configured("TRUST_POLICY_NOT_CONFIGURED").unwrap()
        }
    };
    EvaluationContext::new(EvaluationContextInput {
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
        evidence,
        evidence_trust_policy,
        history: anchor.clone(),
        market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_UNAVAILABLE").unwrap(),
        simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED").unwrap(),
    })
    .unwrap()
}

fn history(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    context: &EvaluationContext,
) -> RiskHistorySnapshot {
    let duplicate = rule_set.duplicate_purchase_enabled().then(|| {
        DuplicatePurchaseHistory::new(
            DuplicatePurchaseQuery::new(
                &intent.principal.organization_id,
                &intent.principal.agent_id,
                &intent.resource.resource_id,
                &intent.intent_id,
                context.evaluation_time(),
                rule_set.duplicate_purchase_window_seconds(),
                rule_set.duplicate_purchase_accounting_boundary(),
            )
            .unwrap(),
            None,
        )
        .unwrap()
    });
    let daily = rule_set.daily_spend_enabled().then(|| {
        DailySpendHistory::new(
            DailySpendQuery::new(
                &intent.principal.organization_id,
                &intent.principal.agent_id,
                &intent.intent_id,
                rule_set.daily_spend_valuation_asset().unwrap(),
                context.evaluation_time(),
                rule_set.daily_spend_window_seconds().unwrap(),
                rule_set.daily_spend_accounting_boundary().unwrap(),
            )
            .unwrap(),
            Vec::new(),
            0,
        )
        .unwrap()
    });
    RiskHistorySnapshot::with_daily_spend(context.history().clone(), duplicate, daily).unwrap()
}

#[test]
fn agent_vendor_values_cannot_suppress_or_create_a_trusted_finding() {
    let rule_set = RiskRuleSet::default();
    let mut first = intent();
    first.context["historical_vendor_median"] = serde_json::json!("12.50");
    let mut second = first.clone();
    second.context["historical_vendor_median"] = serde_json::json!("0.01");
    let first_anchor = anchor(&first);
    let second_anchor = anchor(&second);
    let first_context = context(&first, &rule_set, &first_anchor, Vec::new(), None);
    let second_context = context(&second, &rule_set, &second_anchor, Vec::new(), None);

    let first_result = evaluate_context(
        &first,
        &rule_set,
        &first_context,
        &history(&first, &rule_set, &first_context),
    )
    .unwrap();
    let second_result = evaluate_context(
        &second,
        &rule_set,
        &second_context,
        &history(&second, &rule_set, &second_context),
    )
    .unwrap();

    assert_eq!(
        first_result.rule_set_version,
        second_result.rule_set_version
    );
    assert_eq!(first_result.rule_set_hash, second_result.rule_set_hash);
    assert_eq!(first_result.findings, second_result.findings);
    assert!(first_result
        .iter()
        .any(|finding| finding.code == "VENDOR_PRICE_DATA_MISSING"));
    assert!(!first_result
        .iter()
        .any(|finding| finding.code == "VENDOR_PRICE_DEVIATION"));
}

#[test]
fn only_context_persisted_verified_evidence_drives_vendor_deviation() {
    let intent = intent();
    let rule_set = RiskRuleSet::default();
    let anchor = anchor(&intent);
    let policy = trust_policy();
    let evidence = policy
        .verify(
            &vendor_median(&intent, "8.50"),
            timestamp("2026-08-08T12:00:00Z"),
        )
        .unwrap();
    let context = context(&intent, &rule_set, &anchor, vec![evidence], Some(&policy));

    let result = evaluate_context(
        &intent,
        &rule_set,
        &context,
        &history(&intent, &rule_set, &context),
    )
    .unwrap();

    assert!(result
        .iter()
        .any(|finding| finding.code == "VENDOR_PRICE_DEVIATION"));
    assert!(!result
        .iter()
        .any(|finding| finding.code == "VENDOR_PRICE_DATA_MISSING"));
}

#[test]
fn context_cannot_be_reused_for_a_different_intent() {
    let original = intent();
    let rule_set = RiskRuleSet::default();
    let anchor = anchor(&original);
    let context = context(&original, &rule_set, &anchor, Vec::new(), None);
    let mut changed = original.clone();
    changed.context["historical_vendor_median"] = serde_json::json!("0.01");

    let error = evaluate_context(
        &changed,
        &rule_set,
        &context,
        &history(&original, &rule_set, &context),
    )
    .unwrap_err();

    assert!(matches!(error, RiskEvaluationError::ContextBinding(_)));
}
