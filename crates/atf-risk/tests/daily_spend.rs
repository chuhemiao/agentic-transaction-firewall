use std::str::FromStr;

use atf_core::{
    sha256_hex, AccountingBoundary, Amount, DailySpendAssetTotal, DailySpendHistory,
    DailySpendQuery, EvaluationContext, EvaluationContextInput, EvidenceEnvelope, EvidenceKind,
    EvidenceSource, EvidenceTrustPolicy, EvidenceTrustPolicyReference, ExternalSnapshotReference,
    RepositorySnapshot, RiskHistorySnapshot, SimulationReference, Timestamp, TrustedEvidenceSource,
    VerifiedEvidence, VersionedArtifactReference,
};
use atf_intent::{validate_profile, TransactionIntent};
use atf_risk::{evaluate_context, RiskEvaluation, RiskRuleSet, Severity};

const USDC: &str = "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const ETH: &str = "eip155:1/slip44:60";

fn at(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn rule_set(max_amount: &str) -> RiskRuleSet {
    let mut document: serde_json::Value =
        serde_json::from_str(include_str!("../../../risk-rules/default.json")).unwrap();
    document["rule_set_version"] = serde_json::json!("risk-rules-daily-test-v1");
    document["rules"]["max_fee_ratio"]["enabled"] = serde_json::json!(false);
    document["rules"]["max_fee_ratio"]["missing_data"] = serde_json::json!("NOT_APPLICABLE");
    document["rules"]["vendor_price_deviation"]["enabled"] = serde_json::json!(false);
    document["rules"]["vendor_price_deviation"]["missing_data"] =
        serde_json::json!("NOT_APPLICABLE");
    document["rules"]["duplicate_purchase"]["enabled"] = serde_json::json!(false);
    document["rules"]["first_time_destination"]["enabled"] = serde_json::json!(false);
    document["rules"]["request_frequency"]["enabled"] = serde_json::json!(false);
    document["rules"]["daily_cumulative_spend"] = serde_json::json!({
        "enabled": true,
        "severity": "high",
        "max_amount": max_amount,
        "valuation_asset": USDC,
        "window_seconds": 86_400,
        "accounting_boundary": "PERMITTED",
        "missing_data": "FINDING"
    });
    RiskRuleSet::from_json(&document.to_string()).unwrap()
}

fn intent(amount: &str) -> TransactionIntent {
    let mut intent: TransactionIntent = serde_json::from_str(include_str!(
        "../../../examples/x402-research-agent/intent.json"
    ))
    .unwrap();
    intent.intent_id = "01J0000000000000000000NOW0".into();
    intent.idempotency_key = "idem-daily-now".into();
    intent.created_at = at("2026-08-09T11:59:00Z");
    intent.expires_at = at("2026-08-09T12:30:00Z");
    intent.transaction.asset = USDC.into();
    intent.transaction.amount = amount.parse().unwrap();
    intent.transaction.max_fee = None;
    intent
}

fn repository(intent: &TransactionIntent) -> RepositorySnapshot {
    RepositorySnapshot::new(
        format!("audit-chain:{}:10", intent.principal.organization_id),
        10,
        sha256_hex(format!("daily-spend:{}", intent.canonical_hash()).as_bytes()),
    )
    .unwrap()
}

fn quote_policy() -> EvidenceTrustPolicy {
    EvidenceTrustPolicy::new([TrustedEvidenceSource::unsigned(
        EvidenceSource::AtfEnriched,
        "asset-quotes-v1",
        [EvidenceKind::Price],
    )
    .unwrap()])
    .unwrap()
}

fn quote(intent: &TransactionIntent, base_asset: &str, rate: &str) -> VerifiedEvidence {
    let policy = quote_policy();
    let envelope = EvidenceEnvelope::new(
        EvidenceKind::Price,
        EvidenceSource::AtfEnriched,
        "asset-quotes-v1",
        at("2026-08-09T11:59:00Z"),
        at("2026-08-09T12:05:00Z"),
        serde_json::json!({
            "metric": "ASSET_QUOTE",
            "organization_id": intent.principal.organization_id,
            "base_asset": base_asset,
            "quote_asset": USDC,
            "rate": rate
        }),
        Some(10_000),
    )
    .unwrap();
    policy
        .verify(&envelope, at("2026-08-09T12:00:00Z"))
        .unwrap()
}

fn context(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    repository: &RepositorySnapshot,
    evidence: Vec<VerifiedEvidence>,
) -> EvaluationContext {
    let profile = validate_profile(intent).unwrap();
    let evidence_trust_policy = if evidence.is_empty() {
        EvidenceTrustPolicyReference::not_configured("TRUST_POLICY_NOT_CONFIGURED").unwrap()
    } else {
        let policy = quote_policy();
        EvidenceTrustPolicyReference::configured(
            "asset-quote-trust-v1",
            policy.policy_hash().unwrap(),
        )
        .unwrap()
    };
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
        evidence,
        evidence_trust_policy,
        history: repository.clone(),
        market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_UNAVAILABLE").unwrap(),
        simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED").unwrap(),
    })
    .unwrap()
}

fn evaluate(
    current_amount: &str,
    prior_asset: &str,
    prior_amount: &str,
    evidence: Vec<VerifiedEvidence>,
    unresolved_asset_decision_count: u64,
) -> RiskEvaluation {
    let intent = intent(current_amount);
    let rule_set = rule_set("25.00");
    let repository = repository(&intent);
    let context = context(&intent, &rule_set, &repository, evidence);
    let history = DailySpendHistory::new(
        DailySpendQuery::new(
            &intent.principal.organization_id,
            &intent.principal.agent_id,
            &intent.intent_id,
            USDC,
            context.evaluation_time(),
            86_400,
            AccountingBoundary::Permitted,
        )
        .unwrap(),
        vec![
            DailySpendAssetTotal::new(prior_asset, prior_amount.parse::<Amount>().unwrap(), 2)
                .unwrap(),
        ],
        unresolved_asset_decision_count,
    )
    .unwrap();
    let history = RiskHistorySnapshot::with_daily_spend(repository, None, Some(history)).unwrap();
    evaluate_context(&intent, &rule_set, &context, &history).unwrap()
}

#[test]
fn amount_equal_to_limit_is_allowed_but_one_fixed_point_unit_over_fires() {
    let at_limit = evaluate("5.00", USDC, "20.00", Vec::new(), 0);
    assert!(!at_limit
        .iter()
        .any(|finding| finding.code == "DAILY_CUMULATIVE_SPEND_EXCEEDED"));

    let over_limit = evaluate("5.01", USDC, "20.00", Vec::new(), 0);
    assert!(over_limit.iter().any(|finding| {
        finding.code == "DAILY_CUMULATIVE_SPEND_EXCEEDED" && finding.severity == Severity::High
    }));
}

#[test]
fn missing_cross_asset_quote_is_restrictive_instead_of_silently_permitting() {
    let result = evaluate("1.00", ETH, "10.00", Vec::new(), 0);

    assert!(result.iter().any(|finding| {
        finding.code == "DAILY_SPEND_QUOTE_MISSING" && finding.severity == Severity::High
    }));
    assert!(!result
        .iter()
        .any(|finding| finding.code == "DAILY_CUMULATIVE_SPEND_EXCEEDED"));
}

#[test]
fn exact_trusted_cross_asset_quote_participates_in_the_fixed_point_sum() {
    let current = intent("6.00");
    let result = evaluate("6.00", ETH, "10.00", vec![quote(&current, ETH, "2.00")], 0);

    assert!(result
        .iter()
        .any(|finding| finding.code == "DAILY_CUMULATIVE_SPEND_EXCEEDED"));
    assert!(!result
        .iter()
        .any(|finding| finding.code == "DAILY_SPEND_QUOTE_MISSING"));
}

#[test]
fn a_permitted_row_without_bound_asset_is_restrictive() {
    let result = evaluate("1.00", USDC, "10.00", Vec::new(), 1);

    assert!(result.iter().any(|finding| {
        finding.code == "DAILY_SPEND_HISTORY_INSUFFICIENT_DATA"
            && finding.severity == Severity::High
    }));
}
