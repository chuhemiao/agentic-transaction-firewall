use std::str::FromStr;

use atf_core::{
    sha256_hex, DestinationNormalization, EvaluationContext, EvaluationContextInput,
    EvidenceTrustPolicyReference, ExternalSnapshotReference, FirstDestinationHistory,
    FirstDestinationMatch, FirstDestinationQuery, RepositorySnapshot, RiskHistorySnapshot,
    SimulationReference, Timestamp, VersionedArtifactReference,
};
use atf_intent::{
    normalize_destination, validate_profile, TransactionIntent, PAYMENT_DESTINATION_NORMALIZER_ID,
    PAYMENT_DESTINATION_NORMALIZER_VERSION,
};
use atf_risk::{evaluate_context, RiskRuleSet, Severity};

fn at(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn rule_set(severity: &str) -> RiskRuleSet {
    let mut document: serde_json::Value =
        serde_json::from_str(include_str!("../../../risk-rules/default.json")).unwrap();
    document["rule_set_version"] = serde_json::json!("risk-rules-first-destination-test-v1");
    document["rules"]["max_fee_ratio"]["enabled"] = serde_json::json!(false);
    document["rules"]["max_fee_ratio"]["missing_data"] = serde_json::json!("NOT_APPLICABLE");
    document["rules"]["vendor_price_deviation"]["enabled"] = serde_json::json!(false);
    document["rules"]["vendor_price_deviation"]["missing_data"] =
        serde_json::json!("NOT_APPLICABLE");
    document["rules"]["duplicate_purchase"]["enabled"] = serde_json::json!(false);
    document["rules"]["daily_cumulative_spend"]["enabled"] = serde_json::json!(false);
    document["rules"]["first_time_destination"] = serde_json::json!({
        "enabled": true,
        "severity": severity,
        "normalizer_id": PAYMENT_DESTINATION_NORMALIZER_ID,
        "normalizer_version": PAYMENT_DESTINATION_NORMALIZER_VERSION,
        "accounting_boundary": "PERMITTED",
        "missing_data": "FINDING"
    });
    RiskRuleSet::from_json(&document.to_string()).unwrap()
}

fn intent(destination: &str) -> TransactionIntent {
    let mut intent: TransactionIntent = serde_json::from_str(include_str!(
        "../../../examples/x402-research-agent/intent.json"
    ))
    .unwrap();
    intent.intent_id = "01J0000000000000000000NOW0".into();
    intent.idempotency_key = "idem-first-destination-now".into();
    intent.created_at = at("2026-08-09T11:59:00Z");
    intent.expires_at = at("2026-08-09T12:30:00Z");
    intent.transaction.destination = Some(destination.into());
    intent.transaction.max_fee = None;
    intent
}

fn repository(intent: &TransactionIntent) -> RepositorySnapshot {
    RepositorySnapshot::new(
        format!("audit-chain:{}:10", intent.principal.organization_id),
        10,
        sha256_hex(format!("first-destination:{}", intent.canonical_hash()).as_bytes()),
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
    prior: Option<FirstDestinationMatch>,
    organization_id: &str,
) -> RiskHistorySnapshot {
    let destination = match normalize_destination(intent) {
        Ok(value) => DestinationNormalization::available(value.value()).unwrap(),
        Err(error) => DestinationNormalization::unavailable(error.code()).unwrap(),
    };
    let first = FirstDestinationHistory::new(
        FirstDestinationQuery::new(
            organization_id,
            &intent.intent_id,
            context.profile_id(),
            context.profile_version(),
            rule_set.first_destination_normalizer_id().unwrap(),
            rule_set.first_destination_normalizer_version().unwrap(),
            destination,
            context.evaluation_time(),
            rule_set.first_destination_accounting_boundary().unwrap(),
        )
        .unwrap(),
        prior,
    )
    .unwrap();
    RiskHistorySnapshot::with_first_destination(context.history().clone(), None, None, Some(first))
        .unwrap()
}

#[test]
fn first_normalized_destination_emits_configured_review_or_deny_severity() {
    for (configured, expected) in [("high", Severity::High), ("critical", Severity::Critical)] {
        let rule_set = rule_set(configured);
        let intent = intent("eip155:8453:0x1111111111111111111111111111111111111111");
        let repository = repository(&intent);
        let context = context(&intent, &rule_set, &repository);
        let history = history(
            &intent,
            &context,
            &rule_set,
            None,
            &intent.principal.organization_id,
        );

        let evaluation = evaluate_context(&intent, &rule_set, &context, &history).unwrap();
        assert!(evaluation.iter().any(|finding| {
            finding.code == "FIRST_TIME_DESTINATION" && finding.severity == expected
        }));
    }
}

#[test]
fn prior_permitted_normalized_destination_suppresses_first_time_finding() {
    let rule_set = rule_set("high");
    let intent = intent("eip155:8453:0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    let repository = repository(&intent);
    let context = context(&intent, &rule_set, &repository);
    let prior = FirstDestinationMatch::new(
        "01J0000000000000000000OLD0",
        "01J0000000000000000000DEC0",
        "01J0000000000000000000EVT0",
        9,
        at("2026-08-09T11:00:00Z"),
    )
    .unwrap();
    let history = history(
        &intent,
        &context,
        &rule_set,
        Some(prior),
        &intent.principal.organization_id,
    );

    let evaluation = evaluate_context(&intent, &rule_set, &context, &history).unwrap();
    assert!(!evaluation
        .iter()
        .any(|finding| finding.code == "FIRST_TIME_DESTINATION"));
}

#[test]
fn unsupported_destination_namespace_is_restrictive() {
    let rule_set = rule_set("high");
    let mut intent = intent("chainstd:1:account");
    intent.transaction.network = "chainstd:1".into();
    intent.transaction.asset = "chainstd:1/assetstd:coin".into();
    let repository = repository(&intent);
    let context = context(&intent, &rule_set, &repository);
    let history = history(
        &intent,
        &context,
        &rule_set,
        None,
        &intent.principal.organization_id,
    );

    let evaluation = evaluate_context(&intent, &rule_set, &context, &history).unwrap();
    assert!(evaluation.iter().any(|finding| {
        finding.code == "FIRST_DESTINATION_NORMALIZATION_FAILED"
            && finding.severity == Severity::High
    }));
}

#[test]
fn destination_history_tenant_binding_is_exact() {
    let rule_set = rule_set("high");
    let intent = intent("eip155:8453:0x1111111111111111111111111111111111111111");
    let repository = repository(&intent);
    let context = context(&intent, &rule_set, &repository);
    let wrong_tenant = history(&intent, &context, &rule_set, None, "beta-lab");

    assert!(evaluate_context(&intent, &rule_set, &context, &wrong_tenant).is_err());
}
