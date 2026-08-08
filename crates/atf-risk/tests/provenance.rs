use std::str::FromStr;

use atf_core::{
    EvidenceEnvelope, EvidenceKind, EvidenceSignature, EvidenceSource, EvidenceTrustPolicy,
    Timestamp, TrustedEvidenceSource,
};
use atf_intent::TransactionIntent;
use atf_risk::{evaluate_at, evaluate_with_context_at, RiskContext, RiskRuleSet};
use ed25519_dalek::Signer;

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

fn trust_policy() -> EvidenceTrustPolicy {
    EvidenceTrustPolicy::new([TrustedEvidenceSource::unsigned(
        EvidenceSource::AtfEnriched,
        "vendor-history-v1",
        [EvidenceKind::Price],
    )
    .unwrap()])
    .unwrap()
}

fn permissive_missing_rule_set() -> RiskRuleSet {
    let mut document: serde_json::Value =
        serde_json::from_str(include_str!("../../../risk-rules/default.json")).unwrap();
    document["rules"]["vendor_price_deviation"]["missing_data"] =
        serde_json::json!("NOT_APPLICABLE");
    RiskRuleSet::from_json(&document.to_string()).unwrap()
}

fn evaluate_context(
    intent: &TransactionIntent,
    context: &RiskContext,
    rule_set: &RiskRuleSet,
) -> atf_risk::RiskEvaluation {
    evaluate_with_context_at(intent, rule_set, context, timestamp("2026-08-08T12:00:00Z"))
}

#[test]
fn agent_price_context_is_insufficient_data_not_a_trusted_risk_input() {
    let intent = intent();
    assert_eq!(intent.context["historical_vendor_median"], "8.50");

    let result = evaluate_at(
        &intent,
        &RiskRuleSet::default(),
        timestamp("2026-08-08T12:00:00Z"),
    );

    assert!(result
        .iter()
        .any(|finding| finding.code == "VENDOR_PRICE_INSUFFICIENT_DATA"));
    assert!(!result
        .iter()
        .any(|finding| finding.code == "VENDOR_PRICE_DEVIATION"));
}

#[test]
fn verified_scoped_atf_evidence_drives_vendor_deviation() {
    let intent = intent();
    let evidence = vendor_median(&intent, "8.50");
    let evaluated_at = timestamp("2026-08-08T12:00:00Z");
    let context = RiskContext::from_evidence(&intent, [&evidence], &trust_policy(), evaluated_at);

    let result = evaluate_with_context_at(&intent, &RiskRuleSet::default(), &context, evaluated_at);

    assert!(result
        .iter()
        .any(|finding| finding.code == "VENDOR_PRICE_DEVIATION"));
    assert!(!result
        .iter()
        .any(|finding| finding.code == "VENDOR_PRICE_INSUFFICIENT_DATA"));
}

#[test]
fn agent_override_cannot_replace_verified_evidence() {
    let mut first = intent();
    first.context["historical_vendor_median"] = serde_json::json!("12.50");
    let mut second = first.clone();
    second.context["historical_vendor_median"] = serde_json::json!("0.01");
    let evidence = vendor_median(&first, "8.50");
    let evaluated_at = timestamp("2026-08-08T12:00:00Z");
    let first_context =
        RiskContext::from_evidence(&first, [&evidence], &trust_policy(), evaluated_at);
    let second_context =
        RiskContext::from_evidence(&second, [&evidence], &trust_policy(), evaluated_at);

    let first_result = evaluate_with_context_at(
        &first,
        &RiskRuleSet::default(),
        &first_context,
        evaluated_at,
    );
    let second_result = evaluate_with_context_at(
        &second,
        &RiskRuleSet::default(),
        &second_context,
        evaluated_at,
    );

    assert_eq!(first_result.findings, second_result.findings);
    assert!(first_result
        .iter()
        .any(|finding| finding.code == "VENDOR_PRICE_DEVIATION"));
}

#[test]
fn every_privileged_agent_context_class_is_separated_from_trusted_evidence() {
    let mut intent = intent();
    intent.context = serde_json::json!({
        "historical_vendor_median": "8.50",
        "balance": "100.00",
        "position": {"asset": "BTC", "quantity": "1.0"},
        "leverage": "5",
        "daily_cumulative_spend": "250.00",
        "protocol_risk": "high",
        "address_reputation": "new",
        "market_data_freshness": "10s",
        "simulation_result": "SAFE",
        "non_privileged_hint": "retained only as an Agent hint"
    });

    let context = RiskContext::from_evidence(
        &intent,
        [],
        &EvidenceTrustPolicy::default(),
        timestamp("2026-08-08T12:00:00Z"),
    );
    let rejected = context.rejected_agent_keys().collect::<Vec<_>>();

    for key in [
        "historical_vendor_median",
        "balance",
        "position",
        "leverage",
        "daily_cumulative_spend",
        "protocol_risk",
        "address_reputation",
        "market_data_freshness",
        "simulation_result",
    ] {
        assert!(rejected.contains(&key), "{key} must remain AGENT_PROVIDED");
    }
    assert!(!rejected.contains(&"non_privileged_hint"));
}

#[test]
fn invalid_present_evidence_is_restrictive_even_when_absence_is_not_applicable() {
    let intent = intent();
    let rule_set = permissive_missing_rule_set();
    let evaluated_at = timestamp("2026-08-08T12:00:00Z");

    let mut no_agent_price = intent.clone();
    no_agent_price
        .context
        .as_object_mut()
        .unwrap()
        .remove("historical_vendor_median");
    let absent = RiskContext::from_evidence(
        &no_agent_price,
        [],
        &EvidenceTrustPolicy::default(),
        evaluated_at,
    );
    let absent_result = evaluate_context(&no_agent_price, &absent, &rule_set);
    assert!(!absent_result.iter().any(|finding| {
        finding.code == "VENDOR_PRICE_DATA_MISSING"
            || finding.code == "VENDOR_PRICE_INSUFFICIENT_DATA"
    }));

    let stale = EvidenceEnvelope::new(
        EvidenceKind::Price,
        EvidenceSource::AtfEnriched,
        "vendor-history-v1",
        timestamp("2026-08-08T11:00:00Z"),
        timestamp("2026-08-08T11:30:00Z"),
        vendor_median(&intent, "8.50").value().clone(),
        None,
    )
    .unwrap();
    let stale_context =
        RiskContext::from_evidence(&intent, [&stale], &trust_policy(), evaluated_at);
    let stale_result = evaluate_context(&intent, &stale_context, &rule_set);
    assert!(stale_result.iter().any(|finding| {
        finding.code == "VENDOR_PRICE_INSUFFICIENT_DATA"
            && finding.message.contains("EVIDENCE_STALE")
    }));

    let valid = vendor_median(&intent, "8.50");
    let mut tampered = serde_json::to_value(&valid).unwrap();
    tampered["value"]["amount"] = serde_json::json!("0.01");
    let tampered = EvidenceEnvelope::from_json(&tampered.to_string()).unwrap();
    let tampered_context =
        RiskContext::from_evidence(&intent, [&tampered], &trust_policy(), evaluated_at);
    let tampered_result = evaluate_context(&intent, &tampered_context, &rule_set);
    assert!(tampered_result.iter().any(|finding| {
        finding.code == "VENDOR_PRICE_INSUFFICIENT_DATA"
            && finding.message.contains("EVIDENCE_HASH_MISMATCH")
    }));
}

#[test]
fn missing_required_signature_wrong_scope_and_ambiguity_fail_closed() {
    let intent = intent();
    let rule_set = permissive_missing_rule_set();
    let evaluated_at = timestamp("2026-08-08T12:00:00Z");

    let external = EvidenceEnvelope::new(
        EvidenceKind::Price,
        EvidenceSource::SignedExternalEvidence,
        "external-price-feed",
        timestamp("2026-08-08T11:59:00Z"),
        timestamp("2026-08-08T12:05:00Z"),
        vendor_median(&intent, "8.50").value().clone(),
        None,
    )
    .unwrap();
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
    let signed_policy = EvidenceTrustPolicy::new([TrustedEvidenceSource::signed_ed25519(
        EvidenceSource::SignedExternalEvidence,
        "external-price-feed",
        [EvidenceKind::Price],
        "external-key-1",
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap()])
    .unwrap();
    let unsigned_context =
        RiskContext::from_evidence(&intent, [&external], &signed_policy, evaluated_at);
    let unsigned_result = evaluate_context(&intent, &unsigned_context, &rule_set);
    assert!(unsigned_result.iter().any(|finding| {
        finding.code == "VENDOR_PRICE_INSUFFICIENT_DATA"
            && finding.message.contains("EVIDENCE_SIGNATURE_MISSING")
    }));

    let wrong_signer = ed25519_dalek::SigningKey::from_bytes(&[32; 32]);
    let invalid_proof = wrong_signer.sign(
        &external
            .signature_message("external-key-1")
            .expect("canonical signature message"),
    );
    let invalid_signature = external
        .with_signature(
            EvidenceSignature::ed25519("external-key-1", invalid_proof.to_bytes()).unwrap(),
        )
        .unwrap();
    let invalid_signature_context =
        RiskContext::from_evidence(&intent, [&invalid_signature], &signed_policy, evaluated_at);
    let invalid_signature_result = evaluate_context(&intent, &invalid_signature_context, &rule_set);
    assert!(invalid_signature_result.iter().any(|finding| {
        finding.code == "VENDOR_PRICE_INSUFFICIENT_DATA"
            && finding.message.contains("EVIDENCE_SIGNATURE_INVALID")
    }));

    let mut wrong_scope = vendor_median(&intent, "8.50");
    let mut value = serde_json::to_value(&wrong_scope).unwrap();
    value["value"]["organization_id"] = serde_json::json!("other-organization");
    value.as_object_mut().unwrap().remove("evidence_hash");
    wrong_scope = EvidenceEnvelope::new(
        EvidenceKind::Price,
        EvidenceSource::AtfEnriched,
        "vendor-history-v1",
        timestamp("2026-08-08T11:59:00Z"),
        timestamp("2026-08-08T12:05:00Z"),
        value["value"].clone(),
        None,
    )
    .unwrap();
    let scope_context =
        RiskContext::from_evidence(&intent, [&wrong_scope], &trust_policy(), evaluated_at);
    let scope_result = evaluate_context(&intent, &scope_context, &rule_set);
    assert!(scope_result.iter().any(|finding| {
        finding.code == "VENDOR_PRICE_INSUFFICIENT_DATA"
            && finding.message.contains("EVIDENCE_SCOPE_MISMATCH")
    }));

    let first = vendor_median(&intent, "8.50");
    let second = vendor_median(&intent, "12.00");
    let ambiguous =
        RiskContext::from_evidence(&intent, [&first, &second], &trust_policy(), evaluated_at);
    let ambiguous_result = evaluate_context(&intent, &ambiguous, &rule_set);
    assert!(ambiguous_result.iter().any(|finding| {
        finding.code == "VENDOR_PRICE_INSUFFICIENT_DATA"
            && finding.message.contains("EVIDENCE_AMBIGUOUS")
    }));
}

#[test]
fn unrelated_scopes_exact_duplicates_and_invalid_input_order_are_deterministic() {
    let intent = intent();
    let evaluated_at = timestamp("2026-08-08T12:00:00Z");
    let valid = vendor_median(&intent, "8.50");
    let unrelated = EvidenceEnvelope::new(
        EvidenceKind::Price,
        EvidenceSource::AtfEnriched,
        "vendor-history-v1",
        timestamp("2026-08-08T11:59:00Z"),
        timestamp("2026-08-08T12:05:00Z"),
        serde_json::json!({
            "metric": "HISTORICAL_VENDOR_MEDIAN",
            "organization_id": "alpha-lab",
            "resource_id": "different-resource",
            "asset": intent.transaction.asset,
            "amount": "1.00"
        }),
        None,
    )
    .unwrap();
    let scoped = RiskContext::from_evidence(
        &intent,
        [&unrelated, &valid, &valid],
        &trust_policy(),
        evaluated_at,
    );
    let scoped_result = evaluate_context(&intent, &scoped, &RiskRuleSet::default());
    assert!(scoped_result
        .iter()
        .any(|finding| finding.code == "VENDOR_PRICE_DEVIATION"));
    assert!(!scoped_result
        .iter()
        .any(|finding| finding.code == "VENDOR_PRICE_INSUFFICIENT_DATA"));

    let mut tampered_value = serde_json::to_value(&valid).unwrap();
    tampered_value["value"]["amount"] = serde_json::json!("0.01");
    let tampered = EvidenceEnvelope::from_json(&tampered_value.to_string()).unwrap();
    let stale = EvidenceEnvelope::new(
        EvidenceKind::Price,
        EvidenceSource::AtfEnriched,
        "vendor-history-v1",
        timestamp("2026-08-08T10:00:00Z"),
        timestamp("2026-08-08T11:00:00Z"),
        valid.value().clone(),
        None,
    )
    .unwrap();
    let first =
        RiskContext::from_evidence(&intent, [&stale, &tampered], &trust_policy(), evaluated_at);
    let second =
        RiskContext::from_evidence(&intent, [&tampered, &stale], &trust_policy(), evaluated_at);

    assert_eq!(
        evaluate_context(&intent, &first, &permissive_missing_rule_set()).findings,
        evaluate_context(&intent, &second, &permissive_missing_rule_set()).findings
    );
}

#[test]
fn risk_context_cannot_be_reused_for_a_different_intent() {
    let target = intent();
    let mut different = target.clone();
    different
        .context
        .as_object_mut()
        .unwrap()
        .remove("historical_vendor_median");
    let context = RiskContext::from_evidence(
        &different,
        [],
        &EvidenceTrustPolicy::default(),
        timestamp("2026-08-08T12:00:00Z"),
    );

    let result = evaluate_context(&target, &context, &permissive_missing_rule_set());

    assert!(result.iter().any(|finding| {
        finding.code == "VENDOR_PRICE_INSUFFICIENT_DATA"
            && finding.message.contains("EVIDENCE_CONTEXT_INTENT_MISMATCH")
    }));
}
