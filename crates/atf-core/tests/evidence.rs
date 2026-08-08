use std::str::FromStr;

use atf_core::{
    EvidenceEnvelope, EvidenceError, EvidenceFreshness, EvidenceKind, EvidenceSignature,
    EvidenceSource, EvidenceTrustPolicy, Timestamp, TrustedEvidenceSource,
};
use ed25519_dalek::{Signer, SigningKey};

fn timestamp(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

fn price_value() -> serde_json::Value {
    serde_json::json!({
        "metric": "HISTORICAL_VENDOR_MEDIAN",
        "organization_id": "alpha-lab",
        "resource_id": "btc-orderbook-2026-07-01",
        "asset": "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        "amount": "12.00"
    })
}

fn price_evidence(value: serde_json::Value) -> EvidenceEnvelope {
    EvidenceEnvelope::new(
        EvidenceKind::Price,
        EvidenceSource::AtfEnriched,
        "vendor-history-v1",
        timestamp("2026-08-08T11:59:00Z"),
        timestamp("2026-08-08T12:05:00Z"),
        value,
        Some(9_500),
    )
    .unwrap()
}

#[test]
fn evidence_hash_is_canonical_and_binds_every_payload_field() {
    let baseline = price_evidence(price_value());
    let reordered = price_evidence(serde_json::json!({
        "amount": "12.00",
        "asset": "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
        "resource_id": "btc-orderbook-2026-07-01",
        "organization_id": "alpha-lab",
        "metric": "HISTORICAL_VENDOR_MEDIAN"
    }));

    assert_eq!(baseline.evidence_hash(), reordered.evidence_hash());
    assert_eq!(
        baseline.evidence_hash(),
        "47e567d9f7c7157b5be8698415ce6fbf60bc034e74781c0c4debd4d7de3e2cc4"
    );

    for candidate in [
        EvidenceEnvelope::new(
            EvidenceKind::Balance,
            EvidenceSource::AtfEnriched,
            "vendor-history-v1",
            baseline.observed_at(),
            baseline.expires_at(),
            price_value(),
            Some(9_500),
        )
        .unwrap(),
        EvidenceEnvelope::new(
            EvidenceKind::Price,
            EvidenceSource::AdapterProvided,
            "vendor-history-v1",
            baseline.observed_at(),
            baseline.expires_at(),
            price_value(),
            Some(9_500),
        )
        .unwrap(),
        EvidenceEnvelope::new(
            EvidenceKind::Price,
            EvidenceSource::AtfEnriched,
            "vendor-history-v2",
            baseline.observed_at(),
            baseline.expires_at(),
            price_value(),
            Some(9_500),
        )
        .unwrap(),
        price_evidence(serde_json::json!({"amount": "13.00"})),
    ] {
        assert_ne!(baseline.evidence_hash(), candidate.evidence_hash());
    }
}

#[test]
fn tampering_and_unknown_fields_fail_closed() {
    let baseline = price_evidence(price_value());
    let mut tampered = serde_json::to_value(&baseline).unwrap();
    tampered["value"]["amount"] = serde_json::json!("0.01");
    let tampered = EvidenceEnvelope::from_json(&tampered.to_string()).unwrap();
    assert!(matches!(
        tampered.verify_hash(),
        Err(EvidenceError::HashMismatch)
    ));

    let mut unknown = serde_json::to_value(&baseline).unwrap();
    unknown["unexpected"] = serde_json::json!(true);
    assert!(EvidenceEnvelope::from_json(&unknown.to_string()).is_err());
}

#[test]
fn freshness_is_derived_from_the_explicit_evaluation_time() {
    let evidence = price_evidence(price_value());

    assert_eq!(
        evidence.freshness_at(timestamp("2026-08-08T11:58:59.999Z")),
        EvidenceFreshness::NotYetValid
    );
    assert_eq!(
        evidence.freshness_at(evidence.observed_at()),
        EvidenceFreshness::Fresh
    );
    assert_eq!(
        evidence.freshness_at(timestamp("2026-08-08T12:04:59.999Z")),
        EvidenceFreshness::Fresh
    );
    assert_eq!(
        evidence.freshness_at(evidence.expires_at()),
        EvidenceFreshness::Stale
    );
}

#[test]
fn exact_source_and_kind_allowlists_are_authority_not_self_declared_source_names() {
    assert!(TrustedEvidenceSource::unsigned(
        EvidenceSource::AgentProvided,
        "agent-self-assertion",
        [EvidenceKind::Price],
    )
    .is_err());
    assert!(TrustedEvidenceSource::unsigned(
        EvidenceSource::SignedExternalEvidence,
        "unsigned-external",
        [EvidenceKind::Price],
    )
    .is_err());

    let policy = EvidenceTrustPolicy::new([TrustedEvidenceSource::unsigned(
        EvidenceSource::AtfEnriched,
        "vendor-history-v1",
        [EvidenceKind::Price],
    )
    .unwrap()])
    .unwrap();
    let at = timestamp("2026-08-08T12:00:00Z");
    assert!(policy.verify(&price_evidence(price_value()), at).is_ok());

    let wrong_source_id = EvidenceEnvelope::new(
        EvidenceKind::Price,
        EvidenceSource::AtfEnriched,
        "vendor-history-v2",
        timestamp("2026-08-08T11:59:00Z"),
        timestamp("2026-08-08T12:05:00Z"),
        price_value(),
        None,
    )
    .unwrap();
    assert!(matches!(
        policy.verify(&wrong_source_id, at),
        Err(EvidenceError::UntrustedSource)
    ));

    let wrong_kind = EvidenceEnvelope::new(
        EvidenceKind::Balance,
        EvidenceSource::AtfEnriched,
        "vendor-history-v1",
        timestamp("2026-08-08T11:59:00Z"),
        timestamp("2026-08-08T12:05:00Z"),
        serde_json::json!({"amount": "12.00"}),
        None,
    )
    .unwrap();
    assert!(matches!(
        policy.verify(&wrong_kind, at),
        Err(EvidenceError::KindNotAllowed)
    ));
}

#[test]
fn required_ed25519_proof_is_strict_and_binds_key_id_and_hash() {
    let signing_key = SigningKey::from_bytes(&[23; 32]);
    let trust = TrustedEvidenceSource::signed_ed25519(
        EvidenceSource::SignedExternalEvidence,
        "external-price-feed",
        [EvidenceKind::Price],
        "feed-key-1",
        signing_key.verifying_key().to_bytes(),
    )
    .unwrap();
    let policy = EvidenceTrustPolicy::new([trust]).unwrap();
    let at = timestamp("2026-08-08T12:00:00Z");
    let unsigned = EvidenceEnvelope::new(
        EvidenceKind::Price,
        EvidenceSource::SignedExternalEvidence,
        "external-price-feed",
        timestamp("2026-08-08T11:59:00Z"),
        timestamp("2026-08-08T12:05:00Z"),
        price_value(),
        Some(9_900),
    )
    .unwrap();
    assert!(matches!(
        policy.verify(&unsigned, at),
        Err(EvidenceError::MissingSignature)
    ));

    let signature = signing_key.sign(&unsigned.signature_message("feed-key-1").unwrap());
    let signed = unsigned
        .clone()
        .with_signature(EvidenceSignature::ed25519("feed-key-1", signature.to_bytes()).unwrap())
        .unwrap();
    let verified = policy.verify(&signed, at).unwrap();
    assert_eq!(verified.freshness_status(), EvidenceFreshness::Fresh);
    assert_eq!(verified.evidence_hash(), signed.evidence_hash());
    assert_eq!(verified.observed_at(), signed.observed_at());
    assert_eq!(verified.expires_at(), signed.expires_at());
    assert_eq!(verified.confidence_bps(), Some(9_900));

    let wrong_signer = SigningKey::from_bytes(&[24; 32]);
    let invalid_signature = wrong_signer.sign(&unsigned.signature_message("feed-key-1").unwrap());
    let invalid = unsigned
        .with_signature(
            EvidenceSignature::ed25519("feed-key-1", invalid_signature.to_bytes()).unwrap(),
        )
        .unwrap();
    assert!(matches!(
        policy.verify(&invalid, at),
        Err(EvidenceError::SignatureInvalid)
    ));
}

#[test]
fn stale_not_yet_valid_and_hash_mismatch_have_explicit_error_codes() {
    let policy = EvidenceTrustPolicy::new([TrustedEvidenceSource::unsigned(
        EvidenceSource::AtfEnriched,
        "vendor-history-v1",
        [EvidenceKind::Price],
    )
    .unwrap()])
    .unwrap();
    let evidence = price_evidence(price_value());
    assert!(matches!(
        policy.verify(&evidence, timestamp("2026-08-08T11:58:59Z")),
        Err(EvidenceError::NotYetValid)
    ));
    assert!(matches!(
        policy.verify(&evidence, evidence.expires_at()),
        Err(EvidenceError::Stale)
    ));

    let mut tampered = serde_json::to_value(&evidence).unwrap();
    tampered["value"]["amount"] = serde_json::json!("0.01");
    let tampered = EvidenceEnvelope::from_json(&tampered.to_string()).unwrap();
    assert!(matches!(
        policy.verify(&tampered, timestamp("2026-08-08T12:00:00Z")),
        Err(EvidenceError::HashMismatch)
    ));
}

#[test]
fn public_schema_and_runtime_enforce_the_same_closed_numeric_free_contract() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/evidence.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    let baseline = price_evidence(price_value());
    let baseline_value = serde_json::to_value(&baseline).unwrap();
    assert!(validator.is_valid(&baseline_value));

    for (pointer, replacement) in [
        ("/value/amount", serde_json::json!(12.0)),
        ("/confidence_bps", serde_json::json!(10_001)),
        ("/evidence_version", serde_json::json!("2")),
        ("/evidence_hash", serde_json::json!("A".repeat(64))),
    ] {
        let mut candidate = baseline_value.clone();
        *candidate.pointer_mut(pointer).unwrap() = replacement;
        assert!(!validator.is_valid(&candidate), "Schema accepted {pointer}");
        assert!(
            EvidenceEnvelope::from_json(&candidate.to_string()).is_err(),
            "runtime accepted {pointer}"
        );
    }

    for field in ["confidence_bps", "signature"] {
        let mut candidate = baseline_value.clone();
        candidate[field] = serde_json::Value::Null;
        assert!(!validator.is_valid(&candidate));
        assert!(EvidenceEnvelope::from_json(&candidate.to_string()).is_err());
    }
}

#[test]
fn internally_constructed_evidence_is_bounded_by_the_full_envelope_size() {
    let value = serde_json::json!({"payload": "x".repeat(65_300)});

    assert!(matches!(
        EvidenceEnvelope::new(
            EvidenceKind::ProtocolRisk,
            EvidenceSource::AtfEnriched,
            "risk-enricher-v1",
            timestamp("2026-08-08T11:59:00Z"),
            timestamp("2026-08-08T12:05:00Z"),
            value,
            None,
        ),
        Err(EvidenceError::Invalid(_))
    ));
}
