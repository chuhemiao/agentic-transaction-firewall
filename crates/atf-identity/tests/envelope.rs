use atf_identity::{EnvelopeVerificationContext, IdentityEnvelope, IdentityKeyRecord};
use atf_intent::TransactionIntent;
use ed25519_dalek::{Signer, SigningKey};

use atf_identity::{AgentRecord, AgentStatus, IdentityRegistry, VerifiedIdentity};

const VECTOR: &str = include_str!("../../../conformance/identity-vectors/atf-intent-v1.json");

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut decoded = [0_u8; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    decoded
}

fn vector() -> serde_json::Value {
    serde_json::from_str(VECTOR).expect("vector is valid JSON")
}

fn intent() -> TransactionIntent {
    let raw = serde_json::to_string(&vector()["intent"]).expect("intent vector serializes");
    atf_intent::validate(&raw).expect("intent vector passes every supported validation layer")
}

fn envelope() -> IdentityEnvelope {
    serde_json::from_value(vector()["envelope"].clone()).expect("envelope is valid")
}

fn context() -> EnvelopeVerificationContext<'static> {
    EnvelopeVerificationContext {
        audience: "atf-gateway",
        environment: "production",
        verification_time: "2098-12-31T23:58:30.000Z".parse().unwrap(),
    }
}

fn signing_key() -> SigningKey {
    let vector = vector();
    SigningKey::from_bytes(&decode_hex(vector["test_key_seed_hex"].as_str().unwrap()))
}

fn key_record(key_id: &str, key: ed25519_dalek::VerifyingKey) -> IdentityKeyRecord {
    IdentityKeyRecord::from_public_key_bytes(
        "research-agent-01".into(),
        key_id.into(),
        &key.to_bytes(),
        "2098-01-01T00:00:00.000Z".parse().unwrap(),
        Some("2099-01-01T00:00:00.000Z".parse().unwrap()),
        None,
    )
    .unwrap()
}

fn signature() -> [u8; 64] {
    decode_hex(vector()["signature_hex"].as_str().unwrap())
}

fn agent_record() -> AgentRecord {
    AgentRecord {
        agent_id: "research-agent-01".into(),
        organization_id: "alpha-lab".into(),
        owner_user_id: "user-001".into(),
        agent_type: "research".into(),
        model_provider: "test".into(),
        model_name: "deterministic-vector".into(),
        agent_version: "1.0.0".into(),
        code_hash: "a".repeat(64),
        deployment_environment: "production".into(),
        allowed_tools: Vec::new(),
        allowed_adapters: Vec::new(),
        default_budget: None,
        risk_tier: "standard".into(),
        status: AgentStatus::Active,
        created_at: "2098-01-01T00:00:00.000Z".parse().unwrap(),
        expires_at: Some("2099-01-01T00:00:00.000Z".parse().unwrap()),
    }
}

fn registry() -> IdentityRegistry {
    registry_for(agent_record())
}

fn registry_for(record: AgentRecord) -> IdentityRegistry {
    let mut registry = IdentityRegistry::new();
    registry.register_agent(record).unwrap();
    registry
        .register_key(key_record(
            "identity-key-2026-01",
            signing_key().verifying_key(),
        ))
        .unwrap();
    registry
}

#[test]
fn canonical_bytes_match_the_published_cross_language_vector() {
    let vector = vector();
    let envelope: IdentityEnvelope =
        serde_json::from_value(vector["envelope"].clone()).expect("envelope is valid");

    let canonical = envelope.canonical_bytes();

    assert_eq!(
        std::str::from_utf8(&canonical).expect("canonical envelope is UTF-8"),
        vector["canonical_utf8"].as_str().unwrap()
    );
    assert_eq!(encode_hex(&canonical), vector["canonical_hex"]);
}

#[test]
fn validation_rejects_every_trusted_context_binding_mismatch() {
    let intent = intent();
    let context = context();
    let mut cases = Vec::new();

    let mut wrong_domain = envelope();
    wrong_domain.domain = "OTHER_PROTOCOL".into();
    cases.push((wrong_domain, "IDENTITY_DOMAIN_MISMATCH"));

    let mut wrong_organization = envelope();
    wrong_organization.organization_id = "other-lab".into();
    cases.push((wrong_organization, "IDENTITY_ORGANIZATION_MISMATCH"));

    let mut wrong_agent = envelope();
    wrong_agent.agent_id = "other-agent".into();
    cases.push((wrong_agent, "IDENTITY_AGENT_MISMATCH"));

    let mut wrong_hash = envelope();
    wrong_hash.intent_hash = "0".repeat(64);
    cases.push((wrong_hash, "IDENTITY_INTENT_HASH_MISMATCH"));

    let mut wrong_audience = envelope();
    wrong_audience.audience = "other-service".into();
    cases.push((wrong_audience, "IDENTITY_AUDIENCE_MISMATCH"));

    let mut wrong_environment = envelope();
    wrong_environment.environment = "staging".into();
    cases.push((wrong_environment, "IDENTITY_ENVIRONMENT_MISMATCH"));

    for (candidate, expected_code) in cases {
        let error = candidate.validate(&intent, &context).unwrap_err();
        assert_eq!(error.code(), expected_code);
    }
}

#[test]
fn validation_rejects_noncanonical_identifiers_hashes_and_timestamps() {
    let intent = intent();
    let context = context();

    let mut blank_organization = envelope();
    blank_organization.organization_id.clear();

    let mut ambiguous_key_id = envelope();
    ambiguous_key_id.key_id = "keys/primary".into();

    let mut short_nonce = envelope();
    short_nonce.nonce = "short".into();

    let mut uppercase_hash = envelope();
    uppercase_hash.intent_hash = uppercase_hash.intent_hash.to_uppercase();

    let mut unicode_audience = envelope();
    unicode_audience.audience = "ａｔｆ-gateway".into();

    let mut submillisecond_time = envelope();
    submillisecond_time.issued_at = "2098-12-31T23:58:00.000001Z".parse().unwrap();

    for candidate in [
        blank_organization,
        ambiguous_key_id,
        short_nonce,
        uppercase_hash,
        unicode_audience,
        submillisecond_time,
    ] {
        let error = candidate.validate(&intent, &context).unwrap_err();
        assert_eq!(error.code(), "IDENTITY_ENVELOPE_FIELD_INVALID");
    }
}

#[test]
fn validation_enforces_the_closed_five_minute_time_window() {
    let intent = intent();
    let context = context();

    let mut reversed = envelope();
    reversed.issued_at = reversed.expires_at;

    let mut too_long = envelope();
    too_long.issued_at = "2098-12-31T23:55:00.000Z".parse().unwrap();
    too_long.expires_at = "2099-01-01T00:00:00.001Z".parse().unwrap();

    let mut issued_in_future = envelope();
    issued_in_future.issued_at = "2098-12-31T23:58:30.001Z".parse().unwrap();

    let mut expired = envelope();
    expired.expires_at = context.verification_time;

    let mut starts_before_intent = envelope();
    starts_before_intent.issued_at = "2098-12-31T23:54:59.000Z".parse().unwrap();

    let mut ends_after_intent = envelope();
    ends_after_intent.expires_at = "2099-01-01T00:00:00.001Z".parse().unwrap();

    let cases = [
        (reversed, "IDENTITY_ENVELOPE_TIME_RANGE_INVALID"),
        (too_long, "IDENTITY_ENVELOPE_LIFETIME_EXCEEDED"),
        (issued_in_future, "IDENTITY_ENVELOPE_NOT_YET_VALID"),
        (expired, "IDENTITY_ENVELOPE_EXPIRED"),
        (
            starts_before_intent,
            "IDENTITY_ENVELOPE_OUTSIDE_INTENT_LIFETIME",
        ),
        (
            ends_after_intent,
            "IDENTITY_ENVELOPE_OUTSIDE_INTENT_LIFETIME",
        ),
    ];

    for (candidate, expected_code) in cases {
        let error = candidate.validate(&intent, &context).unwrap_err();
        assert_eq!(error.code(), expected_code);
    }
}

#[test]
fn unknown_and_duplicate_envelope_fields_are_rejected_instead_of_ignored() {
    let mut value = vector()["envelope"].clone();
    value["tenant_override"] = serde_json::json!("other-lab");

    assert!(serde_json::from_value::<IdentityEnvelope>(value).is_err());

    let raw = serde_json::to_string(&envelope()).unwrap();
    let duplicate_domain =
        raw.replacen("\"domain\":", "\"domain\":\"ATF_INTENT_V1\",\"domain\":", 1);
    assert!(serde_json::from_str::<IdentityEnvelope>(&duplicate_domain).is_err());
}

#[test]
fn registry_verifies_the_published_signature_and_returns_exact_bound_identity() {
    let vector = vector();
    let key = signing_key();
    let envelope = envelope();
    let canonical = envelope.canonical_bytes();

    assert_eq!(
        key.verifying_key().to_bytes(),
        decode_hex(vector["public_key_hex"].as_str().unwrap())
    );
    assert_eq!(key.sign(&canonical).to_bytes(), signature());

    let verified = registry()
        .verify_envelope(&intent(), &envelope, &signature(), &context())
        .unwrap();
    assert_eq!(
        verified,
        VerifiedIdentity {
            organization_id: "alpha-lab".into(),
            agent_id: "research-agent-01".into(),
            key_id: "identity-key-2026-01".into(),
            nonce: "01J0000000000000000000N001".into(),
            envelope_expires_at: "2098-12-31T23:59:00.000Z".parse().unwrap(),
        }
    );
}

#[test]
fn every_signed_field_mutation_invalidates_the_published_signature() {
    let intent = intent();
    let context = context();
    let mut registry = registry();
    registry
        .register_key(key_record(
            "identity-key-2026-02",
            signing_key().verifying_key(),
        ))
        .unwrap();

    let mut cases = Vec::new();
    let mut candidate = envelope();
    candidate.domain = "ATF_INTENT_V2".into();
    cases.push(candidate);
    let mut candidate = envelope();
    candidate.organization_id = "other-lab".into();
    cases.push(candidate);
    let mut candidate = envelope();
    candidate.agent_id = "other-agent".into();
    cases.push(candidate);
    let mut candidate = envelope();
    candidate.key_id = "identity-key-2026-02".into();
    cases.push(candidate);
    let mut candidate = envelope();
    candidate.intent_hash = "0".repeat(64);
    cases.push(candidate);
    let mut candidate = envelope();
    candidate.issued_at = "2098-12-31T23:58:00.001Z".parse().unwrap();
    cases.push(candidate);
    let mut candidate = envelope();
    candidate.expires_at = "2098-12-31T23:58:59.999Z".parse().unwrap();
    cases.push(candidate);
    let mut candidate = envelope();
    candidate.nonce = "01J0000000000000000000N002".into();
    cases.push(candidate);
    let mut candidate = envelope();
    candidate.audience = "other-service".into();
    cases.push(candidate);
    let mut candidate = envelope();
    candidate.environment = "staging".into();
    cases.push(candidate);

    for candidate in cases {
        assert!(registry
            .verify_envelope(&intent, &candidate, &signature(), &context)
            .is_err());
    }
}

#[test]
fn verification_uses_only_the_declared_key_and_never_the_legacy_raw_hash() {
    let intent = intent();
    let envelope = envelope();
    let old_key = SigningKey::from_bytes(&[7; 32]);
    let declared_key = SigningKey::from_bytes(&[8; 32]);
    let mut registry = IdentityRegistry::new();
    registry.register_agent(agent_record()).unwrap();
    registry
        .register_key(key_record("old-key", old_key.verifying_key()))
        .unwrap();
    registry
        .register_key(key_record(&envelope.key_id, declared_key.verifying_key()))
        .unwrap();

    let signed_by_other_registered_key = old_key.sign(&envelope.canonical_bytes()).to_bytes();
    let legacy_raw_hash_signature = declared_key
        .sign(intent.canonical_hash().as_bytes())
        .to_bytes();

    for rejected in [signed_by_other_registered_key, legacy_raw_hash_signature] {
        let error = registry
            .verify_envelope(&intent, &envelope, &rejected, &context())
            .unwrap_err();
        assert_eq!(error.code(), "IDENTITY_SIGNATURE_INVALID");
    }

    let valid = declared_key.sign(&envelope.canonical_bytes()).to_bytes();
    assert!(registry
        .verify_envelope(&intent, &envelope, &valid, &context())
        .is_ok());
}

#[test]
fn duplicate_key_ids_are_rejected_instead_of_replacing_key_material() {
    let mut registry = registry();

    let error = registry
        .register_key(key_record(
            "identity-key-2026-01",
            SigningKey::from_bytes(&[9; 32]).verifying_key(),
        ))
        .unwrap_err();

    assert_eq!(error.code(), "IDENTITY_KEY_ALREADY_REGISTERED");
    assert!(registry
        .verify_envelope(&intent(), &envelope(), &signature(), &context())
        .is_ok());
}

#[test]
fn registered_agent_scope_and_lifetime_must_cover_the_envelope() {
    let mut wrong_organization = agent_record();
    wrong_organization.organization_id = "other-lab".into();

    let mut wrong_environment = agent_record();
    wrong_environment.deployment_environment = "staging".into();

    let mut not_yet_active = agent_record();
    not_yet_active.created_at = "2098-12-31T23:58:00.001Z".parse().unwrap();

    let mut expired = agent_record();
    expired.expires_at = Some("2098-12-31T23:58:30.000Z".parse().unwrap());

    let mut expires_before_envelope = agent_record();
    expires_before_envelope.expires_at = Some("2098-12-31T23:58:45.000Z".parse().unwrap());

    let cases = [
        (wrong_organization, "IDENTITY_AGENT_ORGANIZATION_MISMATCH"),
        (wrong_environment, "IDENTITY_AGENT_ENVIRONMENT_MISMATCH"),
        (not_yet_active, "IDENTITY_AGENT_NOT_YET_ACTIVE"),
        (expired, "IDENTITY_AGENT_EXPIRED"),
        (
            expires_before_envelope,
            "IDENTITY_ENVELOPE_EXCEEDS_AGENT_LIFETIME",
        ),
    ];

    for (record, expected_code) in cases {
        let error = registry_for(record)
            .verify_envelope(&intent(), &envelope(), &signature(), &context())
            .unwrap_err();
        assert_eq!(error.code(), expected_code);
    }
}

#[test]
fn agent_status_and_missing_registry_entries_still_fail_closed() {
    for status in [
        AgentStatus::Paused,
        AgentStatus::Revoked,
        AgentStatus::Expired,
    ] {
        let mut record = agent_record();
        record.status = status;
        let error = registry_for(record)
            .verify_envelope(&intent(), &envelope(), &signature(), &context())
            .unwrap_err();
        assert_eq!(error.code(), "IDENTITY_AGENT_NOT_ACTIVE");
    }

    let mut shadow_record = agent_record();
    shadow_record.status = AgentStatus::ShadowOnly;
    assert!(registry_for(shadow_record)
        .verify_envelope(&intent(), &envelope(), &signature(), &context())
        .is_ok());

    let unknown_agent = IdentityRegistry::new()
        .verify_envelope(&intent(), &envelope(), &signature(), &context())
        .unwrap_err();
    assert_eq!(unknown_agent.code(), "IDENTITY_AGENT_UNKNOWN");

    let mut no_key = IdentityRegistry::new();
    no_key.register_agent(agent_record()).unwrap();
    let unknown_key = no_key
        .verify_envelope(&intent(), &envelope(), &signature(), &context())
        .unwrap_err();
    assert_eq!(unknown_key.code(), "IDENTITY_KEY_NOT_REGISTERED");
}

#[test]
fn rotation_overlap_verifies_each_signature_only_under_its_declared_key_id() {
    let first = SigningKey::from_bytes(&[21; 32]);
    let second = SigningKey::from_bytes(&[22; 32]);
    let mut registry = IdentityRegistry::new();
    registry.register_agent(agent_record()).unwrap();
    registry
        .register_key(key_record("rotation-1", first.verifying_key()))
        .unwrap();
    registry
        .register_key(key_record("rotation-2", second.verifying_key()))
        .unwrap();

    for (key_id, key) in [("rotation-1", first), ("rotation-2", second)] {
        let mut envelope = envelope();
        envelope.key_id = key_id.into();
        let signature = key.sign(&envelope.canonical_bytes()).to_bytes();
        let verified = registry
            .verify_envelope(&intent(), &envelope, &signature, &context())
            .unwrap();
        assert_eq!(verified.key_id, key_id);
    }
}
