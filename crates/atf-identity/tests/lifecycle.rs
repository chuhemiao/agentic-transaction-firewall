use atf_identity::{
    AgentRecord, AgentStatus, EnvelopeVerificationContext, IdentityEnvelope, IdentityError,
    IdentityKeyRecord, IdentityRegistry,
};
use ed25519_dalek::SigningKey;

const VECTOR: &str = include_str!("../../../conformance/identity-vectors/atf-intent-v1.json");

fn agent_record() -> AgentRecord {
    AgentRecord {
        agent_id: "research-agent-01".into(),
        organization_id: "alpha-lab".into(),
        owner_user_id: "user-001".into(),
        agent_type: "research".into(),
        model_provider: "test".into(),
        model_name: "deterministic-model".into(),
        agent_version: "1.0.0".into(),
        code_hash: "a".repeat(64),
        deployment_environment: "production".into(),
        allowed_tools: vec!["mcp-market-data".into()],
        allowed_adapters: vec!["x402".into()],
        default_budget: Some("20.00".parse().unwrap()),
        risk_tier: "standard".into(),
        status: AgentStatus::Active,
        created_at: "2098-01-01T00:00:00.000Z".parse().unwrap(),
        expires_at: Some("2099-01-01T00:00:00.000Z".parse().unwrap()),
    }
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut decoded = [0_u8; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    decoded
}

fn vector_value() -> serde_json::Value {
    serde_json::from_str(VECTOR).unwrap()
}

fn identity_key_record() -> IdentityKeyRecord {
    let vector = vector_value();
    let signing_key = SigningKey::from_bytes(&decode_hex(
        vector["deterministic_seed_hex"].as_str().unwrap(),
    ));
    IdentityKeyRecord {
        agent_id: "research-agent-01".into(),
        key_id: "identity-key-2026-01".into(),
        verifying_key: signing_key.verifying_key(),
        activates_at: "2098-12-31T23:58:00.000Z".parse().unwrap(),
        expires_at: Some("2098-12-31T23:59:00.000Z".parse().unwrap()),
        revoked_at: None,
    }
}

#[test]
fn revoked_and_expired_agents_are_terminal_while_operational_states_can_change() {
    for from in [
        AgentStatus::Active,
        AgentStatus::ShadowOnly,
        AgentStatus::Paused,
    ] {
        for to in [
            AgentStatus::Active,
            AgentStatus::ShadowOnly,
            AgentStatus::Paused,
            AgentStatus::Revoked,
            AgentStatus::Expired,
        ] {
            let result = from.validate_transition_to(to);
            if from == to {
                assert_eq!(
                    result,
                    Err(IdentityError::InvalidAgentStatusTransition { from, to })
                );
            } else {
                assert!(result.is_ok(), "{from:?} should transition to {to:?}");
            }
        }
    }

    for terminal in [AgentStatus::Revoked, AgentStatus::Expired] {
        for to in [
            AgentStatus::Active,
            AgentStatus::ShadowOnly,
            AgentStatus::Paused,
            AgentStatus::Revoked,
            AgentStatus::Expired,
        ] {
            assert_eq!(
                terminal.validate_transition_to(to),
                Err(IdentityError::InvalidAgentStatusTransition { from: terminal, to })
            );
        }
    }
}

#[test]
fn agent_records_validate_and_canonically_bind_every_persisted_field() {
    let record = agent_record();
    record.validate().unwrap();

    let canonical = record.canonical_bytes();
    let decoded: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
    assert_eq!(decoded["agent_id"], "research-agent-01");
    assert_eq!(record.canonical_hash().len(), 64);

    let mut changed = record.clone();
    changed.status = AgentStatus::Paused;
    assert_ne!(changed.canonical_hash(), record.canonical_hash());
}

#[test]
fn agent_records_reject_noncanonical_fields_and_invalid_lifetimes() {
    let mut bad_id = agent_record();
    bad_id.agent_id = "agents/research".into();

    let mut bad_hash = agent_record();
    bad_hash.code_hash = "A".repeat(64);

    let mut unordered_tools = agent_record();
    unordered_tools.allowed_tools = vec!["tool-z".into(), "tool-a".into()];

    let mut negative_budget = agent_record();
    negative_budget.default_budget = Some("-0.01".parse().unwrap());

    let mut submillisecond = agent_record();
    submillisecond.created_at = "2098-01-01T00:00:00.000001Z".parse().unwrap();

    let mut invalid_expiry = agent_record();
    invalid_expiry.expires_at = Some(invalid_expiry.created_at);

    for (candidate, field) in [
        (bad_id, "agent_id"),
        (bad_hash, "code_hash"),
        (unordered_tools, "allowed_tools"),
        (negative_budget, "default_budget"),
        (submillisecond, "created_at"),
        (invalid_expiry, "expires_at"),
    ] {
        assert_eq!(
            candidate.validate(),
            Err(IdentityError::InvalidAgentField { field })
        );
    }
}

#[test]
fn registry_rejects_invalid_or_duplicate_agent_authority() {
    let mut registry = IdentityRegistry::new();
    let mut invalid = agent_record();
    invalid.organization_id = "not/a/tenant".into();
    assert_eq!(
        registry.register_agent(invalid),
        Err(IdentityError::InvalidAgentField {
            field: "organization_id"
        })
    );

    registry.register_agent(agent_record()).unwrap();
    assert_eq!(
        registry.register_agent(agent_record()),
        Err(IdentityError::DuplicateAgentId {
            agent_id: "research-agent-01".into()
        })
    );
}

#[test]
fn exact_keys_enforce_activation_expiry_revocation_and_envelope_containment() {
    let vector = vector_value();
    let raw_intent = serde_json::to_string(&vector["intent"]).unwrap();
    let intent = atf_intent::validate(&raw_intent).unwrap();
    let envelope: IdentityEnvelope = serde_json::from_value(vector["envelope"].clone()).unwrap();
    let signature = decode_hex(vector["signature_hex"].as_str().unwrap());
    let context = EnvelopeVerificationContext {
        audience: "atf-gateway",
        environment: "production",
        verification_time: "2098-12-31T23:58:30.000Z".parse().unwrap(),
    };

    let verify = |key: IdentityKeyRecord| {
        let mut registry = IdentityRegistry::new();
        registry.register_agent(agent_record()).unwrap();
        registry.register_key(key).unwrap();
        registry.verify_envelope(&intent, &envelope, &signature, &context)
    };

    assert!(verify(identity_key_record()).is_ok());

    let mut not_yet_active = identity_key_record();
    not_yet_active.activates_at = "2098-12-31T23:58:00.001Z".parse().unwrap();
    assert_eq!(
        verify(not_yet_active).unwrap_err().code(),
        "IDENTITY_KEY_NOT_YET_ACTIVE"
    );

    let mut expired = identity_key_record();
    expired.expires_at = Some(context.verification_time);
    assert_eq!(verify(expired).unwrap_err().code(), "IDENTITY_KEY_EXPIRED");

    let mut revoked = identity_key_record();
    revoked.revoked_at = Some(context.verification_time);
    assert_eq!(verify(revoked).unwrap_err().code(), "IDENTITY_KEY_REVOKED");

    let mut envelope_outlives_key = identity_key_record();
    envelope_outlives_key.expires_at = Some("2098-12-31T23:58:45.000Z".parse().unwrap());
    assert_eq!(
        verify(envelope_outlives_key).unwrap_err().code(),
        "IDENTITY_ENVELOPE_EXCEEDS_KEY_LIFETIME"
    );
}

#[test]
fn key_records_reject_invalid_public_bytes_and_time_ranges() {
    let invalid_key = IdentityKeyRecord::from_public_key_bytes(
        "research-agent-01".into(),
        "key-invalid".into(),
        &[0xff; 31],
        "2098-12-31T23:58:00.000Z".parse().unwrap(),
        None,
        None,
    )
    .unwrap_err();
    assert_eq!(invalid_key.code(), "IDENTITY_KEY_FIELD_INVALID");

    let public_key = identity_key_record().public_key_bytes();
    let invalid_range = IdentityKeyRecord::from_public_key_bytes(
        "research-agent-01".into(),
        "key-invalid-range".into(),
        &public_key,
        "2098-12-31T23:58:00.000Z".parse().unwrap(),
        Some("2098-12-31T23:58:00.000Z".parse().unwrap()),
        None,
    )
    .unwrap_err();
    assert_eq!(invalid_range.code(), "IDENTITY_KEY_FIELD_INVALID");
}
