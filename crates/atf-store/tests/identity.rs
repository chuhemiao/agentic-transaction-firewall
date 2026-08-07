use atf_audit::{
    AgentRegisteredPayload, AgentStatusChangedPayload, AuditPayload, IdentityKeyRegisteredPayload,
    IdentityKeyRevokedPayload, NewAuditEvent,
};
use atf_core::Timestamp;
use atf_identity::{
    AgentRecord, AgentStatus, EnvelopeVerificationContext, IdentityEnvelope, IdentityError,
    IdentityKeyRecord,
};
use atf_store::{Store, StoreError};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, Executor, PgConnection, PgPool,
};

const VECTOR: &str = include_str!("../../../conformance/identity-vectors/atf-intent-v1.json");

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut decoded = [0_u8; N];
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).unwrap();
    }
    decoded
}
use std::{
    env,
    error::Error,
    process,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

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
        created_at: "2026-08-08T09:00:00.000Z".parse().unwrap(),
        expires_at: Some("2027-08-08T09:00:00.000Z".parse().unwrap()),
    }
}

fn occurred_at() -> Timestamp {
    "2026-08-08T10:00:00.000Z".parse().unwrap()
}

fn identity_key_record(key_id: &str) -> IdentityKeyRecord {
    let vector: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
    let public_key: [u8; 32] = decode_hex(vector["public_key_hex"].as_str().unwrap());
    IdentityKeyRecord::from_public_key_bytes(
        "research-agent-01".into(),
        key_id.into(),
        &public_key,
        "2026-08-08T10:00:00.000Z".parse().unwrap(),
        Some("2026-09-08T10:00:00.000Z".parse().unwrap()),
        None,
    )
    .unwrap()
}

fn vector_agent_record() -> AgentRecord {
    let mut record = agent_record();
    record.created_at = "2098-01-01T00:00:00.000Z".parse().unwrap();
    record.expires_at = Some("2099-01-01T00:00:00.000Z".parse().unwrap());
    record
}

fn vector_identity_key_record() -> IdentityKeyRecord {
    let vector: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
    let public_key: [u8; 32] = decode_hex(vector["public_key_hex"].as_str().unwrap());
    IdentityKeyRecord::from_public_key_bytes(
        "research-agent-01".into(),
        "identity-key-2026-01".into(),
        &public_key,
        "2098-12-31T23:58:00.000Z".parse().unwrap(),
        Some("2098-12-31T23:59:00.000Z".parse().unwrap()),
        None,
    )
    .unwrap()
}

#[tokio::test]
async fn provisioned_agent_survives_restart_with_matching_typed_audit_evidence(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("agent_restart").await?;
    database.seed_organization("alpha-lab").await?;
    let store = Store::connect(&database.url).await?;

    let stored = store
        .provision_agent(agent_record(), "operator-1", occurred_at())
        .await?;
    assert_eq!(stored.lifecycle_version, 1);
    assert_eq!(stored.record, agent_record());
    store.close().await;

    let restarted = Store::connect(&database.url).await?;
    let reloaded = restarted
        .load_agent("alpha-lab", "research-agent-01")
        .await?;
    assert_eq!(reloaded, stored);

    let chain = restarted.load_verified_audit_chain("alpha-lab").await?;
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].event.event_id, stored.last_event_id);
    assert_eq!(
        chain[0].event.typed_payload()?,
        AuditPayload::AgentRegistered(AgentRegisteredPayload {
            organization_id: "alpha-lab".into(),
            agent_id: "research-agent-01".into(),
            status: "ACTIVE".into(),
            record_hash: agent_record().canonical_hash(),
            lifecycle_version: 1,
            actor_id: "operator-1".into(),
        })
    );

    restarted.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn agent_status_changes_survive_restart_and_terminal_states_cannot_be_reactivated(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("agent_status").await?;
    database.seed_organization("alpha-lab").await?;
    let store = Store::connect(&database.url).await?;
    store
        .provision_agent(agent_record(), "operator-1", occurred_at())
        .await?;

    let paused_at: Timestamp = "2026-08-08T11:00:00.000Z".parse().unwrap();
    let paused = store
        .set_agent_status(
            "alpha-lab",
            "research-agent-01",
            AgentStatus::Paused,
            "operator-1",
            "OPERATOR_PAUSE",
            paused_at,
        )
        .await?;
    assert_eq!(paused.record.status, AgentStatus::Paused);
    assert_eq!(paused.lifecycle_version, 2);
    store.close().await;

    let restarted = Store::connect(&database.url).await?;
    let reloaded = restarted
        .load_agent("alpha-lab", "research-agent-01")
        .await?;
    assert_eq!(reloaded, paused);
    let chain = restarted.load_verified_audit_chain("alpha-lab").await?;
    assert_eq!(
        chain.last().unwrap().event.typed_payload()?,
        AuditPayload::AgentStatusChanged(AgentStatusChangedPayload {
            organization_id: "alpha-lab".into(),
            agent_id: "research-agent-01".into(),
            previous_status: "ACTIVE".into(),
            status: "PAUSED".into(),
            record_hash: paused.record.canonical_hash(),
            lifecycle_version: 2,
            actor_id: "operator-1".into(),
            reason_code: "OPERATOR_PAUSE".into(),
        })
    );

    let revoked_at: Timestamp = "2026-08-08T12:00:00.000Z".parse().unwrap();
    restarted
        .set_agent_status(
            "alpha-lab",
            "research-agent-01",
            AgentStatus::Revoked,
            "operator-1",
            "AGENT_REVOKED",
            revoked_at,
        )
        .await?;
    let reactivate = restarted
        .set_agent_status(
            "alpha-lab",
            "research-agent-01",
            AgentStatus::Active,
            "operator-1",
            "INVALID_REACTIVATION",
            "2026-08-08T13:00:00.000Z".parse().unwrap(),
        )
        .await
        .expect_err("revoked Agents are terminal");
    assert!(matches!(
        reactivate,
        atf_store::StoreError::IdentityDomain(
            atf_identity::IdentityError::InvalidAgentStatusTransition {
                from: AgentStatus::Revoked,
                to: AgentStatus::Active
            }
        )
    ));

    restarted.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn registered_exact_key_survives_restart_with_fingerprint_only_audit_evidence(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("key_restart").await?;
    database.seed_organization("alpha-lab").await?;
    let store = Store::connect(&database.url).await?;
    store
        .provision_agent(agent_record(), "operator-1", occurred_at())
        .await?;

    let stored = store
        .register_identity_key(
            "alpha-lab",
            identity_key_record("identity-key-2026-01"),
            "operator-1",
            occurred_at(),
        )
        .await?;
    assert_eq!(stored.lifecycle_version, 1);
    store.close().await;

    let restarted = Store::connect(&database.url).await?;
    let snapshot = restarted
        .load_identity_snapshot("alpha-lab", "research-agent-01", "identity-key-2026-01")
        .await?;
    assert_eq!(snapshot.key(), &stored);
    assert_eq!(snapshot.agent().record, agent_record());

    let chain = restarted.load_verified_audit_chain("alpha-lab").await?;
    let payload = chain.last().unwrap().event.typed_payload()?;
    assert_eq!(
        payload,
        AuditPayload::IdentityKeyRegistered(IdentityKeyRegisteredPayload {
            organization_id: "alpha-lab".into(),
            agent_id: "research-agent-01".into(),
            key_id: "identity-key-2026-01".into(),
            algorithm: "ED25519".into(),
            public_key_fingerprint: stored.record.public_key_fingerprint(),
            key_record_hash: stored.key_record_hash.clone(),
            activates_at: stored.record.activates_at,
            expires_at: stored.record.expires_at,
            lifecycle_version: 1,
            actor_id: "operator-1".into(),
        })
    );
    let data = &chain.last().unwrap().event.data;
    assert!(data.get("public_key").is_none());
    assert!(data.get("private_key").is_none());

    restarted.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn revoked_key_fails_exact_envelope_verification_after_restart() -> Result<(), Box<dyn Error>>
{
    let database = TestDatabase::create("key_revoked").await?;
    database.seed_organization("alpha-lab").await?;
    let store = Store::connect(&database.url).await?;
    let provisioned_at: Timestamp = "2098-12-31T23:57:00.000Z".parse().unwrap();
    store
        .provision_agent(vector_agent_record(), "operator-1", provisioned_at)
        .await?;
    store
        .register_identity_key(
            "alpha-lab",
            vector_identity_key_record(),
            "operator-1",
            provisioned_at,
        )
        .await?;

    let vector: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
    let raw_intent = serde_json::to_string(&vector["intent"])?;
    let intent = atf_intent::validate(&raw_intent)?;
    let envelope: IdentityEnvelope = serde_json::from_value(vector["envelope"].clone())?;
    let signature = decode_hex(vector["signature_hex"].as_str().unwrap());
    let context = EnvelopeVerificationContext {
        audience: "atf-gateway",
        environment: "production",
        verification_time: "2098-12-31T23:58:30.000Z".parse().unwrap(),
    };
    let before = store
        .load_identity_snapshot("alpha-lab", "research-agent-01", "identity-key-2026-01")
        .await?;
    assert!(before
        .verify_envelope(&intent, &envelope, &signature, &context)
        .is_ok());

    let revoked_at: Timestamp = "2098-12-31T23:58:20.000Z".parse().unwrap();
    let revoked = store
        .revoke_identity_key(
            "alpha-lab",
            "research-agent-01",
            "identity-key-2026-01",
            "operator-1",
            "KEY_COMPROMISED",
            revoked_at,
        )
        .await?;
    assert_eq!(revoked.lifecycle_version, 2);
    assert_eq!(revoked.record.revoked_at, Some(revoked_at));
    store.close().await;

    let restarted = Store::connect(&database.url).await?;
    let after = restarted
        .load_identity_snapshot("alpha-lab", "research-agent-01", "identity-key-2026-01")
        .await?;
    let error = after
        .verify_envelope(&intent, &envelope, &signature, &context)
        .unwrap_err();
    assert_eq!(error.code(), "IDENTITY_KEY_REVOKED");
    let payload = restarted
        .load_verified_audit_chain("alpha-lab")
        .await?
        .last()
        .unwrap()
        .event
        .typed_payload()?;
    assert_eq!(
        payload,
        AuditPayload::IdentityKeyRevoked(IdentityKeyRevokedPayload {
            organization_id: "alpha-lab".into(),
            agent_id: "research-agent-01".into(),
            key_id: "identity-key-2026-01".into(),
            public_key_fingerprint: revoked.record.public_key_fingerprint(),
            key_record_hash: revoked.key_record_hash,
            revoked_at,
            lifecycle_version: 2,
            actor_id: "operator-1".into(),
            reason_code: "KEY_COMPROMISED".into(),
        })
    );

    restarted.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn bounded_rotation_overlap_verifies_only_each_envelopes_exact_key_after_restart(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("key_overlap").await?;
    database.seed_organization("alpha-lab").await?;
    let store = Store::connect(&database.url).await?;
    let mutation_time: Timestamp = "2098-12-31T23:57:00.000Z".parse().unwrap();
    store
        .provision_agent(vector_agent_record(), "operator-1", mutation_time)
        .await?;

    let old_key = SigningKey::from_bytes(&[21; 32]);
    let new_key = SigningKey::from_bytes(&[22; 32]);
    for (key_id, key, activates_at, expires_at) in [
        (
            "rotation-1",
            &old_key,
            "2098-12-31T23:57:30.000Z",
            "2098-12-31T23:59:30.000Z",
        ),
        (
            "rotation-2",
            &new_key,
            "2098-12-31T23:58:00.000Z",
            "2099-01-01T00:00:00.000Z",
        ),
    ] {
        store
            .register_identity_key(
                "alpha-lab",
                IdentityKeyRecord::from_public_key_bytes(
                    "research-agent-01".into(),
                    key_id.into(),
                    &key.verifying_key().to_bytes(),
                    activates_at.parse().unwrap(),
                    Some(expires_at.parse().unwrap()),
                    None,
                )?,
                "operator-1",
                mutation_time,
            )
            .await?;
    }
    store.close().await;

    let restarted = Store::connect(&database.url).await?;
    let vector: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
    let raw_intent = serde_json::to_string(&vector["intent"])?;
    let intent = atf_intent::validate(&raw_intent)?;
    let base_envelope: IdentityEnvelope = serde_json::from_value(vector["envelope"].clone())?;
    let context = EnvelopeVerificationContext {
        audience: "atf-gateway",
        environment: "production",
        verification_time: "2098-12-31T23:58:30.000Z".parse().unwrap(),
    };

    for (key_id, signing_key, other_key) in [
        ("rotation-1", &old_key, &new_key),
        ("rotation-2", &new_key, &old_key),
    ] {
        let mut envelope = base_envelope.clone();
        envelope.key_id = key_id.into();
        let snapshot = restarted
            .load_identity_snapshot("alpha-lab", "research-agent-01", key_id)
            .await?;
        let exact_signature = signing_key.sign(&envelope.canonical_bytes()).to_bytes();
        let wrong_signature = other_key.sign(&envelope.canonical_bytes()).to_bytes();
        assert!(snapshot
            .verify_envelope(&intent, &envelope, &exact_signature, &context)
            .is_ok());
        assert_eq!(
            snapshot
                .verify_envelope(&intent, &envelope, &wrong_signature, &context)
                .unwrap_err()
                .code(),
            "IDENTITY_SIGNATURE_INVALID"
        );
    }

    restarted.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn durable_agent_and_key_lifecycle_states_fail_closed_after_restart(
) -> Result<(), Box<dyn Error>> {
    for (label, status) in [
        ("agent_paused", AgentStatus::Paused),
        ("agent_expired", AgentStatus::Expired),
        ("agent_revoked", AgentStatus::Revoked),
    ] {
        let database = TestDatabase::create(label).await?;
        database.seed_organization("alpha-lab").await?;
        let store = Store::connect(&database.url).await?;
        let mutation_time: Timestamp = "2098-12-31T23:57:00.000Z".parse().unwrap();
        store
            .provision_agent(vector_agent_record(), "operator-1", mutation_time)
            .await?;
        store
            .register_identity_key(
                "alpha-lab",
                vector_identity_key_record(),
                "operator-1",
                mutation_time,
            )
            .await?;
        store
            .set_agent_status(
                "alpha-lab",
                "research-agent-01",
                status,
                "operator-1",
                "TEST_LIFECYCLE_STATE",
                "2098-12-31T23:58:20.000Z".parse().unwrap(),
            )
            .await?;
        store.close().await;

        let restarted = Store::connect(&database.url).await?;
        let inputs = vector_verification_inputs()?;
        let snapshot = restarted
            .load_identity_snapshot("alpha-lab", "research-agent-01", "identity-key-2026-01")
            .await?;
        let error = snapshot
            .verify_envelope(
                &inputs.intent,
                &inputs.envelope,
                &inputs.signature,
                &inputs.context,
            )
            .unwrap_err();
        assert_eq!(error.code(), "IDENTITY_AGENT_NOT_ACTIVE");
        restarted.close().await;
        database.destroy().await?;
    }

    for (label, activates_at, expires_at, expected_code) in [
        (
            "key_inactive",
            "2098-12-31T23:58:01.000Z",
            "2098-12-31T23:59:30.000Z",
            "IDENTITY_KEY_NOT_YET_ACTIVE",
        ),
        (
            "key_expired",
            "2098-12-31T23:57:30.000Z",
            "2098-12-31T23:58:20.000Z",
            "IDENTITY_KEY_EXPIRED",
        ),
    ] {
        let database = TestDatabase::create(label).await?;
        database.seed_organization("alpha-lab").await?;
        let store = Store::connect(&database.url).await?;
        let mutation_time: Timestamp = "2098-12-31T23:57:00.000Z".parse().unwrap();
        store
            .provision_agent(vector_agent_record(), "operator-1", mutation_time)
            .await?;
        let vector: serde_json::Value = serde_json::from_str(VECTOR).unwrap();
        let public_key = decode_hex::<32>(vector["public_key_hex"].as_str().unwrap());
        store
            .register_identity_key(
                "alpha-lab",
                IdentityKeyRecord::from_public_key_bytes(
                    "research-agent-01".into(),
                    "identity-key-2026-01".into(),
                    &public_key,
                    activates_at.parse().unwrap(),
                    Some(expires_at.parse().unwrap()),
                    None,
                )?,
                "operator-1",
                mutation_time,
            )
            .await?;
        store.close().await;

        let restarted = Store::connect(&database.url).await?;
        let inputs = vector_verification_inputs()?;
        let snapshot = restarted
            .load_identity_snapshot("alpha-lab", "research-agent-01", "identity-key-2026-01")
            .await?;
        assert_eq!(
            snapshot
                .verify_envelope(
                    &inputs.intent,
                    &inputs.envelope,
                    &inputs.signature,
                    &inputs.context,
                )
                .unwrap_err()
                .code(),
            expected_code
        );
        restarted.close().await;
        database.destroy().await?;
    }

    Ok(())
}

struct VectorVerificationInputs {
    intent: atf_intent::TransactionIntent,
    envelope: IdentityEnvelope,
    signature: [u8; 64],
    context: EnvelopeVerificationContext<'static>,
}

fn vector_verification_inputs() -> Result<VectorVerificationInputs, Box<dyn Error>> {
    let vector: serde_json::Value = serde_json::from_str(VECTOR)?;
    let raw_intent = serde_json::to_string(&vector["intent"])?;
    Ok(VectorVerificationInputs {
        intent: atf_intent::validate(&raw_intent)?,
        envelope: serde_json::from_value(vector["envelope"].clone())?,
        signature: decode_hex(vector["signature_hex"].as_str().unwrap()),
        context: EnvelopeVerificationContext {
            audience: "atf-gateway",
            environment: "production",
            verification_time: "2098-12-31T23:58:30.000Z".parse().unwrap(),
        },
    })
}

#[tokio::test]
async fn identity_mutations_are_atomic_tenant_scoped_and_serialized() -> Result<(), Box<dyn Error>>
{
    let database = TestDatabase::create("atomic_tenant_concurrent").await?;
    database.seed_organization("alpha-lab").await?;
    database.seed_organization("beta-lab").await?;
    let store = Store::connect(&database.url).await?;
    store
        .provision_agent(agent_record(), "operator-1", occurred_at())
        .await?;

    let mut forged_record = agent_record();
    forged_record.status = AgentStatus::Paused;
    let forged_event = NewAuditEvent::from_payload(
        "2026-08-08T10:30:00.000Z".parse().unwrap(),
        None,
        AuditPayload::AgentStatusChanged(AgentStatusChangedPayload {
            organization_id: "alpha-lab".into(),
            agent_id: "research-agent-01".into(),
            previous_status: "ACTIVE".into(),
            status: "PAUSED".into(),
            record_hash: forged_record.canonical_hash(),
            lifecycle_version: 2,
            actor_id: "operator-2".into(),
            reason_code: "BYPASS_ATOMIC_STATE".into(),
        }),
    )?;
    assert!(matches!(
        store
            .append_audit_event("alpha-lab", forged_event)
            .await
            .expect_err("identity lifecycle evidence requires its state transaction"),
        StoreError::InvalidAuditEvent { .. }
    ));
    assert_eq!(store.load_verified_audit_chain("alpha-lab").await?.len(), 1);

    let duplicate_agent = store
        .provision_agent(agent_record(), "operator-2", occurred_at())
        .await
        .expect_err("duplicate Agent must fail");
    assert!(matches!(duplicate_agent, StoreError::AgentConflict { .. }));
    assert_eq!(store.load_verified_audit_chain("alpha-lab").await?.len(), 1);

    store
        .register_identity_key(
            "alpha-lab",
            identity_key_record("identity-key-2026-01"),
            "operator-1",
            occurred_at(),
        )
        .await?;
    let duplicate_key = store
        .register_identity_key(
            "alpha-lab",
            identity_key_record("identity-key-2026-01"),
            "operator-2",
            occurred_at(),
        )
        .await
        .expect_err("duplicate key must fail");
    assert!(matches!(
        duplicate_key,
        StoreError::IdentityKeyConflict { .. }
    ));
    assert_eq!(store.load_verified_audit_chain("alpha-lab").await?.len(), 2);

    assert!(matches!(
        store
            .load_agent("beta-lab", "research-agent-01")
            .await
            .unwrap_err(),
        StoreError::AgentNotFound { .. }
    ));
    assert!(matches!(
        store
            .load_identity_snapshot("beta-lab", "research-agent-01", "identity-key-2026-01")
            .await
            .unwrap_err(),
        StoreError::AgentNotFound { .. }
    ));

    let status_time: Timestamp = "2026-08-08T11:00:00.000Z".parse().unwrap();
    let first = store.set_agent_status(
        "alpha-lab",
        "research-agent-01",
        AgentStatus::Paused,
        "operator-1",
        "CONCURRENT_PAUSE",
        status_time,
    );
    let second = store.set_agent_status(
        "alpha-lab",
        "research-agent-01",
        AgentStatus::Paused,
        "operator-2",
        "CONCURRENT_PAUSE",
        status_time,
    );
    let (first, second) = tokio::join!(first, second);
    assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    let rejected = if first.is_err() { first } else { second }.unwrap_err();
    assert!(matches!(
        rejected,
        StoreError::IdentityDomain(IdentityError::InvalidAgentStatusTransition {
            from: AgentStatus::Paused,
            to: AgentStatus::Paused,
        })
    ));
    assert_eq!(store.load_verified_audit_chain("alpha-lab").await?.len(), 3);
    assert_eq!(
        store
            .load_agent("alpha-lab", "research-agent-01")
            .await?
            .lifecycle_version,
        2
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn verified_identity_reads_reject_agent_and_key_row_tampering() -> Result<(), Box<dyn Error>>
{
    for (label, table, mutation) in [
        (
            "tamper_agent",
            "agents",
            "UPDATE agents SET record_hash = repeat('0', 64) WHERE organization_id = 'alpha-lab' AND agent_id = 'research-agent-01'",
        ),
        (
            "tamper_key",
            "identity_keys",
            "UPDATE identity_keys SET public_key_fingerprint = repeat('0', 64) WHERE organization_id = 'alpha-lab' AND agent_id = 'research-agent-01' AND key_id = 'identity-key-2026-01'",
        ),
    ] {
        let database = TestDatabase::create(label).await?;
        database.seed_organization("alpha-lab").await?;
        let store = Store::connect(&database.url).await?;
        store
            .provision_agent(agent_record(), "operator-1", occurred_at())
            .await?;
        store
            .register_identity_key(
                "alpha-lab",
                identity_key_record("identity-key-2026-01"),
                "operator-1",
                occurred_at(),
            )
            .await?;

        database
            .pool
            .execute(format!("ALTER TABLE {table} DISABLE TRIGGER USER").as_str())
            .await?;
        database.pool.execute(mutation).await?;
        database
            .pool
            .execute(format!("ALTER TABLE {table} ENABLE TRIGGER USER").as_str())
            .await?;

        assert!(matches!(
            store
                .load_identity_snapshot(
                    "alpha-lab",
                    "research-agent-01",
                    "identity-key-2026-01"
                )
                .await
                .unwrap_err(),
            StoreError::IdentityStateCorrupt { .. }
        ));
        store.close().await;
        database.destroy().await?;
    }
    Ok(())
}

#[tokio::test]
async fn database_guards_reject_identity_rebinding_deletion_and_truncate(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("identity_db_guards").await?;
    database.seed_organization("alpha-lab").await?;
    let store = Store::connect(&database.url).await?;
    store
        .provision_agent(agent_record(), "operator-1", occurred_at())
        .await?;
    store
        .register_identity_key(
            "alpha-lab",
            identity_key_record("identity-key-2026-01"),
            "operator-1",
            occurred_at(),
        )
        .await?;

    for statement in [
        "UPDATE agents SET status = 'PAUSED' WHERE organization_id = 'alpha-lab' AND agent_id = 'research-agent-01'",
        "UPDATE identity_keys SET public_key = decode(repeat('00', 32), 'hex') WHERE organization_id = 'alpha-lab' AND agent_id = 'research-agent-01' AND key_id = 'identity-key-2026-01'",
        "DELETE FROM identity_keys WHERE organization_id = 'alpha-lab' AND agent_id = 'research-agent-01' AND key_id = 'identity-key-2026-01'",
        "DELETE FROM agents WHERE organization_id = 'alpha-lab' AND agent_id = 'research-agent-01'",
    ] {
        let error = database
            .pool
            .execute(statement)
            .await
            .expect_err("identity lifecycle guards must reject direct mutation");
        assert_sqlstate(&error, "55000");
    }
    for statement in ["TRUNCATE identity_keys", "TRUNCATE agents CASCADE"] {
        let error = database
            .pool
            .execute(statement)
            .await
            .expect_err("identity lifecycle tables must reject truncate");
        assert_sqlstate_one_of(&error, &["55000", "0A000"]);
    }

    store.close().await;
    database.destroy().await?;
    Ok(())
}

struct TestDatabase {
    admin: PgConnection,
    pool: PgPool,
    name: String,
    url: String,
}

impl TestDatabase {
    async fn create(label: &str) -> Result<Self, Box<dyn Error>> {
        let admin_url = env::var("ATF_TEST_DATABASE_URL").expect(
            "ATF_TEST_DATABASE_URL must allow the test to create and drop PostgreSQL databases",
        );
        let admin_options = PgConnectOptions::from_str(&admin_url)?;
        let name = format!("atf_ds015_{label}_{}", unique_suffix());
        let quoted_name = quote_identifier(&name);
        let mut admin = PgConnection::connect_with(&admin_options).await?;
        admin
            .execute(format!("CREATE DATABASE {quoted_name}").as_str())
            .await?;

        let database_options = admin_options.database(&name);
        let url = database_options.to_url_lossy().to_string();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(database_options)
            .await?;
        atf_store::migrate_pool(&pool).await?;

        Ok(Self {
            admin,
            pool,
            name,
            url,
        })
    }

    async fn seed_organization(&self, organization_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO organizations (organization_id) VALUES ($1)")
            .bind(organization_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn destroy(self) -> Result<(), Box<dyn Error>> {
        self.pool.close().await;
        let quoted_name = quote_identifier(&self.name);
        let mut admin = self.admin;
        admin
            .execute(format!("DROP DATABASE {quoted_name}").as_str())
            .await?;
        Ok(())
    }
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_nanos();
    format!("{}_{nanos}", process::id())
}

fn quote_identifier(identifier: &str) -> String {
    assert!(
        identifier
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_'),
        "test-generated PostgreSQL identifiers must be alphanumeric"
    );
    format!("\"{identifier}\"")
}

fn assert_sqlstate(error: &sqlx::Error, expected: &str) {
    let actual = error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .map(|code| code.into_owned());
    assert_eq!(
        actual.as_deref(),
        Some(expected),
        "unexpected error: {error}"
    );
}

fn assert_sqlstate_one_of(error: &sqlx::Error, expected: &[&str]) {
    let actual = error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .map(|code| code.into_owned());
    assert!(
        actual
            .as_deref()
            .is_some_and(|code| expected.contains(&code)),
        "unexpected SQLSTATE for {error}: {actual:?}"
    );
}
