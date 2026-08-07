use atf_audit::{AuditPayload, EventType};
use atf_core::{Amount, IntentLifecycleState, Timestamp};
use atf_identity::{AgentRecord, AgentStatus, IdentityEnvelope, IdentityKeyRecord};
use atf_intent::{Action, Mandate, Principal, Resource, Transaction, TransactionIntent};
use atf_store::{AuthenticatedAdmissionInput, Store, StoreError};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, Executor, PgConnection, PgPool,
};
use std::{
    env,
    error::Error,
    process,
    str::FromStr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Barrier;

const ORGANIZATION_ID: &str = "alpha-lab";
const AGENT_ID: &str = "research-agent-01";
const KEY_ID: &str = "identity-key-01";
const AUDIENCE: &str = "atf-gateway";
const ENVIRONMENT: &str = "test";

#[tokio::test]
async fn authenticated_admission_consumes_nonce_and_exact_retry_adds_nothing(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("nonce_exact_retry").await?;
    let signing_key = provision_identity(&database).await?;
    let store = Store::connect(&database.url).await?;
    let intent = sample_intent("01J0000000000000000000A100", "idem-a", "12.50");
    let input = signed_input(intent.clone(), "nonce-0123456789abcdef", &signing_key);

    let grant = store.authenticate_and_admit(input.clone()).await?;
    assert_eq!(grant.admitted.intent, intent);
    assert_eq!(
        grant.admitted.lifecycle.state,
        IntentLifecycleState::IdentityVerified
    );
    assert_eq!(grant.admitted.lifecycle.version, 2);
    assert_eq!(grant.admitted.identity.key_id, KEY_ID);
    assert_eq!(grant.admitted.identity.envelope_hash.len(), 64);

    let before_retry = database.record_counts().await?;
    assert_eq!(before_retry, (1, 1, 0, 0, 4));
    let error = store
        .authenticate_and_admit(input)
        .await
        .expect_err("an exact active retry observes the existing evaluator");
    assert!(matches!(error, StoreError::IdempotencyInProgress { .. }));
    assert_eq!(database.record_counts().await?, before_retry);

    let nonce: (String, String, String, String, i64, i64) = sqlx::query_as(
        r#"
        SELECT nonce_hash::text, intent_id, intent_hash::text,
               envelope_hash::text, agent_lifecycle_version,
               key_lifecycle_version
        FROM identity_nonces
        "#,
    )
    .fetch_one(&database.pool)
    .await?;
    assert_eq!(nonce.0, atf_core::sha256_hex(b"nonce-0123456789abcdef"));
    assert_eq!(nonce.1, "01J0000000000000000000A100");
    assert_eq!(nonce.2, intent.canonical_hash());
    assert_eq!(nonce.3, grant.admitted.identity.envelope_hash);
    assert_eq!((nonce.4, nonce.5), (1, 1));

    let chain = store.load_verified_audit_chain(ORGANIZATION_ID).await?;
    let types: Vec<EventType> = chain.iter().map(|item| item.event.event_type).collect();
    assert_eq!(
        types,
        vec![
            EventType::AgentRegistered,
            EventType::IdentityKeyRegistered,
            EventType::IntentReceived,
            EventType::IdentityVerified,
        ]
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn fresh_nonce_retry_is_consumed_without_duplicate_admission() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("fresh_retry").await?;
    let signing_key = provision_identity(&database).await?;
    let store = Store::connect(&database.url).await?;
    let intent = sample_intent("01J0000000000000000000A200", "idem-a", "12.50");
    store
        .authenticate_and_admit(signed_input(
            intent.clone(),
            "nonce-0123456789abcdef",
            &signing_key,
        ))
        .await?;

    let error = store
        .authenticate_and_admit(signed_input(intent, "nonce-fedcba9876543210", &signing_key))
        .await
        .expect_err("a fresh authenticated retry still observes active work");
    assert!(matches!(error, StoreError::IdempotencyInProgress { .. }));
    assert_eq!(database.record_counts().await?, (2, 1, 0, 0, 5));

    let chain = store.load_verified_audit_chain(ORGANIZATION_ID).await?;
    let retry = chain.last().expect("fresh retry has identity evidence");
    assert_eq!(retry.event.event_type, EventType::IdentityVerified);
    assert!(retry.event.intent_id.is_none());

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn invalid_signature_is_audited_without_admission_or_nonce() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("bad_signature").await?;
    let signing_key = provision_identity(&database).await?;
    let store = Store::connect(&database.url).await?;
    let intent = sample_intent("01J0000000000000000000A300", "idem-a", "12.50");
    let mut input = signed_input(intent, "nonce-0123456789abcdef", &signing_key);
    input.signature = [0; 64];

    let error = store
        .authenticate_and_admit(input)
        .await
        .expect_err("invalid proof must fail closed");
    assert!(matches!(
        error,
        StoreError::IdentityRejected {
            reason_code: "IDENTITY_SIGNATURE_INVALID"
        }
    ));
    assert_eq!(database.record_counts().await?, (0, 0, 0, 0, 3));
    let chain = store.load_verified_audit_chain(ORGANIZATION_ID).await?;
    let rejected = chain.last().unwrap();
    assert_eq!(rejected.event.event_type, EventType::IdentityRejected);
    assert!(rejected.event.intent_id.is_none());
    assert_eq!(
        rejected.event.typed_payload()?,
        AuditPayload::IdentityRejected(atf_audit::IdentityRejectedPayload {
            organization_id: ORGANIZATION_ID.into(),
            agent_id: AGENT_ID.into(),
            reason_code: "IDENTITY_SIGNATURE_INVALID".into(),
        })
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn concurrent_nonce_reuse_binds_one_intent_and_audits_the_loser() -> Result<(), Box<dyn Error>>
{
    let database = TestDatabase::create("nonce_race").await?;
    let signing_key = provision_identity(&database).await?;
    let store_a = Store::connect(&database.url).await?;
    let store_b = Store::connect(&database.url).await?;
    let first = signed_input(
        sample_intent("01J0000000000000000000A400", "idem-a", "12.50"),
        "nonce-0123456789abcdef",
        &signing_key,
    );
    let second = signed_input(
        sample_intent("01J0000000000000000000A500", "idem-b", "11.50"),
        "nonce-0123456789abcdef",
        &signing_key,
    );
    let barrier = Arc::new(Barrier::new(2));

    let left = {
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store_a.authenticate_and_admit(first).await
        }
    };
    let right = {
        let barrier = barrier.clone();
        async move {
            barrier.wait().await;
            store_b.authenticate_and_admit(second).await
        }
    };
    let (left, right) = tokio::join!(left, right);
    match (left, right) {
        (Ok(_), Err(StoreError::NonceReplay { .. }))
        | (Err(StoreError::NonceReplay { .. }), Ok(_)) => {}
        outcomes => panic!("expected one admission and one replay, got {outcomes:?}"),
    }

    assert_eq!(database.record_counts().await?, (1, 1, 0, 0, 5));
    let verifier = Store::connect(&database.url).await?;
    let chain = verifier.load_verified_audit_chain(ORGANIZATION_ID).await?;
    let replay = chain
        .iter()
        .find(|item| item.event.event_type == EventType::ReplayDetected)
        .expect("losing binding produces ReplayDetected");
    assert!(replay.event.intent_id.is_none());
    assert_eq!(
        replay.event.data["nonce_hash"],
        atf_core::sha256_hex(b"nonce-0123456789abcdef")
    );
    assert!(replay.event.data.get("nonce").is_none());
    assert!(replay.event.data.get("signature").is_none());

    verifier.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn nonce_rows_are_immutable_and_restart_reads_reject_privileged_tampering(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("nonce_tamper").await?;
    let signing_key = provision_identity(&database).await?;
    let store = Store::connect(&database.url).await?;
    let intent = sample_intent("01J0000000000000000000A600", "idem-a", "12.50");
    store
        .authenticate_and_admit(signed_input(intent, "nonce-0123456789abcdef", &signing_key))
        .await?;

    let update = sqlx::query("UPDATE identity_nonces SET key_id = 'another-key'")
        .execute(&database.pool)
        .await
        .expect_err("Nonce bindings cannot be updated");
    assert_sqlstate(&update, "55000");
    let delete = sqlx::query("DELETE FROM identity_nonces")
        .execute(&database.pool)
        .await
        .expect_err("Nonce bindings cannot be deleted");
    assert_sqlstate(&delete, "55000");
    let truncate = sqlx::query("TRUNCATE identity_nonces")
        .execute(&database.pool)
        .await
        .expect_err("Nonce bindings cannot be truncated");
    assert_sqlstate(&truncate, "55000");

    store.close().await;
    sqlx::query("ALTER TABLE identity_nonces DISABLE TRIGGER USER")
        .execute(&database.pool)
        .await?;
    sqlx::query("UPDATE identity_nonces SET envelope_hash = $1")
        .bind("0".repeat(64))
        .execute(&database.pool)
        .await?;
    sqlx::query("ALTER TABLE identity_nonces ENABLE TRIGGER USER")
        .execute(&database.pool)
        .await?;

    let restarted = Store::connect(&database.url).await?;
    let error = restarted
        .load_admitted_intent(ORGANIZATION_ID, "01J0000000000000000000A600")
        .await
        .expect_err("a tampered Nonce binding must fail closed after restart");
    assert!(matches!(error, StoreError::NonceStateCorrupt { .. }));

    restarted.close().await;
    database.destroy().await?;
    Ok(())
}

fn signed_input(
    intent: TransactionIntent,
    nonce: &str,
    signing_key: &SigningKey,
) -> AuthenticatedAdmissionInput {
    let envelope = IdentityEnvelope {
        domain: "ATF_INTENT_V1".into(),
        organization_id: ORGANIZATION_ID.into(),
        agent_id: AGENT_ID.into(),
        key_id: KEY_ID.into(),
        intent_hash: intent.canonical_hash(),
        issued_at: timestamp("2026-08-08T01:00:00.000Z"),
        expires_at: timestamp("2026-08-08T01:04:00.000Z"),
        nonce: nonce.into(),
        audience: AUDIENCE.into(),
        environment: ENVIRONMENT.into(),
    };
    let signature = signing_key.sign(&envelope.canonical_bytes()).to_bytes();
    AuthenticatedAdmissionInput {
        intent,
        envelope,
        signature,
        audience: AUDIENCE.into(),
        environment: ENVIRONMENT.into(),
        received_at: timestamp("2026-08-08T01:00:01.000Z"),
        lease_duration: Duration::from_secs(30),
    }
}

async fn provision_identity(database: &TestDatabase) -> Result<SigningKey, Box<dyn Error>> {
    database.seed_organization(ORGANIZATION_ID).await?;
    let store = Store::connect(&database.url).await?;
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    store
        .provision_agent(
            agent_record(),
            "operator-1",
            timestamp("2026-08-08T00:00:00Z"),
        )
        .await?;
    store
        .register_identity_key(
            ORGANIZATION_ID,
            IdentityKeyRecord::from_public_key_bytes(
                AGENT_ID.into(),
                KEY_ID.into(),
                signing_key.verifying_key().as_bytes(),
                timestamp("2026-08-08T00:00:00Z"),
                Some(timestamp("2026-08-09T00:00:00Z")),
                None,
            )?,
            "operator-1",
            timestamp("2026-08-08T00:00:01Z"),
        )
        .await?;
    store.close().await;
    Ok(signing_key)
}

fn agent_record() -> AgentRecord {
    AgentRecord {
        agent_id: AGENT_ID.into(),
        organization_id: ORGANIZATION_ID.into(),
        owner_user_id: "user-001".into(),
        agent_type: "research".into(),
        model_provider: "test".into(),
        model_name: "deterministic-model".into(),
        agent_version: "1.0.0".into(),
        code_hash: "a".repeat(64),
        deployment_environment: ENVIRONMENT.into(),
        allowed_tools: vec!["mcp-market-data".into()],
        allowed_adapters: vec!["x402".into()],
        default_budget: Some("20.00".parse().unwrap()),
        risk_tier: "standard".into(),
        status: AgentStatus::Active,
        created_at: timestamp("2026-08-07T00:00:00Z"),
        expires_at: Some(timestamp("2026-08-09T00:00:00Z")),
    }
}

fn sample_intent(intent_id: &str, idempotency_key: &str, amount: &str) -> TransactionIntent {
    TransactionIntent {
        spec_version: "1.0".into(),
        intent_id: intent_id.into(),
        idempotency_key: idempotency_key.into(),
        created_at: timestamp("2026-08-08T00:59:00Z"),
        expires_at: timestamp("2026-08-08T01:05:00Z"),
        principal: Principal {
            organization_id: ORGANIZATION_ID.into(),
            user_id: Some("user-001".into()),
            agent_id: AGENT_ID.into(),
            agent_version: Some("1.0.0".into()),
            strategy_id: None,
        },
        mandate: Mandate {
            mandate_id: "mandate-001".into(),
            task_id: Some("task-001".into()),
            purpose: "purchase a dataset".into(),
            budget_id: Some("budget-001".into()),
            human_authorized: true,
        },
        action: Action {
            category: "payment".into(),
            operation: "purchase_api_resource".into(),
        },
        resource: Resource {
            protocol: "x402".into(),
            venue: Some("vendor-a".into()),
            resource_id: "dataset-a".into(),
            resource_type: Some("dataset".into()),
        },
        transaction: Transaction {
            network: "eip155:8453".into(),
            asset: "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".into(),
            amount: Amount::from_str(amount).unwrap(),
            destination: Some("eip155:8453:0x1111111111111111111111111111111111111111".into()),
            contract: None,
            calldata_hash: None,
            max_fee: Some(Amount::from_str("0.25").unwrap()),
            slippage_bps: None,
            leverage: None,
        },
        context: serde_json::json!({"task_budget": "20.00"}),
        metadata: serde_json::json!({"labels": ["research"]}),
    }
}

fn timestamp(value: &str) -> Timestamp {
    value.parse().unwrap()
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

struct TestDatabase {
    admin: PgConnection,
    pool: PgPool,
    name: String,
    url: String,
}

impl TestDatabase {
    async fn create(label: &str) -> Result<Self, Box<dyn Error>> {
        let admin_url = env::var("ATF_TEST_DATABASE_URL")?;
        let admin_options = PgConnectOptions::from_str(&admin_url)?;
        let name = format!("atf_ds016_{label}_{}", unique_suffix());
        let mut admin = PgConnection::connect_with(&admin_options).await?;
        admin
            .execute(format!("CREATE DATABASE {}", quote_identifier(&name)).as_str())
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

    async fn record_counts(&self) -> Result<(i64, i64, i64, i64, i64), sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT
                (SELECT count(*) FROM identity_nonces),
                (SELECT count(*) FROM intents),
                (SELECT count(*) FROM evaluations),
                (SELECT count(*) FROM decisions),
                (SELECT count(*) FROM audit_events)
            "#,
        )
        .fetch_one(&self.pool)
        .await
    }

    async fn destroy(self) -> Result<(), Box<dyn Error>> {
        self.pool.close().await;
        let mut admin = self.admin;
        admin
            .execute(format!("DROP DATABASE {}", quote_identifier(&self.name)).as_str())
            .await?;
        Ok(())
    }
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{}_{nanos}", process::id())
}

fn quote_identifier(identifier: &str) -> String {
    assert!(identifier
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
    format!("\"{identifier}\"")
}
