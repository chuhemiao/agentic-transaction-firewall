use std::{
    env,
    error::Error,
    process,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use atf_core::{
    EvaluationContext, EvaluationContextInput, EvidenceTrustPolicyReference,
    ExternalSnapshotReference, RepositorySnapshot, SimulationReference, Timestamp,
    VersionedArtifactReference,
};
use atf_identity::{AgentRecord, AgentStatus, IdentityEnvelope, IdentityKeyRecord};
use atf_intent::{Action, Mandate, Principal, Resource, Transaction, TransactionIntent};
use atf_store::{AuthenticatedAdmissionInput, EvaluationContextPersistence, Store, StoreError};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, Executor, PgConnection, PgPool,
};

const TEST_KEY_ID: &str = "key-a";
const TEST_AUDIENCE: &str = "atf-store-test";
const TEST_ENVIRONMENT: &str = "test";

#[tokio::test]
async fn context_is_atomic_immutable_idempotent_and_verified_after_restart(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("context").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let intent = sample_intent();
    let admission = store
        .authenticate_and_admit(authenticated_input(intent.clone()))
        .await?;
    let chain = store.load_verified_audit_chain("org-a").await?;
    for invalid_context in [
        context_for_parts(
            &intent,
            &chain,
            "01J0000000000000000000EC98",
            serde_json::json!({"forged": true}),
            "atf.agent-commerce.payment",
        ),
        context_for_parts(
            &intent,
            &chain,
            "01J0000000000000000000EC99",
            intent.context.clone(),
            "forged.profile",
        ),
    ] {
        let error = store
            .persist_evaluation_context(EvaluationContextPersistence {
                organization_id: "org-a".into(),
                expected_intent_hash: intent.canonical_hash(),
                evaluator_lease: admission.evaluator_lease.clone(),
                context: invalid_context,
            })
            .await
            .expect_err("the snapshot must derive its Agent context and Profile from the Intent");
        assert!(matches!(error, StoreError::InvalidRepositoryInput { .. }));
    }
    let unwritten_contexts: i64 = sqlx::query_scalar("SELECT count(*) FROM evaluation_contexts")
        .fetch_one(&database.pool)
        .await?;
    assert_eq!(unwritten_contexts, 0);

    let context = context_for(&intent, &chain, "01J0000000000000000000EC00");
    let input = EvaluationContextPersistence {
        organization_id: "org-a".into(),
        expected_intent_hash: intent.canonical_hash(),
        evaluator_lease: admission.evaluator_lease.clone(),
        context: context.clone(),
    };

    let stored = store.persist_evaluation_context(input.clone()).await?;
    assert_eq!(stored.context, context);
    assert_eq!(
        stored.audit_event.event.event_type,
        atf_audit::EventType::ContextEnriched
    );
    assert_eq!(
        stored.audit_event.event.intent_id.as_deref(),
        Some("intent-a")
    );

    let event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE organization_id = 'org-a' AND event_type = 'ContextEnriched'",
    )
    .fetch_one(&database.pool)
    .await?;
    let retried = store.persist_evaluation_context(input).await?;
    assert_eq!(retried.context, context);
    assert_eq!(
        retried.audit_event.event.event_id,
        stored.audit_event.event.event_id
    );
    let retry_event_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE organization_id = 'org-a' AND event_type = 'ContextEnriched'",
    )
    .fetch_one(&database.pool)
    .await?;
    assert_eq!((event_count, retry_event_count), (1, 1));

    let conflicting = context_for(&intent, &chain, "01J0000000000000000000EC01");
    let error = store
        .persist_evaluation_context(EvaluationContextPersistence {
            organization_id: "org-a".into(),
            expected_intent_hash: intent.canonical_hash(),
            evaluator_lease: admission.evaluator_lease,
            context: conflicting,
        })
        .await
        .expect_err("one Intent cannot acquire a second Evaluation Context");
    assert!(matches!(
        error,
        StoreError::EvaluationContextConflict { .. }
    ));

    for statement in [
        "UPDATE evaluation_contexts SET environment = 'other' WHERE organization_id = 'org-a'",
        "DELETE FROM evaluation_contexts WHERE organization_id = 'org-a'",
        "TRUNCATE evaluation_contexts",
    ] {
        assert!(sqlx::query(statement)
            .execute(&database.pool)
            .await
            .is_err());
    }

    store.close().await;
    let restarted = Store::connect(&database.url).await?;
    let loaded = restarted
        .load_evaluation_context("org-a", context.evaluation_id())
        .await?
        .expect("the snapshot survives restart");
    assert_eq!(loaded.context, context);
    assert!(!loaded.context.is_newly_constructed());

    restarted.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn stale_lease_and_row_tampering_fail_closed() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("context_tamper").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let intent = sample_intent();
    let admission = store
        .authenticate_and_admit(authenticated_input(intent.clone()))
        .await?;
    let chain = store.load_verified_audit_chain("org-a").await?;
    let context = context_for(&intent, &chain, "01J0000000000000000000EC00");

    sqlx::query(
        "UPDATE idempotency_reservations SET lease_expires_at = clock_timestamp() - interval '1 second' WHERE organization_id = 'org-a'",
    )
    .execute(&database.pool)
    .await?;
    let error = store
        .persist_evaluation_context(EvaluationContextPersistence {
            organization_id: "org-a".into(),
            expected_intent_hash: intent.canonical_hash(),
            evaluator_lease: admission.evaluator_lease,
            context: context.clone(),
        })
        .await
        .expect_err("an expired evaluator cannot create a context");
    assert!(matches!(error, StoreError::EvaluatorLeaseLost { .. }));

    let lease = store
        .reclaim_expired_idempotency(
            "org-a",
            &intent.idempotency_key,
            &intent.canonical_hash(),
            Duration::from_secs(30),
        )
        .await?;
    store
        .persist_evaluation_context(EvaluationContextPersistence {
            organization_id: "org-a".into(),
            expected_intent_hash: intent.canonical_hash(),
            evaluator_lease: lease,
            context: context.clone(),
        })
        .await?;

    sqlx::query(
        "ALTER TABLE evaluation_contexts DISABLE TRIGGER evaluation_contexts_protect_mutation",
    )
    .execute(&database.pool)
    .await?;
    sqlx::query(
        "UPDATE evaluation_contexts SET canonical_context = jsonb_set(canonical_context, '{environment}', '\"tampered\"'::jsonb) WHERE organization_id = 'org-a'",
    )
    .execute(&database.pool)
    .await?;
    sqlx::query(
        "ALTER TABLE evaluation_contexts ENABLE TRIGGER evaluation_contexts_protect_mutation",
    )
    .execute(&database.pool)
    .await?;

    let error = store
        .load_evaluation_context("org-a", context.evaluation_id())
        .await
        .expect_err("redundant-column tampering must be detected");
    assert!(matches!(error, StoreError::DurableStateCorrupt { .. }));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

fn context_for(
    intent: &TransactionIntent,
    chain: &[atf_store::StoredAuditEvent],
    evaluation_id: &str,
) -> EvaluationContext {
    context_for_parts(
        intent,
        chain,
        evaluation_id,
        intent.context.clone(),
        "atf.agent-commerce.payment",
    )
}

fn context_for_parts(
    intent: &TransactionIntent,
    chain: &[atf_store::StoredAuditEvent],
    evaluation_id: &str,
    agent_context: serde_json::Value,
    profile_id: &str,
) -> EvaluationContext {
    let tail = chain.last().expect("admission creates Audit evidence");
    EvaluationContext::new(EvaluationContextInput {
        evaluation_id: evaluation_id.into(),
        intent_id: intent.intent_id.clone(),
        intent_hash: intent.canonical_hash(),
        evaluation_time: timestamp("2026-08-08T01:01:00Z"),
        environment: TEST_ENVIRONMENT.into(),
        profile_id: profile_id.into(),
        profile_version: "1.0".into(),
        policy: VersionedArtifactReference::available("policy-a", "1.0.0", "b".repeat(64)).unwrap(),
        risk: VersionedArtifactReference::available(
            "atf-risk-engine-v1",
            "risk-rules-1.0.0",
            "c".repeat(64),
        )
        .unwrap(),
        context_snapshot_id: "01J0000000000000000000CS00".into(),
        agent_context,
        evidence: Vec::new(),
        evidence_trust_policy: EvidenceTrustPolicyReference::not_configured(
            "TRUST_POLICY_NOT_CONFIGURED",
        )
        .unwrap(),
        history: RepositorySnapshot::new(
            format!("audit-chain:org-a:{}", tail.sequence),
            u64::try_from(tail.sequence).unwrap(),
            tail.event_hash.clone(),
        )
        .unwrap(),
        market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_SNAPSHOT_UNAVAILABLE")
            .unwrap(),
        simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED").unwrap(),
    })
    .unwrap()
}

fn authenticated_input(intent: TransactionIntent) -> AuthenticatedAdmissionInput {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let intent_hash = intent.canonical_hash();
    let envelope = IdentityEnvelope {
        domain: "ATF_INTENT_V1".into(),
        organization_id: intent.principal.organization_id.clone(),
        agent_id: intent.principal.agent_id.clone(),
        key_id: TEST_KEY_ID.into(),
        intent_hash: intent_hash.clone(),
        issued_at: timestamp("2026-08-08T01:00:00Z"),
        expires_at: timestamp("2026-08-08T01:05:00Z"),
        nonce: format!("nonce-{}", &intent_hash[..32]),
        audience: TEST_AUDIENCE.into(),
        environment: TEST_ENVIRONMENT.into(),
    };
    let signature = signing_key.sign(&envelope.canonical_bytes()).to_bytes();
    AuthenticatedAdmissionInput {
        intent,
        envelope,
        signature,
        audience: TEST_AUDIENCE.into(),
        environment: TEST_ENVIRONMENT.into(),
        received_at: timestamp("2026-08-08T01:00:00Z"),
        lease_duration: Duration::from_secs(30),
    }
}

fn sample_intent() -> TransactionIntent {
    TransactionIntent {
        spec_version: "1.0".into(),
        intent_id: "intent-a".into(),
        idempotency_key: "idem-a".into(),
        created_at: timestamp("2026-08-08T00:00:00Z"),
        expires_at: timestamp("2026-08-08T02:00:00Z"),
        principal: Principal {
            organization_id: "org-a".into(),
            user_id: Some("user-a".into()),
            agent_id: "agent-a".into(),
            agent_version: Some("1.0.0".into()),
            strategy_id: None,
        },
        mandate: Mandate {
            mandate_id: "mandate-a".into(),
            task_id: Some("task-a".into()),
            purpose: "purchase a dataset".into(),
            budget_id: Some("budget-a".into()),
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
            amount: "12.50".parse().unwrap(),
            destination: Some("eip155:8453:0x1111111111111111111111111111111111111111".into()),
            contract: None,
            calldata_hash: None,
            max_fee: None,
            slippage_bps: None,
            leverage: None,
        },
        context: serde_json::json!({"task_budget": "20.00"}),
        metadata: serde_json::json!({}),
    }
}

fn timestamp(value: &str) -> Timestamp {
    value.parse().unwrap()
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
        let name = format!("atf_ds023_{label}_{}", unique_suffix());
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

    async fn seed_organization(&self, organization_id: &str) -> Result<(), Box<dyn Error>> {
        sqlx::query("INSERT INTO organizations (organization_id) VALUES ($1)")
            .bind(organization_id)
            .execute(&self.pool)
            .await?;
        provision_identity(&self.url, organization_id).await
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

async fn provision_identity(
    database_url: &str,
    organization_id: &str,
) -> Result<(), Box<dyn Error>> {
    let store = Store::connect(database_url).await?;
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    store
        .provision_agent(
            AgentRecord {
                agent_id: "agent-a".into(),
                organization_id: organization_id.into(),
                owner_user_id: "user-a".into(),
                agent_type: "test".into(),
                model_provider: "test".into(),
                model_name: "deterministic".into(),
                agent_version: "1.0.0".into(),
                code_hash: "a".repeat(64),
                deployment_environment: TEST_ENVIRONMENT.into(),
                allowed_tools: Vec::new(),
                allowed_adapters: Vec::new(),
                default_budget: None,
                risk_tier: "standard".into(),
                status: AgentStatus::Active,
                created_at: timestamp("2026-08-07T00:00:00Z"),
                expires_at: Some(timestamp("2026-08-09T00:00:00Z")),
            },
            "test-operator",
            timestamp("2026-08-08T00:00:00Z"),
        )
        .await?;
    store
        .register_identity_key(
            organization_id,
            IdentityKeyRecord::from_public_key_bytes(
                "agent-a".into(),
                TEST_KEY_ID.into(),
                signing_key.verifying_key().as_bytes(),
                timestamp("2026-08-08T00:00:00Z"),
                Some(timestamp("2026-08-09T00:00:00Z")),
                None,
            )?,
            "test-operator",
            timestamp("2026-08-08T00:00:01Z"),
        )
        .await?;
    store.close().await;
    Ok(())
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
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_'));
    format!("\"{identifier}\"")
}
