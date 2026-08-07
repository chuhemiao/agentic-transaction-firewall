use atf_audit::{
    OptionalModuleOutcome, PolicyEvaluatedPayload, PolicyOutcome, RequiredModuleOutcome,
    RiskEvaluatedPayload, SimulationCompletedPayload,
};
use atf_core::{Amount, Timestamp};
use atf_decision::{Decision, DecisionKind, Reason};
use atf_identity::{AgentRecord, AgentStatus, IdentityEnvelope, IdentityKeyRecord};
use atf_intent::{Action, Mandate, Principal, Resource, Transaction, TransactionIntent};
use atf_store::{
    AdmissionGrant, AuthenticatedAdmissionInput, EvaluationInput, FinalizationInput,
    IdempotencyState, Store, StoreError,
};
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

const TEST_KEY_ID: &str = "key-a";
const TEST_AUDIENCE: &str = "atf-store-test";
const TEST_ENVIRONMENT: &str = "test";

struct AdmissionInput {
    intent: TransactionIntent,
    received_at: Timestamp,
    lease_duration: Duration,
}

trait AuthenticatedAdmissionTestExt {
    async fn admit_intent(&self, input: AdmissionInput) -> Result<AdmissionGrant, StoreError>;
}

impl AuthenticatedAdmissionTestExt for Store {
    async fn admit_intent(&self, input: AdmissionInput) -> Result<AdmissionGrant, StoreError> {
        self.authenticate_and_admit(authenticated_input(input))
            .await
    }
}

#[tokio::test]
async fn concurrent_same_key_and_hash_create_one_reservation_and_one_evaluator_lease(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("concurrent_new").await?;
    database.seed_organization("org-a").await?;
    let store_a = Store::connect(&database.url).await?;
    let store_b = Store::connect(&database.url).await?;
    let intent = sample_intent("org-a", "intent-a", "idem-a", "12.50");
    let barrier = Arc::new(Barrier::new(2));

    let first = {
        let barrier = barrier.clone();
        let intent = intent.clone();
        let store = store_a.clone();
        async move {
            barrier.wait().await;
            store
                .admit_intent(AdmissionInput {
                    intent,
                    received_at: timestamp("2026-08-08T01:00:00Z"),
                    lease_duration: Duration::from_secs(30),
                })
                .await
        }
    };
    let second = {
        let barrier = barrier.clone();
        let intent = intent.clone();
        let store = store_b.clone();
        async move {
            barrier.wait().await;
            store
                .admit_intent(AdmissionInput {
                    intent,
                    received_at: timestamp("2026-08-08T01:00:00Z"),
                    lease_duration: Duration::from_secs(30),
                })
                .await
        }
    };

    let (first, second) = tokio::join!(first, second);
    let (grant, error) = match (first, second) {
        (Ok(grant), Err(error)) | (Err(error), Ok(grant)) => (grant, error),
        outcomes => panic!("expected one lease winner and one observer, got {outcomes:?}"),
    };
    assert!(matches!(error, StoreError::IdempotencyInProgress { .. }));
    assert_eq!(grant.admitted.intent, intent);
    assert_eq!(grant.evaluator_lease.generation(), 1);

    let counts: (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            (SELECT count(*) FROM idempotency_reservations),
            (SELECT count(*) FROM intents),
            (SELECT count(*) FROM audit_events)
        "#,
    )
    .fetch_one(&database.pool)
    .await?;
    assert_eq!(counts, (1, 1, 4));

    let restarted = Store::connect(&database.url).await?;
    let reservation = restarted
        .load_idempotency_reservation("org-a", "idem-a")
        .await?
        .expect("the committed reservation survives another Store instance");
    assert_eq!(reservation.state, IdempotencyState::InProgress);
    assert_eq!(reservation.intent_id, "intent-a");
    assert_eq!(reservation.intent_hash, intent.canonical_hash());
    assert_eq!(reservation.lease_generation, 1);
    assert!(reservation.result.is_none());

    store_a.close().await;
    store_b.close().await;
    restarted.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn same_key_with_a_different_hash_never_rebinds_the_original_reservation(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("hash_conflict").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let original = sample_intent("org-a", "intent-a", "idem-a", "12.50");
    store
        .admit_intent(AdmissionInput {
            intent: original.clone(),
            received_at: timestamp("2026-08-08T01:00:00Z"),
            lease_duration: Duration::from_secs(30),
        })
        .await?;

    let conflicting = sample_intent("org-a", "intent-a", "idem-a", "99.00");
    let error = store
        .admit_intent(AdmissionInput {
            intent: conflicting.clone(),
            received_at: timestamp("2026-08-08T01:00:01Z"),
            lease_duration: Duration::from_secs(30),
        })
        .await
        .expect_err("one organization/key must never bind to another hash");
    assert!(matches!(
        error,
        StoreError::IdempotencyConflict {
            ref submitted_hash,
            ref stored_hash,
            ..
        } if submitted_hash == &conflicting.canonical_hash()
            && stored_hash == &original.canonical_hash()
    ));

    let reservation = store
        .load_idempotency_reservation("org-a", "idem-a")
        .await?
        .expect("the original reservation remains durable");
    assert_eq!(reservation.intent_hash, original.canonical_hash());
    assert_eq!(reservation.intent_id, "intent-a");
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM intents")
            .fetch_one(&database.pool)
            .await?,
        1
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn current_evaluator_can_renew_its_lease_without_changing_the_fencing_generation(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("renew").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let grant = store
        .admit_intent(AdmissionInput {
            intent: sample_intent("org-a", "intent-a", "idem-a", "12.50"),
            received_at: timestamp("2026-08-08T01:00:00Z"),
            lease_duration: Duration::from_secs(1),
        })
        .await?;

    let renewed = store
        .renew_evaluator_lease(&grant.evaluator_lease, Duration::from_secs(30))
        .await?;

    assert_eq!(renewed.generation(), 1);
    assert!(renewed.expires_at() > grant.evaluator_lease.expires_at());
    let not_shortened = store
        .renew_evaluator_lease(&renewed, Duration::from_millis(1))
        .await?;
    assert_eq!(not_shortened.generation(), 1);
    assert!(not_shortened.expires_at() >= renewed.expires_at());
    let reservation = store
        .load_idempotency_reservation("org-a", "idem-a")
        .await?
        .expect("the renewed reservation remains queryable");
    assert_eq!(reservation.lease_generation, 1);
    assert_eq!(reservation.lease_expires_at, not_shortened.expires_at());

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn reclaiming_an_unknown_reservation_fails_closed() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("missing").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;

    let error = store
        .reclaim_expired_idempotency(
            "org-a",
            "missing-key",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            Duration::from_secs(30),
        )
        .await
        .expect_err("reclaim cannot invent an admission");
    assert!(matches!(error, StoreError::IdempotencyNotFound { .. }));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn invalid_lease_duration_is_rejected_before_durable_admission() -> Result<(), Box<dyn Error>>
{
    let database = TestDatabase::create("invalid_lease").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;

    let error = store
        .admit_intent(AdmissionInput {
            intent: sample_intent("org-a", "intent-a", "idem-a", "12.50"),
            received_at: timestamp("2026-08-08T01:00:00Z"),
            lease_duration: Duration::ZERO,
        })
        .await
        .expect_err("a zero-duration evaluator lease is unsafe");
    assert!(matches!(error, StoreError::InvalidRepositoryInput { .. }));
    for (intent_id, idempotency_key, lease_duration) in [
        (
            "intent-fractional",
            "idem-fractional",
            Duration::from_micros(1_500),
        ),
        (
            "intent-over-max",
            "idem-over-max",
            Duration::from_secs(300) + Duration::from_micros(1),
        ),
    ] {
        let error = store
            .admit_intent(AdmissionInput {
                intent: sample_intent("org-a", intent_id, idempotency_key, "12.50"),
                received_at: timestamp("2026-08-08T01:00:00Z"),
                lease_duration,
            })
            .await
            .expect_err("lease durations must be exact, bounded milliseconds");
        assert!(matches!(error, StoreError::InvalidRepositoryInput { .. }));
    }
    let counts: (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM idempotency_reservations), (SELECT count(*) FROM intents), (SELECT count(*) FROM audit_events)",
    )
    .fetch_one(&database.pool)
    .await?;
    assert_eq!(counts, (0, 0, 2));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn reclaimed_leases_are_fenced_and_can_only_complete_with_a_fail_closed_error(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("fencing").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let intent = sample_intent("org-a", "intent-a", "idem-a", "12.50");
    let grant = store
        .admit_intent(AdmissionInput {
            intent,
            received_at: timestamp("2026-08-08T01:00:00Z"),
            lease_duration: Duration::from_millis(1),
        })
        .await?;
    let stale_lease = grant.evaluator_lease.clone();
    tokio::time::sleep(Duration::from_millis(10)).await;

    let recovered_lease = store
        .reclaim_expired_idempotency(
            "org-a",
            "idem-a",
            &grant.admitted.intent_hash,
            Duration::from_secs(30),
        )
        .await?;
    assert_eq!(recovered_lease.generation(), 2);

    let stale_error = store
        .finalize_decision(finalization_input(
            &grant,
            stale_lease,
            "decision-stale",
            DecisionKind::Permit,
        ))
        .await
        .expect_err("the old generation must be fenced after reclaim");
    assert!(matches!(stale_error, StoreError::EvaluatorLeaseLost { .. }));

    let unsafe_recovery = store
        .finalize_decision(finalization_input(
            &grant,
            recovered_lease.clone(),
            "decision-unsafe-recovery",
            DecisionKind::Permit,
        ))
        .await
        .expect_err("recovery cannot silently evaluate with unpinned current inputs");
    assert!(matches!(
        unsafe_recovery,
        StoreError::RecoveredWorkMustFailClosed { .. }
    ));

    let finalized = store
        .finalize_decision(finalization_input(
            &grant,
            recovered_lease,
            "decision-error",
            DecisionKind::Error,
        ))
        .await?;
    assert_eq!(finalized.decision.decision, DecisionKind::Error);

    let retry = store
        .admit_intent(AdmissionInput {
            intent: grant.admitted.intent.clone(),
            received_at: timestamp("2026-08-08T01:00:03Z"),
            lease_duration: Duration::from_secs(30),
        })
        .await
        .expect_err("a completed key must return its immutable result state");
    assert!(matches!(
        retry,
        StoreError::IdempotencyCompleted {
            ref decision_id,
            ..
        } if decision_id == "decision-error"
    ));

    let reservation = store
        .load_idempotency_reservation("org-a", "idem-a")
        .await?
        .expect("completion remains queryable");
    assert_eq!(reservation.state, IdempotencyState::Completed);
    assert_eq!(reservation.lease_generation, 2);
    let result = reservation.result.expect("completion binds the result");
    assert_eq!(result.evaluation_id, finalized.evaluation.evaluation_id);
    assert_eq!(result.decision_id, finalized.decision.decision_id);
    assert_eq!(result.decision_hash, finalized.decision_hash);

    let mutation = sqlx::query(
        r#"
        UPDATE idempotency_reservations
        SET result_decision_hash = $3
        WHERE organization_id = $1 AND idempotency_key = $2
        "#,
    )
    .bind("org-a")
    .bind("idem-a")
    .bind("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    .execute(&database.pool)
    .await
    .expect_err("a completed reservation must be immutable");
    assert_sqlstate(&mutation, "55000");
    let deletion = sqlx::query(
        "DELETE FROM idempotency_reservations WHERE organization_id = $1 AND idempotency_key = $2",
    )
    .bind("org-a")
    .bind("idem-a")
    .execute(&database.pool)
    .await
    .expect_err("a durable idempotency binding must not be deleted");
    assert_sqlstate(&deletion, "55000");
    let truncate = sqlx::query("TRUNCATE idempotency_reservations")
        .execute(&database.pool)
        .await
        .expect_err("durable idempotency bindings must not be truncated");
    assert_sqlstate(&truncate, "0A000");

    let restarted = Store::connect(&database.url).await?;
    let reloaded = restarted
        .load_finalized_decision("org-a", "intent-a")
        .await?
        .expect("the fenced completed result survives another Store instance");
    assert_eq!(reloaded, finalized);

    sqlx::query("ALTER TABLE idempotency_reservations DISABLE TRIGGER USER")
        .execute(&database.pool)
        .await?;
    sqlx::query(
        r#"
        UPDATE idempotency_reservations
        SET state = 'IN_PROGRESS',
            result_evaluation_id = NULL,
            result_decision_id = NULL,
            result_decision_hash = NULL,
            completed_at = NULL
        WHERE organization_id = 'org-a' AND idempotency_key = 'idem-a'
        "#,
    )
    .execute(&database.pool)
    .await?;
    sqlx::query("ALTER TABLE idempotency_reservations ENABLE TRIGGER USER")
        .execute(&database.pool)
        .await?;
    let error = restarted
        .load_finalized_decision("org-a", "intent-a")
        .await
        .expect_err("a Decision without its completed idempotency result is not queryable");
    assert!(matches!(
        error,
        StoreError::IncompleteDecisionEvidence { .. }
    ));

    store.close().await;
    restarted.close().await;
    database.destroy().await?;
    Ok(())
}

fn finalization_input(
    grant: &AdmissionGrant,
    evaluator_lease: atf_store::EvaluatorLease,
    decision_id: &str,
    decision_kind: DecisionKind,
) -> FinalizationInput {
    let is_error = decision_kind == DecisionKind::Error;
    FinalizationInput {
        organization_id: grant.admitted.organization_id.clone(),
        intent_id: grant.admitted.intent.intent_id.clone(),
        expected_intent_hash: grant.admitted.intent_hash.clone(),
        expected_lifecycle_version: grant.admitted.lifecycle.version,
        evaluator_lease,
        evaluation: EvaluationInput {
            evaluation_id: "evaluation-a".into(),
            evaluated_at: timestamp("2026-08-08T01:00:01Z"),
            policy: PolicyEvaluatedPayload {
                outcome: if is_error {
                    RequiredModuleOutcome::Error {
                        error_code: "RECOVERY_CONTEXT_UNAVAILABLE".into(),
                    }
                } else {
                    RequiredModuleOutcome::Succeeded {
                        result: PolicyOutcome::Permit,
                    }
                },
                policy_ids: if is_error {
                    Vec::new()
                } else {
                    vec!["policy-a".into()]
                },
            },
            risk: if is_error {
                RiskEvaluatedPayload {
                    outcome: OptionalModuleOutcome::NotRun {
                        reason_code: "POLICY_ERROR".into(),
                    },
                }
            } else {
                RiskEvaluatedPayload {
                    outcome: OptionalModuleOutcome::Succeeded { result: Vec::new() },
                }
            },
            simulation: SimulationCompletedPayload {
                outcome: OptionalModuleOutcome::NotRun {
                    reason_code: "SIMULATOR_NOT_IMPLEMENTED".into(),
                },
            },
        },
        decision: Decision {
            decision_id: decision_id.into(),
            intent_id: grant.admitted.intent.intent_id.clone(),
            decision: decision_kind,
            reasons: vec![Reason {
                code: if is_error {
                    "RECOVERY_CONTEXT_UNAVAILABLE".into()
                } else {
                    "policy-a".into()
                },
                severity: if is_error {
                    "critical".into()
                } else {
                    "info".into()
                },
                message: if is_error {
                    "Recovery failed closed.".into()
                } else {
                    "Policy allowed the request.".into()
                },
            }],
        },
        decided_at: timestamp("2026-08-08T01:00:02Z"),
    }
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

fn sample_intent(
    organization_id: &str,
    intent_id: &str,
    idempotency_key: &str,
    amount: &str,
) -> TransactionIntent {
    TransactionIntent {
        spec_version: "1.0".into(),
        intent_id: intent_id.into(),
        idempotency_key: idempotency_key.into(),
        created_at: timestamp("2026-08-08T00:00:00Z"),
        expires_at: timestamp("2026-08-08T02:00:00Z"),
        principal: Principal {
            organization_id: organization_id.into(),
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
            amount: Amount::from_str(amount).expect("test amount is valid"),
            destination: Some("eip155:8453:0x1111111111111111111111111111111111111111".into()),
            contract: None,
            calldata_hash: None,
            max_fee: Some(Amount::from_str("0.25").expect("test amount is valid")),
            slippage_bps: None,
            leverage: None,
        },
        context: serde_json::json!({"task_budget": "20.00"}),
        metadata: serde_json::json!({"labels": ["research"]}),
    }
}

fn timestamp(value: &str) -> Timestamp {
    value.parse().expect("test timestamp is valid RFC 3339")
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
        let name = format!("atf_ds012_{label}_{}", unique_suffix());
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
        provision_identity(&self.url, organization_id).await?;
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

fn authenticated_input(input: AdmissionInput) -> AuthenticatedAdmissionInput {
    let signing_key = SigningKey::from_bytes(&[42; 32]);
    let intent_hash = input.intent.canonical_hash();
    let envelope = IdentityEnvelope {
        domain: "ATF_INTENT_V1".into(),
        organization_id: input.intent.principal.organization_id.clone(),
        agent_id: input.intent.principal.agent_id.clone(),
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
        intent: input.intent,
        envelope,
        signature,
        audience: TEST_AUDIENCE.into(),
        environment: TEST_ENVIRONMENT.into(),
        received_at: input.received_at,
        lease_duration: input.lease_duration,
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
            test_agent(organization_id),
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

fn test_agent(organization_id: &str) -> AgentRecord {
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
