use atf_core::{Amount, Timestamp};
use atf_decision::{Decision, DecisionKind, Reason};
use atf_intent::{Action, Mandate, Principal, Resource, Transaction, TransactionIntent};
use atf_store::{
    AdmissionInput, EvaluationInput, FinalizationInput, Store, StoreError, StoredEvaluation,
};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, Executor, PgConnection, PgPool,
};
use std::{
    env,
    error::Error,
    process,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

#[tokio::test]
async fn admission_is_atomic_and_never_overwrites_canonical_intent() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("admission").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let intent = sample_intent("org-a", "intent-a", "idem-a", "12.50");

    let admitted = store
        .admit_intent(AdmissionInput {
            intent: intent.clone(),
            received_at: timestamp("2026-08-08T01:00:00.123456Z"),
        })
        .await?;

    assert_eq!(admitted.intent, intent);
    assert_eq!(admitted.intent_hash, intent.canonical_hash());
    assert_eq!(admitted.received_at.to_string(), "2026-08-08T01:00:00.123Z");
    assert_eq!(
        admitted.audit_event.event.event_type,
        atf_audit::EventType::IntentReceived
    );
    assert_eq!(
        admitted.audit_event.event.intent_id.as_deref(),
        Some("intent-a")
    );

    let mut conflicting = intent.clone();
    conflicting.transaction.amount = Amount::from_str("99.00")?;
    let error = store
        .admit_intent(AdmissionInput {
            intent: conflicting,
            received_at: timestamp("2026-08-08T01:00:01Z"),
        })
        .await
        .expect_err("an immutable Intent must not be overwritten");
    assert!(matches!(error, StoreError::IntentConflict { .. }));

    let reloaded = store
        .load_admitted_intent("org-a", "intent-a")
        .await?
        .expect("the original admission remains queryable");
    assert_eq!(reloaded.intent, intent);
    assert_eq!(reloaded.intent_hash, intent.canonical_hash());
    assert_eq!(store.load_verified_audit_chain("org-a").await?.len(), 1);

    let reused_key = sample_intent("org-a", "intent-b", "idem-a", "7.00");
    let error = store
        .admit_intent(AdmissionInput {
            intent: reused_key,
            received_at: timestamp("2026-08-08T01:00:02Z"),
        })
        .await
        .expect_err("one idempotency key must never bind to a second Intent");
    assert!(matches!(error, StoreError::IntentConflict { .. }));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn admission_audit_failure_rolls_back_the_intent() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("admission_rollback").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;

    sqlx::query(
        r#"
        CREATE FUNCTION reject_test_intent_received()
        RETURNS TRIGGER
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NEW.event_type = 'IntentReceived' THEN
                RAISE EXCEPTION 'injected admission failure' USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END;
        $$
        "#,
    )
    .execute(&database.pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TRIGGER audit_events_reject_test_intent_received
        BEFORE INSERT ON audit_events
        FOR EACH ROW
        EXECUTE FUNCTION reject_test_intent_received()
        "#,
    )
    .execute(&database.pool)
    .await?;

    let error = store
        .admit_intent(AdmissionInput {
            intent: sample_intent("org-a", "intent-a", "idem-a", "12.50"),
            received_at: timestamp("2026-08-08T01:00:00Z"),
        })
        .await
        .expect_err("the injected Audit insert failure must abort admission");
    assert!(matches!(error, StoreError::Database(_)));

    let (intents, events, heads): (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM intents), (SELECT count(*) FROM audit_events), (SELECT count(*) FROM audit_chain_heads)",
    )
    .fetch_one(&database.pool)
    .await?;
    assert_eq!((intents, events, heads), (0, 0, 0));
    assert!(store
        .load_admitted_intent("org-a", "intent-a")
        .await?
        .is_none());

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn finalization_is_queryable_only_with_matching_evaluation_and_audit_evidence(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("complete").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let intent = sample_intent("org-a", "intent-a", "idem-a", "12.50");
    let admitted = store
        .admit_intent(AdmissionInput {
            intent: intent.clone(),
            received_at: timestamp("2026-08-08T01:00:00Z"),
        })
        .await?;
    let decision = sample_decision("decision-a", "intent-a");

    let finalized = store
        .finalize_decision(FinalizationInput {
            organization_id: "org-a".into(),
            intent_id: "intent-a".into(),
            expected_intent_hash: admitted.intent_hash.clone(),
            evaluation: EvaluationInput {
                evaluation_id: "evaluation-a".into(),
                evaluated_at: timestamp("2026-08-08T01:00:01Z"),
                evidence: serde_json::json!({
                    "policy": {"decision": "PERMIT"},
                    "risk": {"findings": []}
                }),
            },
            decision: decision.clone(),
            decided_at: timestamp("2026-08-08T01:00:02Z"),
        })
        .await?;

    assert_eq!(finalized.decision, decision);
    assert_eq!(finalized.evaluation.intent_hash, admitted.intent_hash);
    assert_eq!(
        finalized.audit_event.evaluation_id.as_deref(),
        Some("evaluation-a")
    );
    assert_eq!(
        finalized.audit_event.decision_id.as_deref(),
        Some("decision-a")
    );

    let reloaded = store
        .load_finalized_decision("org-a", "intent-a")
        .await?
        .expect("a committed, evidence-complete Decision is queryable");
    assert_eq!(reloaded, finalized);

    let chain = store.load_verified_audit_chain("org-a").await?;
    assert_eq!(chain.len(), 2);
    assert_eq!(
        chain[1].event.event_type,
        atf_audit::EventType::DecisionRecorded
    );
    assert_eq!(chain[1].evaluation_id.as_deref(), Some("evaluation-a"));
    assert_eq!(chain[1].decision_id.as_deref(), Some("decision-a"));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn audit_failure_rolls_back_every_finalization_record() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("rollback").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let intent = sample_intent("org-a", "intent-a", "idem-a", "12.50");
    let admitted = store
        .admit_intent(AdmissionInput {
            intent,
            received_at: timestamp("2026-08-08T01:00:00Z"),
        })
        .await?;

    sqlx::query(
        r#"
        CREATE FUNCTION reject_test_decision_recorded()
        RETURNS TRIGGER
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NEW.event_type = 'DecisionRecorded' THEN
                RAISE EXCEPTION 'injected finalization failure' USING ERRCODE = '55000';
            END IF;
            RETURN NEW;
        END;
        $$
        "#,
    )
    .execute(&database.pool)
    .await?;
    sqlx::query(
        r#"
        CREATE TRIGGER audit_events_reject_test_decision_recorded
        BEFORE INSERT ON audit_events
        FOR EACH ROW
        EXECUTE FUNCTION reject_test_decision_recorded()
        "#,
    )
    .execute(&database.pool)
    .await?;

    let error = store
        .finalize_decision(FinalizationInput {
            organization_id: "org-a".into(),
            intent_id: "intent-a".into(),
            expected_intent_hash: admitted.intent_hash,
            evaluation: EvaluationInput {
                evaluation_id: "evaluation-a".into(),
                evaluated_at: timestamp("2026-08-08T01:00:01Z"),
                evidence: serde_json::json!({"policy": {"decision": "PERMIT"}}),
            },
            decision: sample_decision("decision-a", "intent-a"),
            decided_at: timestamp("2026-08-08T01:00:02Z"),
        })
        .await
        .expect_err("the injected Audit insert failure must abort finalization");
    assert!(matches!(error, StoreError::Database(_)));

    let (evaluations, decisions, decision_events): (i64, i64, i64) = sqlx::query_as(
        r#"
        SELECT
            (SELECT count(*) FROM evaluations WHERE organization_id = 'org-a'),
            (SELECT count(*) FROM decisions WHERE organization_id = 'org-a'),
            (SELECT count(*) FROM audit_events
             WHERE organization_id = 'org-a' AND event_type = 'DecisionRecorded')
        "#,
    )
    .fetch_one(&database.pool)
    .await?;
    assert_eq!((evaluations, decisions, decision_events), (0, 0, 0));
    assert!(store
        .load_finalized_decision("org-a", "intent-a")
        .await?
        .is_none());

    let chain = store.load_verified_audit_chain("org-a").await?;
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].sequence, 1);

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn finalization_rejects_an_intent_hash_mismatch_without_writes() -> Result<(), Box<dyn Error>>
{
    let database = TestDatabase::create("hash_mismatch").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let intent = sample_intent("org-a", "intent-a", "idem-a", "12.50");
    store
        .admit_intent(AdmissionInput {
            intent,
            received_at: timestamp("2026-08-08T01:00:00Z"),
        })
        .await?;

    let error = store
        .finalize_decision(FinalizationInput {
            organization_id: "org-a".into(),
            intent_id: "intent-a".into(),
            expected_intent_hash: "f".repeat(64),
            evaluation: EvaluationInput {
                evaluation_id: "evaluation-a".into(),
                evaluated_at: timestamp("2026-08-08T01:00:01Z"),
                evidence: serde_json::json!({"policy": {"decision": "PERMIT"}}),
            },
            decision: sample_decision("decision-a", "intent-a"),
            decided_at: timestamp("2026-08-08T01:00:02Z"),
        })
        .await
        .expect_err("stale or mismatched evaluation input must fail closed");
    assert!(matches!(error, StoreError::IntentHashMismatch { .. }));

    let (evaluations, decisions): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM evaluations), (SELECT count(*) FROM decisions)",
    )
    .fetch_one(&database.pool)
    .await?;
    assert_eq!((evaluations, decisions), (0, 0));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn read_api_rejects_a_decision_without_bound_audit_evidence() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("missing_evidence").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let intent = sample_intent("org-a", "intent-a", "idem-a", "12.50");
    let admitted = store
        .admit_intent(AdmissionInput {
            intent,
            received_at: timestamp("2026-08-08T01:00:00Z"),
        })
        .await?;

    let evaluated_at = timestamp("2026-08-08T01:00:01Z");
    let evaluation = StoredEvaluation {
        schema_version: 1,
        evaluation_id: "evaluation-a".into(),
        intent_id: "intent-a".into(),
        intent_hash: admitted.intent_hash,
        evaluated_at,
        evidence: serde_json::json!({"policy": {"decision": "PERMIT"}}),
    };
    let evaluation_value = atf_core::sort_json_keys(serde_json::to_value(&evaluation)?);
    let evaluation_bytes = serde_json::to_vec(&evaluation_value)?;
    let evaluation_hash = atf_core::sha256_hex(&evaluation_bytes);
    sqlx::query(
        r#"
        INSERT INTO evaluations (
            organization_id, evaluation_id, intent_id, canonical_evaluation,
            canonical_evaluation_bytes, evaluation_hash, evaluated_at
        ) VALUES ('org-a', 'evaluation-a', 'intent-a', $1, $2, $3, $4)
        "#,
    )
    .bind(evaluation_value)
    .bind(evaluation_bytes)
    .bind(evaluation_hash)
    .bind(evaluated_at.as_datetime())
    .execute(&database.pool)
    .await?;

    let decision = sample_decision("decision-a", "intent-a");
    let decision_value = atf_core::sort_json_keys(serde_json::to_value(&decision)?);
    let decision_bytes = serde_json::to_vec(&decision_value)?;
    let decision_hash = atf_core::sha256_hex(&decision_bytes);
    sqlx::query(
        r#"
        INSERT INTO decisions (
            organization_id, decision_id, intent_id, evaluation_id,
            canonical_decision, canonical_decision_bytes, decision_hash, decided_at
        ) VALUES ('org-a', 'decision-a', 'intent-a', 'evaluation-a', $1, $2, $3, $4)
        "#,
    )
    .bind(decision_value)
    .bind(decision_bytes)
    .bind(decision_hash)
    .bind(timestamp("2026-08-08T01:00:02Z").as_datetime())
    .execute(&database.pool)
    .await?;

    let error = store
        .load_finalized_decision("org-a", "intent-a")
        .await
        .expect_err("a Decision without DecisionRecorded evidence must not be exposed");
    assert!(matches!(
        error,
        StoreError::IncompleteDecisionEvidence { .. }
    ));

    store.close().await;
    database.destroy().await?;
    Ok(())
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
        expires_at: timestamp("2026-08-08T00:05:00Z"),
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
            network: "base".into(),
            asset: "eip155:8453/erc20:0x0".into(),
            amount: Amount::from_str(amount).expect("test amount is valid"),
            destination: Some("0x0000000000000000000000000000000000000001".into()),
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

fn sample_decision(decision_id: &str, intent_id: &str) -> Decision {
    Decision {
        decision_id: decision_id.into(),
        intent_id: intent_id.into(),
        decision: DecisionKind::Permit,
        reasons: vec![Reason {
            code: "policy-a".into(),
            severity: "info".into(),
            message: "policy allowed the request".into(),
        }],
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
        let name = format!("atf_ds004_{label}_{}", unique_suffix());
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
