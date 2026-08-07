use atf_audit::{
    AuditPayload, EventType, IntentCancelledPayload, NewAuditEvent, OptionalModuleOutcome,
    PolicyEvaluatedPayload, PolicyOutcome, RequiredModuleOutcome, RiskEvaluatedPayload,
    SimulationCompletedPayload,
};
use atf_core::{Amount, IntentLifecycleState as State, Timestamp};
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
    assert_eq!(admitted.lifecycle.state, State::Received);
    assert_eq!(admitted.lifecycle.version, 1);
    assert_eq!(admitted.lifecycle.contract_version, 1);
    assert_eq!(
        admitted.lifecycle.last_event_id.as_deref(),
        Some(admitted.audit_event.event.event_id.as_str())
    );
    assert_eq!(
        admitted.audit_event.event.event_type,
        atf_audit::EventType::IntentReceived
    );
    assert_eq!(
        admitted.audit_event.event.intent_id.as_deref(),
        Some("intent-a")
    );
    assert!(matches!(
        admitted.audit_event.event.typed_payload()?,
        atf_audit::AuditPayload::IntentReceived(_)
    ));

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
            expected_lifecycle_version: admitted.lifecycle.version,
            evaluation: evaluation_input("evaluation-a", "2026-08-08T01:00:01Z"),
            decision: decision.clone(),
            decided_at: timestamp("2026-08-08T01:00:02Z"),
        })
        .await?;

    assert_eq!(finalized.decision, decision);
    assert_eq!(finalized.evaluation.intent_hash, admitted.intent_hash);
    assert_eq!(finalized.lifecycle.state, State::DecidedPermit);
    assert_eq!(finalized.lifecycle.version, 6);
    assert_eq!(finalized.lifecycle.contract_version, 1);
    assert_eq!(
        finalized.lifecycle.last_event_id.as_deref(),
        Some(finalized.audit_event.event.event_id.as_str())
    );
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
    assert_eq!(chain.len(), 6);
    assert_eq!(
        chain
            .iter()
            .map(|stored| stored.event.event_type)
            .collect::<Vec<_>>(),
        vec![
            EventType::IntentReceived,
            EventType::IdentityVerificationSkipped,
            EventType::PolicyEvaluated,
            EventType::RiskEvaluated,
            EventType::SimulationCompleted,
            EventType::DecisionRecorded,
        ]
    );
    assert_eq!(chain[5].evaluation_id.as_deref(), Some("evaluation-a"));
    assert_eq!(chain[5].decision_id.as_deref(), Some("decision-a"));
    assert!(matches!(
        chain[5].event.typed_payload()?,
        AuditPayload::DecisionRecorded(_)
    ));

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
            IF NEW.event_type = 'RiskEvaluated' THEN
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
            expected_lifecycle_version: admitted.lifecycle.version,
            evaluation: evaluation_input("evaluation-a", "2026-08-08T01:00:01Z"),
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
    assert_eq!(
        store
            .load_intent_lifecycle("org-a", "intent-a")
            .await?
            .expect("the admitted lifecycle remains")
            .state,
        State::Received
    );

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
    let admitted = store
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
            expected_lifecycle_version: admitted.lifecycle.version,
            evaluation: evaluation_input("evaluation-a", "2026-08-08T01:00:01Z"),
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
async fn finalization_rejects_a_decision_time_before_evaluation_without_writes(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("time_order").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let admitted = store
        .admit_intent(AdmissionInput {
            intent: sample_intent("org-a", "intent-a", "idem-a", "12.50"),
            received_at: timestamp("2026-08-08T01:00:00Z"),
        })
        .await?;

    let error = store
        .finalize_decision(FinalizationInput {
            organization_id: "org-a".into(),
            intent_id: "intent-a".into(),
            expected_intent_hash: admitted.intent_hash,
            expected_lifecycle_version: admitted.lifecycle.version,
            evaluation: evaluation_input("evaluation-a", "2026-08-08T01:00:02Z"),
            decision: sample_decision("decision-a", "intent-a"),
            decided_at: timestamp("2026-08-08T01:00:01Z"),
        })
        .await
        .expect_err("a Decision cannot predate the Evaluation it records");
    assert!(matches!(error, StoreError::InvalidRepositoryInput { .. }));
    let (evaluations, decisions): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM evaluations), (SELECT count(*) FROM decisions)",
    )
    .fetch_one(&database.pool)
    .await?;
    assert_eq!((evaluations, decisions), (0, 0));
    assert_eq!(store.load_verified_audit_chain("org-a").await?.len(), 1);

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

#[tokio::test]
async fn expected_lifecycle_version_allows_only_one_concurrent_finalizer(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("lifecycle_race").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let admitted = store
        .admit_intent(AdmissionInput {
            intent: sample_intent("org-a", "intent-a", "idem-a", "12.50"),
            received_at: timestamp("2026-08-08T01:00:00Z"),
        })
        .await?;

    let input_a = FinalizationInput {
        organization_id: "org-a".into(),
        intent_id: "intent-a".into(),
        expected_intent_hash: admitted.intent_hash.clone(),
        expected_lifecycle_version: admitted.lifecycle.version,
        evaluation: evaluation_input("evaluation-a", "2026-08-08T01:00:01Z"),
        decision: sample_decision("decision-a", "intent-a"),
        decided_at: timestamp("2026-08-08T01:00:02Z"),
    };
    let input_b = FinalizationInput {
        organization_id: "org-a".into(),
        intent_id: "intent-a".into(),
        expected_intent_hash: admitted.intent_hash,
        expected_lifecycle_version: admitted.lifecycle.version,
        evaluation: evaluation_input("evaluation-b", "2026-08-08T01:00:01Z"),
        decision: sample_decision("decision-b", "intent-a"),
        decided_at: timestamp("2026-08-08T01:00:02Z"),
    };

    let store_a = store.clone();
    let store_b = store.clone();
    let (result_a, result_b) = tokio::join!(
        store_a.finalize_decision(input_a),
        store_b.finalize_decision(input_b)
    );

    let results = [result_a, result_b];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(StoreError::LifecycleConflict { .. })))
            .count(),
        1
    );
    let (evaluations, decisions): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM evaluations), (SELECT count(*) FROM decisions)",
    )
    .fetch_one(&database.pool)
    .await?;
    assert_eq!((evaluations, decisions), (1, 1));
    assert_eq!(store.load_verified_audit_chain("org-a").await?.len(), 6);

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn lifecycle_reader_rejects_materialized_state_that_disagrees_with_audit_replay(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("lifecycle_tamper").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    store
        .admit_intent(AdmissionInput {
            intent: sample_intent("org-a", "intent-a", "idem-a", "12.50"),
            received_at: timestamp("2026-08-08T01:00:00Z"),
        })
        .await?;

    sqlx::query(
        r#"
        UPDATE intents
        SET lifecycle_state = 'IDENTITY_UNVERIFIED', lifecycle_version = 2
        WHERE organization_id = 'org-a' AND intent_id = 'intent-a'
        "#,
    )
    .execute(&database.pool)
    .await?;

    let error = store
        .load_intent_lifecycle("org-a", "intent-a")
        .await
        .expect_err("materialized lifecycle drift must fail closed");
    assert!(matches!(error, StoreError::DurableStateCorrupt { .. }));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn generic_audit_append_cannot_create_lifecycle_evidence_without_state(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("lifecycle_append_boundary").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    store
        .admit_intent(AdmissionInput {
            intent: sample_intent("org-a", "intent-a", "idem-a", "12.50"),
            received_at: timestamp("2026-08-08T01:00:00Z"),
        })
        .await?;

    let event = NewAuditEvent::from_payload(
        timestamp("2026-08-08T01:00:01Z"),
        Some("intent-a".into()),
        AuditPayload::IntentCancelled(IntentCancelledPayload {
            actor_id: "operator-a".into(),
            reason_code: "TEST_CANCEL".into(),
        }),
    )?;
    let error = store
        .append_audit_event("org-a", event)
        .await
        .expect_err("generic append must not split lifecycle state from its evidence");
    assert!(matches!(error, StoreError::InvalidAuditEvent { .. }));
    assert_eq!(store.load_verified_audit_chain("org-a").await?.len(), 1);

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn typed_risk_failure_commits_a_decided_error_terminal_state() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("risk_error").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let admitted = store
        .admit_intent(AdmissionInput {
            intent: sample_intent("org-a", "intent-a", "idem-a", "12.50"),
            received_at: timestamp("2026-08-08T01:00:00Z"),
        })
        .await?;
    let mut evaluation = evaluation_input("evaluation-a", "2026-08-08T01:00:01Z");
    evaluation.risk.outcome = OptionalModuleOutcome::Error {
        error_code: "RISK_EVALUATION_ERROR".into(),
    };
    let mut decision = sample_decision("decision-a", "intent-a");
    decision.decision = DecisionKind::Error;

    let finalized = store
        .finalize_decision(FinalizationInput {
            organization_id: "org-a".into(),
            intent_id: "intent-a".into(),
            expected_intent_hash: admitted.intent_hash,
            expected_lifecycle_version: admitted.lifecycle.version,
            evaluation,
            decision,
            decided_at: timestamp("2026-08-08T01:00:02Z"),
        })
        .await?;

    assert_eq!(finalized.lifecycle.state, State::DecidedError);
    assert_eq!(
        finalized.evaluation.evidence["risk"]["outcome"]["error_code"],
        "RISK_EVALUATION_ERROR"
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}

fn evaluation_input(evaluation_id: &str, evaluated_at: &str) -> EvaluationInput {
    EvaluationInput {
        evaluation_id: evaluation_id.into(),
        evaluated_at: timestamp(evaluated_at),
        policy: PolicyEvaluatedPayload {
            outcome: RequiredModuleOutcome::Succeeded {
                result: PolicyOutcome::Permit,
            },
            policy_ids: vec!["policy-a".into()],
        },
        risk: RiskEvaluatedPayload {
            outcome: OptionalModuleOutcome::Succeeded { result: Vec::new() },
        },
        simulation: SimulationCompletedPayload {
            outcome: OptionalModuleOutcome::NotRun {
                reason_code: "SIMULATOR_NOT_IMPLEMENTED".into(),
            },
        },
    }
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
