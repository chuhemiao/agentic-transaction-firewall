use atf_audit::{
    AuditPayload, EventType, IntentCancelledPayload, NewAuditEvent, OptionalModuleOutcome,
    PolicyEvaluatedPayload, PolicyOutcome, RequiredModuleOutcome, RiskEvaluatedPayload,
    SimulationCompletedPayload,
};
use atf_core::{
    Amount, EvaluationContext, EvaluationContextInput, EvidenceTrustPolicyReference,
    ExternalSnapshotReference, IntentLifecycleState as State, RepositorySnapshot,
    SimulationReference, Timestamp, VersionedArtifactReference,
};
use atf_decision::{Decision, DecisionKind, Reason};
use atf_identity::{AgentRecord, AgentStatus, IdentityEnvelope, IdentityKeyRecord};
use atf_intent::{Action, Mandate, Principal, Resource, Transaction, TransactionIntent};
use atf_store::{
    AdmissionGrant, AuthenticatedAdmissionInput, EvaluationContextPersistence, EvaluationInput,
    FinalizationInput, IdempotencyState, Store, StoreError, StoredAuditEvent, StoredEvaluation,
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
    time::{Duration, SystemTime, UNIX_EPOCH},
};

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
async fn admission_is_atomic_and_never_overwrites_canonical_intent() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("admission").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let intent = sample_intent("org-a", "intent-a", "idem-a", "12.50");

    let admitted = store
        .admit_intent(AdmissionInput {
            intent: intent.clone(),
            received_at: timestamp("2026-08-08T01:00:00.123456Z"),
            lease_duration: Duration::from_secs(30),
        })
        .await?;

    assert_eq!(admitted.admitted.intent, intent);
    assert_eq!(admitted.admitted.intent_hash, intent.canonical_hash());
    assert_eq!(
        admitted.admitted.received_at.to_string(),
        "2026-08-08T01:00:00.123Z"
    );
    assert_eq!(admitted.admitted.lifecycle.state, State::IdentityVerified);
    assert_eq!(admitted.admitted.lifecycle.version, 2);
    assert_eq!(admitted.admitted.lifecycle.contract_version, 1);
    assert_ne!(
        admitted.admitted.lifecycle.last_event_id.as_deref(),
        Some(admitted.admitted.audit_event.event.event_id.as_str())
    );
    assert_eq!(
        admitted.admitted.audit_event.event.event_type,
        atf_audit::EventType::IntentReceived
    );
    assert_eq!(
        admitted.admitted.audit_event.event.intent_id.as_deref(),
        Some("intent-a")
    );
    assert!(matches!(
        admitted.admitted.audit_event.event.typed_payload()?,
        atf_audit::AuditPayload::IntentReceived(_)
    ));

    let mut conflicting = intent.clone();
    conflicting.transaction.amount = Amount::from_str("99.00")?;
    let error = store
        .admit_intent(AdmissionInput {
            intent: conflicting,
            received_at: timestamp("2026-08-08T01:00:01Z"),
            lease_duration: Duration::from_secs(30),
        })
        .await
        .expect_err("an immutable Intent must not be overwritten");
    assert!(matches!(error, StoreError::IdempotencyConflict { .. }));

    let reloaded = store
        .load_admitted_intent("org-a", "intent-a")
        .await?
        .expect("the original admission remains queryable");
    assert_eq!(reloaded.intent, intent);
    assert_eq!(reloaded.intent_hash, intent.canonical_hash());
    assert_eq!(
        request_events(store.load_verified_audit_chain("org-a").await?).len(),
        2
    );

    let reused_key = sample_intent("org-a", "intent-b", "idem-a", "7.00");
    let error = store
        .admit_intent(AdmissionInput {
            intent: reused_key,
            received_at: timestamp("2026-08-08T01:00:02Z"),
            lease_duration: Duration::from_secs(30),
        })
        .await
        .expect_err("one idempotency key must never bind to a second Intent");
    assert!(matches!(error, StoreError::IdempotencyConflict { .. }));

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
            lease_duration: Duration::from_secs(30),
        })
        .await
        .expect_err("the injected Audit insert failure must abort admission");
    assert!(matches!(error, StoreError::Database(_)));

    let (reservations, intents, events, heads): (i64, i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM idempotency_reservations), (SELECT count(*) FROM intents), (SELECT count(*) FROM audit_events), (SELECT count(*) FROM audit_chain_heads)",
    )
    .fetch_one(&database.pool)
    .await?;
    assert_eq!((reservations, intents, events, heads), (0, 0, 2, 1));
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
            lease_duration: Duration::from_secs(30),
        })
        .await?;
    let decision = sample_decision("decision-a", "intent-a");
    let context_hash =
        persist_test_context(&store, &admitted, "evaluation-a", "2026-08-08T01:00:01Z").await?;

    let finalized = store
        .finalize_decision(FinalizationInput {
            organization_id: "org-a".into(),
            intent_id: "intent-a".into(),
            evaluator_lease: admitted.evaluator_lease.clone(),
            expected_intent_hash: admitted.admitted.intent_hash.clone(),
            expected_lifecycle_version: admitted.admitted.lifecycle.version,
            evaluation: evaluation_input("evaluation-a", "2026-08-08T01:00:01Z", &context_hash),
            decision: decision.clone(),
            decided_at: timestamp("2026-08-08T01:00:02Z"),
        })
        .await?;

    assert_eq!(finalized.decision, decision);
    assert_eq!(
        finalized.evaluation.intent_hash,
        admitted.admitted.intent_hash
    );
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

    let chain = request_events(store.load_verified_audit_chain("org-a").await?);
    assert_eq!(chain.len(), 7);
    assert_eq!(
        chain
            .iter()
            .map(|stored| stored.event.event_type)
            .collect::<Vec<_>>(),
        vec![
            EventType::IntentReceived,
            EventType::IdentityVerified,
            EventType::ContextEnriched,
            EventType::PolicyEvaluated,
            EventType::RiskEvaluated,
            EventType::SimulationCompleted,
            EventType::DecisionRecorded,
        ]
    );
    assert_eq!(chain[6].evaluation_id.as_deref(), Some("evaluation-a"));
    assert_eq!(chain[6].decision_id.as_deref(), Some("decision-a"));
    assert!(matches!(
        chain[6].event.typed_payload()?,
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
            lease_duration: Duration::from_secs(30),
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
    let context_hash =
        persist_test_context(&store, &admitted, "evaluation-a", "2026-08-08T01:00:01Z").await?;

    let error = store
        .finalize_decision(FinalizationInput {
            organization_id: "org-a".into(),
            intent_id: "intent-a".into(),
            evaluator_lease: admitted.evaluator_lease.clone(),
            expected_intent_hash: admitted.admitted.intent_hash.clone(),
            expected_lifecycle_version: admitted.admitted.lifecycle.version,
            evaluation: evaluation_input("evaluation-a", "2026-08-08T01:00:01Z", &context_hash),
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
    let reservation = store
        .load_idempotency_reservation("org-a", "idem-a")
        .await?
        .expect("the admission reservation remains after rollback");
    assert_eq!(reservation.state, IdempotencyState::InProgress);
    assert!(reservation.result.is_none());
    assert!(store
        .load_finalized_decision("org-a", "intent-a")
        .await?
        .is_none());

    let chain = request_events(store.load_verified_audit_chain("org-a").await?);
    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0].event.event_type, EventType::IntentReceived);
    assert_eq!(chain[1].event.event_type, EventType::IdentityVerified);
    assert_eq!(chain[2].event.event_type, EventType::ContextEnriched);
    assert_eq!(
        store
            .load_intent_lifecycle("org-a", "intent-a")
            .await?
            .expect("the admitted lifecycle remains")
            .state,
        State::IdentityVerified
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
            lease_duration: Duration::from_secs(30),
        })
        .await?;

    let error = store
        .finalize_decision(FinalizationInput {
            organization_id: "org-a".into(),
            intent_id: "intent-a".into(),
            evaluator_lease: admitted.evaluator_lease.clone(),
            expected_intent_hash: "f".repeat(64),
            expected_lifecycle_version: admitted.admitted.lifecycle.version,
            evaluation: evaluation_input("evaluation-a", "2026-08-08T01:00:01Z", &"e".repeat(64)),
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
            lease_duration: Duration::from_secs(30),
        })
        .await?;

    let error = store
        .finalize_decision(FinalizationInput {
            organization_id: "org-a".into(),
            intent_id: "intent-a".into(),
            evaluator_lease: admitted.evaluator_lease.clone(),
            expected_intent_hash: admitted.admitted.intent_hash.clone(),
            expected_lifecycle_version: admitted.admitted.lifecycle.version,
            evaluation: evaluation_input("evaluation-a", "2026-08-08T01:00:02Z", &"e".repeat(64)),
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
    assert_eq!(
        request_events(store.load_verified_audit_chain("org-a").await?).len(),
        2
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn finalization_rejects_succeeded_risk_when_context_marks_it_unavailable(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("unavailable_risk").await?;
    database.seed_organization("org-a").await?;
    let store = Store::connect(&database.url).await?;
    let admitted = store
        .admit_intent(AdmissionInput {
            intent: sample_intent("org-a", "intent-a", "idem-a", "12.50"),
            received_at: timestamp("2026-08-08T01:00:00Z"),
            lease_duration: Duration::from_secs(30),
        })
        .await?;
    let context_hash = persist_test_context_with_risk(
        &store,
        &admitted,
        "evaluation-a",
        "2026-08-08T01:00:01Z",
        VersionedArtifactReference::unavailable("RISK_ARTIFACT_UNAVAILABLE")?,
    )
    .await?;
    let mut evaluation = evaluation_input("evaluation-a", "2026-08-08T01:00:01Z", &context_hash);
    evaluation.risk.risk_rule_set_version = None;
    evaluation.risk.risk_rule_set_hash = None;

    let error = store
        .finalize_decision(FinalizationInput {
            organization_id: "org-a".into(),
            intent_id: "intent-a".into(),
            evaluator_lease: admitted.evaluator_lease,
            expected_intent_hash: admitted.admitted.intent_hash,
            expected_lifecycle_version: admitted.admitted.lifecycle.version,
            evaluation,
            decision: sample_decision("decision-a", "intent-a"),
            decided_at: timestamp("2026-08-08T01:00:02Z"),
        })
        .await
        .expect_err("an unavailable Risk artifact cannot produce a successful result");
    assert!(matches!(error, StoreError::InvalidRepositoryInput { .. }));

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
            lease_duration: Duration::from_secs(30),
        })
        .await?;

    let evaluated_at = timestamp("2026-08-08T01:00:01Z");
    let evaluation = StoredEvaluation {
        schema_version: 1,
        evaluation_id: "evaluation-a".into(),
        intent_id: "intent-a".into(),
        intent_hash: admitted.admitted.intent_hash.clone(),
        evaluation_context_hash: None,
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
            lease_duration: Duration::from_secs(30),
        })
        .await?;
    let context_hash =
        persist_test_context(&store, &admitted, "evaluation-a", "2026-08-08T01:00:01Z").await?;

    let input_a = FinalizationInput {
        organization_id: "org-a".into(),
        intent_id: "intent-a".into(),
        evaluator_lease: admitted.evaluator_lease.clone(),
        expected_intent_hash: admitted.admitted.intent_hash.clone(),
        expected_lifecycle_version: admitted.admitted.lifecycle.version,
        evaluation: evaluation_input("evaluation-a", "2026-08-08T01:00:01Z", &context_hash),
        decision: sample_decision("decision-a", "intent-a"),
        decided_at: timestamp("2026-08-08T01:00:02Z"),
    };
    let input_b = FinalizationInput {
        organization_id: "org-a".into(),
        intent_id: "intent-a".into(),
        evaluator_lease: admitted.evaluator_lease.clone(),
        expected_intent_hash: admitted.admitted.intent_hash.clone(),
        expected_lifecycle_version: admitted.admitted.lifecycle.version,
        evaluation: evaluation_input("evaluation-a", "2026-08-08T01:00:01Z", &context_hash),
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
            .filter(|result| matches!(result, Err(StoreError::EvaluatorLeaseLost { .. })))
            .count(),
        1
    );
    let (evaluations, decisions): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM evaluations), (SELECT count(*) FROM decisions)",
    )
    .fetch_one(&database.pool)
    .await?;
    assert_eq!((evaluations, decisions), (1, 1));
    assert_eq!(
        request_events(store.load_verified_audit_chain("org-a").await?).len(),
        7
    );

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
            lease_duration: Duration::from_secs(30),
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
            lease_duration: Duration::from_secs(30),
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
    assert_eq!(
        request_events(store.load_verified_audit_chain("org-a").await?).len(),
        2
    );

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
            lease_duration: Duration::from_secs(30),
        })
        .await?;
    let context_hash =
        persist_test_context(&store, &admitted, "evaluation-a", "2026-08-08T01:00:01Z").await?;
    let mut evaluation = evaluation_input("evaluation-a", "2026-08-08T01:00:01Z", &context_hash);
    evaluation.risk.outcome = OptionalModuleOutcome::Error {
        error_code: "RISK_EVALUATION_ERROR".into(),
    };
    let mut decision = sample_decision("decision-a", "intent-a");
    decision.decision = DecisionKind::Error;

    let finalized = store
        .finalize_decision(FinalizationInput {
            organization_id: "org-a".into(),
            intent_id: "intent-a".into(),
            evaluator_lease: admitted.evaluator_lease.clone(),
            expected_intent_hash: admitted.admitted.intent_hash.clone(),
            expected_lifecycle_version: admitted.admitted.lifecycle.version,
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

async fn persist_test_context(
    store: &Store,
    admitted: &AdmissionGrant,
    evaluation_id: &str,
    evaluated_at: &str,
) -> Result<String, StoreError> {
    let risk =
        VersionedArtifactReference::available("atf-risk-engine-v1", "risk-test-1", "c".repeat(64))?;
    persist_test_context_with_risk(store, admitted, evaluation_id, evaluated_at, risk).await
}

async fn persist_test_context_with_risk(
    store: &Store,
    admitted: &AdmissionGrant,
    evaluation_id: &str,
    evaluated_at: &str,
    risk: VersionedArtifactReference,
) -> Result<String, StoreError> {
    let chain = store
        .load_verified_audit_chain(&admitted.admitted.organization_id)
        .await?;
    let tail = chain
        .last()
        .ok_or_else(|| StoreError::IncompleteAdmissionEvidence {
            organization_id: admitted.admitted.organization_id.clone(),
            intent_id: admitted.admitted.intent.intent_id.clone(),
        })?;
    let through_sequence =
        u64::try_from(tail.sequence).map_err(|_| StoreError::InvalidRepositoryInput {
            reason: "test Audit sequence is out of range".into(),
        })?;
    let context = EvaluationContext::new(EvaluationContextInput {
        evaluation_id: evaluation_id.into(),
        intent_id: admitted.admitted.intent.intent_id.clone(),
        intent_hash: admitted.admitted.intent_hash.clone(),
        evaluation_time: timestamp(evaluated_at),
        environment: TEST_ENVIRONMENT.into(),
        profile_id: "atf.agent-commerce.payment".into(),
        profile_version: "1.0".into(),
        policy: VersionedArtifactReference::available("policy-a", "1.0.0", "b".repeat(64))?,
        risk,
        context_snapshot_id: format!("snapshot-{evaluation_id}"),
        agent_context: admitted.admitted.intent.context.clone(),
        evidence: Vec::new(),
        evidence_trust_policy: EvidenceTrustPolicyReference::not_configured(
            "TRUST_POLICY_NOT_CONFIGURED",
        )?,
        history: RepositorySnapshot::new(
            format!(
                "audit-chain:{}:{through_sequence}",
                admitted.admitted.organization_id
            ),
            through_sequence,
            tail.event_hash.clone(),
        )?,
        market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_SNAPSHOT_UNAVAILABLE")?,
        simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED")?,
    })?;
    let context_hash = context.evaluation_context_hash().to_owned();
    store
        .persist_evaluation_context(EvaluationContextPersistence {
            organization_id: admitted.admitted.organization_id.clone(),
            expected_intent_hash: admitted.admitted.intent_hash.clone(),
            evaluator_lease: admitted.evaluator_lease.clone(),
            context,
        })
        .await?;
    Ok(context_hash)
}

fn evaluation_input(
    evaluation_id: &str,
    evaluated_at: &str,
    evaluation_context_hash: &str,
) -> EvaluationInput {
    EvaluationInput {
        evaluation_id: evaluation_id.into(),
        evaluation_context_hash: evaluation_context_hash.into(),
        evaluated_at: timestamp(evaluated_at),
        policy: PolicyEvaluatedPayload {
            outcome: RequiredModuleOutcome::Succeeded {
                result: PolicyOutcome::Permit,
            },
            policy_ids: vec!["policy-a".into()],
        },
        risk: RiskEvaluatedPayload {
            risk_rule_set_version: Some("risk-test-1".into()),
            risk_rule_set_hash: Some("c".repeat(64)),
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

fn request_events(chain: Vec<StoredAuditEvent>) -> Vec<StoredAuditEvent> {
    chain
        .into_iter()
        .filter(|stored| stored.event.intent_id.is_some())
        .collect()
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
