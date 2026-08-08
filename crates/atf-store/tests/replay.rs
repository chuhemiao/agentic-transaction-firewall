use std::{
    env,
    error::Error,
    path::{Path, PathBuf},
    process,
    str::FromStr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use atf_audit::{
    AuditPayload, EventType, OptionalModuleOutcome, PolicyEvaluatedPayload,
    PolicyOutcome as AuditPolicyOutcome, RequiredModuleOutcome, RiskEvaluatedPayload,
    RiskFindingEvidence, RiskSeverity, SimulationCompletedPayload,
};
use atf_core::{
    sort_json_keys, Amount, EvaluationContext, EvaluationContextInput,
    EvidenceTrustPolicyReference, ExternalSnapshotReference, RepositorySnapshot,
    SimulationReference, Timestamp, VersionedArtifactReference,
};
use atf_decision::{decide, DecisionInput, PolicyDecisionInput, RiskDecisionInput};
use atf_identity::{AgentRecord, AgentStatus, IdentityEnvelope, IdentityKeyRecord};
use atf_intent::{Action, Mandate, Principal, Resource, Transaction, TransactionIntent};
use atf_policy::{
    policy_bundle_signature_message, PolicyBundle, PolicyBundleLoadContext, PolicyBundleSignature,
};
use atf_risk::{RiskEvaluation, RiskRuleSet, Severity};
use atf_store::{
    operator_subject_fingerprint, AuthenticatedAdmissionInput, CounterfactualReplayRequest,
    EvaluationContextPersistence, EvaluationInput, FinalizationInput, OperatorKind,
    OperatorRegistration, OperatorRole, OriginalReplayRequest, PolicyReplaySelection, ReplayError,
    RiskReplaySelection, Store,
};
use ed25519_dalek::{Signer, SigningKey};
use serde::Deserialize;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, Executor, PgConnection, PgPool,
};

const ORGANIZATION_ID: &str = "alpha-lab";
const ENVIRONMENT: &str = "development";
const AGENT_ID: &str = "research-agent-01";
const KEY_ID: &str = "identity-key-01";
const AUDIENCE: &str = "atf-gateway";
const OPERATOR_ID: &str = "replay-operator";

#[derive(Deserialize)]
struct ReplayConformance {
    schema_version: u32,
    fixture_id: String,
    expected_decision_relation: String,
    stable_errors: StableReplayErrors,
}

#[derive(Deserialize)]
struct StableReplayErrors {
    authorization_denied: String,
    missing_risk_artifact: String,
    tampered_context: String,
    tampered_risk_artifact: String,
}

#[derive(Deserialize)]
struct CounterfactualConformance {
    schema_version: u32,
    fixture_id: String,
    authoritative: bool,
    expected_lineage: String,
    expected_outcome_relation: String,
    stable_errors: CounterfactualStableErrors,
}

#[derive(Deserialize)]
struct CounterfactualStableErrors {
    authorization_denied: String,
    missing_selected_artifact: String,
    identity_conflict: String,
}

fn conformance() -> ReplayConformance {
    let fixture: ReplayConformance = serde_json::from_str(include_str!(
        "../../../conformance/replay-tests/original.json"
    ))
    .expect("Original Replay conformance fixture is valid JSON");
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.fixture_id, "ds026-original-replay-v1");
    assert_eq!(
        fixture.expected_decision_relation,
        "REPLAYED_EQUALS_ORIGINAL"
    );
    fixture
}

fn counterfactual_conformance() -> CounterfactualConformance {
    let fixture: CounterfactualConformance = serde_json::from_str(include_str!(
        "../../../conformance/replay-tests/counterfactual.json"
    ))
    .expect("Counterfactual Replay conformance fixture is valid JSON");
    assert_eq!(fixture.schema_version, 1);
    assert_eq!(fixture.fixture_id, "ds027-counterfactual-replay-v1");
    assert!(!fixture.authoritative);
    assert_eq!(fixture.expected_lineage, "LINKED_TO_ORIGINAL");
    assert_eq!(fixture.expected_outcome_relation, "CHANGED");
    fixture
}

#[tokio::test]
async fn counterfactual_replay_persists_new_lineage_without_overwriting_authority(
) -> Result<(), Box<dyn Error>> {
    let fixture = ReplayFixture::create("counterfactual", true).await?;
    let original = fixture.finalized.clone();
    let original_context = original
        .evaluation_context
        .as_ref()
        .expect("DS-025 fixture has a Context");
    let selected_policy = PolicyReplaySelection {
        bundle_id: original_context
            .policy()
            .available_parts()
            .expect("available Policy")
            .0
            .into(),
        policy_version: original_context
            .policy()
            .available_parts()
            .expect("available Policy")
            .1
            .into(),
        bundle_hash: original_context
            .policy()
            .available_parts()
            .expect("available Policy")
            .2
            .into(),
    };
    let selected_risk_rule_set = counterfactual_rule_set()?;
    fixture
        .store
        .install_risk_rule_set(
            ORGANIZATION_ID,
            ENVIRONMENT,
            &selected_risk_rule_set,
            OPERATOR_ID,
            at("2026-08-08T12:00:03Z"),
        )
        .await?;
    let selected_risk = RiskReplaySelection {
        engine_version: selected_risk_rule_set.engine_version().into(),
        rule_set_version: selected_risk_rule_set.version().into(),
        rule_set_hash: selected_risk_rule_set.rule_set_hash().into(),
    };
    let before_authority: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM evaluations), (SELECT count(*) FROM decisions)",
    )
    .fetch_one(&fixture.database.pool)
    .await?;
    fixture.store.close().await;
    let restarted = Store::connect(&fixture.database.url).await?;

    let result = restarted
        .replay_counterfactual(CounterfactualReplayRequest {
            replay_id: "01J0000000000000000000CF01".into(),
            organization_id: ORGANIZATION_ID.into(),
            intent_id: original.decision.intent_id.clone(),
            counterfactual_evaluation_id: "01J0000000000000000000CE01".into(),
            counterfactual_decision_id: "01J0000000000000000000CD01".into(),
            selected_policy: selected_policy.clone(),
            selected_risk: selected_risk.clone(),
            actor_id: OPERATOR_ID.into(),
            occurred_at: at("2026-08-08T12:00:04Z"),
        })
        .await?;

    let _ = counterfactual_conformance();
    assert!(!result.authoritative);
    assert!(result.outcome_changed);
    assert_eq!(
        result.original_evaluation_id,
        original.evaluation.evaluation_id
    );
    assert_eq!(result.original_decision_id, original.decision.decision_id);
    assert_eq!(result.original_decision_hash, original.decision_hash);
    assert_eq!(result.original_outcome, original.decision.decision);
    assert_eq!(
        result.evaluation.evaluation_id,
        "01J0000000000000000000CE01"
    );
    assert_eq!(result.decision.decision_id, "01J0000000000000000000CD01");
    assert_ne!(
        result.evaluation.evaluation_id,
        result.original_evaluation_id
    );
    assert_ne!(result.decision.decision_id, result.original_decision_id);
    assert_ne!(result.decision.decision, result.original_outcome);
    assert_eq!(result.selected_policy, selected_policy);
    assert_eq!(result.selected_risk, selected_risk);
    assert_eq!(result.decision.decision_hash, result.decision_hash);
    assert_eq!(
        result.audit_event.event.event_type,
        EventType::CounterfactualReplayCompleted
    );
    let AuditPayload::CounterfactualReplayCompleted(evidence) =
        result.audit_event.event.typed_payload()?
    else {
        panic!("Counterfactual Replay must append typed evidence");
    };
    assert!(!evidence.authoritative);
    assert!(evidence.outcome_changed);
    assert_eq!(evidence.original_decision_hash, original.decision_hash);
    assert_eq!(evidence.counterfactual_decision_hash, result.decision_hash);

    let after_authority: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM evaluations), (SELECT count(*) FROM decisions)",
    )
    .fetch_one(&fixture.database.pool)
    .await?;
    assert_eq!(after_authority, before_authority);
    let replay_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM counterfactual_replays")
        .fetch_one(&fixture.database.pool)
        .await?;
    assert_eq!(replay_rows, 1);

    let reloaded = restarted
        .load_counterfactual_replay(ORGANIZATION_ID, &result.replay_id)
        .await?
        .expect("Counterfactual Replay survives restart");
    assert_eq!(reloaded.evaluation, result.evaluation);
    assert_eq!(
        reloaded.decision.canonical_bytes(),
        result.decision.canonical_bytes()
    );
    assert_eq!(reloaded.audit_event, result.audit_event);
    let unchanged = restarted
        .load_finalized_decision(ORGANIZATION_ID, &original.decision.intent_id)
        .await?
        .expect("original Decision remains authoritative");
    assert_eq!(
        unchanged.decision.canonical_bytes(),
        original.decision.canonical_bytes()
    );

    let mut tampered_evaluation = serde_json::to_value(&result.evaluation)?;
    tampered_evaluation["policy_result"]["policy_ids"] =
        serde_json::json!(["counterfactual-evidence-was-rewritten"]);
    let tampered_evaluation = sort_json_keys(tampered_evaluation);
    let tampered_bytes = serde_json::to_vec(&tampered_evaluation)?;
    let tampered_hash = atf_core::sha256_hex(&tampered_bytes);
    sqlx::query(
        "ALTER TABLE counterfactual_replays DISABLE TRIGGER counterfactual_replays_protect_mutation",
    )
    .execute(&fixture.database.pool)
    .await?;
    sqlx::query(
        "UPDATE counterfactual_replays SET canonical_evaluation = $1, canonical_evaluation_bytes = $2, evaluation_hash = $3 WHERE organization_id = $4 AND replay_id = $5",
    )
    .bind(&tampered_evaluation)
    .bind(&tampered_bytes)
    .bind(&tampered_hash)
    .bind(ORGANIZATION_ID)
    .bind(&result.replay_id)
    .execute(&fixture.database.pool)
    .await?;
    sqlx::query(
        "ALTER TABLE counterfactual_replays ENABLE TRIGGER counterfactual_replays_protect_mutation",
    )
    .execute(&fixture.database.pool)
    .await?;
    let tampered = restarted
        .load_counterfactual_replay(ORGANIZATION_ID, &result.replay_id)
        .await
        .expect_err("Audit-bound Evaluation evidence cannot be rewritten consistently");
    assert!(matches!(tampered, ReplayError::InputTampered));

    restarted.close().await;
    fixture.database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn counterfactual_authorization_precedes_selected_artifact_discovery(
) -> Result<(), Box<dyn Error>> {
    let fixture = ReplayFixture::create("counterfactual_auth", true).await?;
    let original_context = fixture
        .finalized
        .evaluation_context
        .as_ref()
        .expect("DS-025 fixture has a Context");
    let (bundle_id, policy_version, _) = original_context
        .policy()
        .available_parts()
        .expect("available Policy");
    let error = fixture
        .store
        .replay_counterfactual(CounterfactualReplayRequest {
            replay_id: "01J0000000000000000000CF02".into(),
            organization_id: ORGANIZATION_ID.into(),
            intent_id: fixture.finalized.decision.intent_id.clone(),
            counterfactual_evaluation_id: "01J0000000000000000000CE02".into(),
            counterfactual_decision_id: "01J0000000000000000000CD02".into(),
            selected_policy: PolicyReplaySelection {
                bundle_id: bundle_id.into(),
                policy_version: policy_version.into(),
                bundle_hash: "f".repeat(64),
            },
            selected_risk: RiskReplaySelection {
                engine_version: "missing-engine".into(),
                rule_set_version: "missing-version".into(),
                rule_set_hash: "e".repeat(64),
            },
            actor_id: "unknown-operator".into(),
            occurred_at: at("2026-08-08T12:00:04Z"),
        })
        .await
        .expect_err("authorization must conceal selected artifact existence");

    assert_eq!(
        error.code(),
        counterfactual_conformance()
            .stable_errors
            .authorization_denied
    );
    assert!(matches!(error, ReplayError::AuthorizationDenied));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM counterfactual_replays")
        .fetch_one(&fixture.database.pool)
        .await?;
    assert_eq!(rows, 0);

    fixture.store.close().await;
    fixture.database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn counterfactual_missing_selected_artifact_fails_closed_with_stable_code(
) -> Result<(), Box<dyn Error>> {
    let fixture = ReplayFixture::create("counterfactual_missing", true).await?;
    let original_context = fixture
        .finalized
        .evaluation_context
        .as_ref()
        .expect("DS-025 fixture has a Context");
    let (bundle_id, policy_version, bundle_hash) = original_context
        .policy()
        .available_parts()
        .expect("available Policy");
    let error = fixture
        .store
        .replay_counterfactual(CounterfactualReplayRequest {
            replay_id: "01J0000000000000000000CF03".into(),
            organization_id: ORGANIZATION_ID.into(),
            intent_id: fixture.finalized.decision.intent_id.clone(),
            counterfactual_evaluation_id: "01J0000000000000000000CE03".into(),
            counterfactual_decision_id: "01J0000000000000000000CD03".into(),
            selected_policy: PolicyReplaySelection {
                bundle_id: bundle_id.into(),
                policy_version: policy_version.into(),
                bundle_hash: bundle_hash.into(),
            },
            selected_risk: RiskReplaySelection {
                engine_version: "atf-risk-engine-v1".into(),
                rule_set_version: "risk-rules-missing".into(),
                rule_set_hash: "e".repeat(64),
            },
            actor_id: OPERATOR_ID.into(),
            occurred_at: at("2026-08-08T12:00:04Z"),
        })
        .await
        .expect_err("a selected artifact must never fall back to a default");

    assert_eq!(
        error.code(),
        counterfactual_conformance()
            .stable_errors
            .missing_selected_artifact
    );
    assert!(matches!(error, ReplayError::SelectedArtifactMissing));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM counterfactual_replays")
        .fetch_one(&fixture.database.pool)
        .await?;
    assert_eq!(rows, 0);

    fixture.store.close().await;
    fixture.database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn counterfactual_identity_conflict_rolls_back_duplicate_evidence(
) -> Result<(), Box<dyn Error>> {
    let fixture = ReplayFixture::create("counterfactual_conflict", true).await?;
    let original_context = fixture
        .finalized
        .evaluation_context
        .as_ref()
        .expect("DS-025 fixture has a Context");
    let (bundle_id, policy_version, bundle_hash) = original_context
        .policy()
        .available_parts()
        .expect("available Policy");
    let selected_risk_rule_set = counterfactual_rule_set()?;
    fixture
        .store
        .install_risk_rule_set(
            ORGANIZATION_ID,
            ENVIRONMENT,
            &selected_risk_rule_set,
            OPERATOR_ID,
            at("2026-08-08T12:00:03Z"),
        )
        .await?;
    let request = CounterfactualReplayRequest {
        replay_id: "01J0000000000000000000CF04".into(),
        organization_id: ORGANIZATION_ID.into(),
        intent_id: fixture.finalized.decision.intent_id.clone(),
        counterfactual_evaluation_id: "01J0000000000000000000CE04".into(),
        counterfactual_decision_id: "01J0000000000000000000CD04".into(),
        selected_policy: PolicyReplaySelection {
            bundle_id: bundle_id.into(),
            policy_version: policy_version.into(),
            bundle_hash: bundle_hash.into(),
        },
        selected_risk: RiskReplaySelection {
            engine_version: selected_risk_rule_set.engine_version().into(),
            rule_set_version: selected_risk_rule_set.version().into(),
            rule_set_hash: selected_risk_rule_set.rule_set_hash().into(),
        },
        actor_id: OPERATOR_ID.into(),
        occurred_at: at("2026-08-08T12:00:04Z"),
    };
    fixture.store.replay_counterfactual(request.clone()).await?;
    let before_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE event_type = 'CounterfactualReplayCompleted'",
    )
    .fetch_one(&fixture.database.pool)
    .await?;

    let error = fixture
        .store
        .replay_counterfactual(request)
        .await
        .expect_err("immutable Replay identities cannot be reused");

    assert_eq!(
        error.code(),
        counterfactual_conformance().stable_errors.identity_conflict
    );
    assert!(matches!(error, ReplayError::CounterfactualConflict));
    let after_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE event_type = 'CounterfactualReplayCompleted'",
    )
    .fetch_one(&fixture.database.pool)
    .await?;
    assert_eq!(after_events, before_events);

    fixture.store.close().await;
    fixture.database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn original_replay_reproduces_hash_after_restart_without_overwriting_authority(
) -> Result<(), Box<dyn Error>> {
    let fixture = ReplayFixture::create("original", true).await?;
    let original = fixture.finalized.clone();
    fixture.store.close().await;
    let restarted = Store::connect(&fixture.database.url).await?;
    let before: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM evaluations), (SELECT count(*) FROM decisions)",
    )
    .fetch_one(&fixture.database.pool)
    .await?;

    let result = restarted
        .replay_original(OriginalReplayRequest {
            replay_id: "01J0000000000000000000RP01".into(),
            organization_id: ORGANIZATION_ID.into(),
            intent_id: original.decision.intent_id.clone(),
            actor_id: OPERATOR_ID.into(),
            occurred_at: at("2026-08-08T12:00:03Z"),
        })
        .await?;

    assert!(result.matched);
    let _ = conformance();
    assert_eq!(result.original_decision_hash, original.decision_hash);
    assert_eq!(result.replayed_decision_hash, original.decision_hash);
    assert_eq!(
        result.original_evaluation_id,
        original.evaluation.evaluation_id
    );
    assert_eq!(result.original_decision_id, original.decision.decision_id);
    assert_eq!(
        result.audit_event.event.event_type,
        EventType::OriginalReplayCompleted
    );
    assert_eq!(
        result.audit_event.evaluation_id.as_deref(),
        Some(original.evaluation.evaluation_id.as_str())
    );
    assert_eq!(
        result.audit_event.decision_id.as_deref(),
        Some(original.decision.decision_id.as_str())
    );
    let AuditPayload::OriginalReplayCompleted(evidence) =
        result.audit_event.event.typed_payload()?
    else {
        panic!("Original Replay must append typed evidence");
    };
    assert!(evidence.matched);
    assert!(!evidence.authoritative);
    assert_eq!(evidence.original_decision_hash, original.decision_hash);
    assert_eq!(evidence.replayed_decision_hash, original.decision_hash);

    let after: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM evaluations), (SELECT count(*) FROM decisions)",
    )
    .fetch_one(&fixture.database.pool)
    .await?;
    assert_eq!(
        after, before,
        "Original Replay must not create or replace authority"
    );
    let reloaded = restarted
        .load_finalized_decision(ORGANIZATION_ID, &original.decision.intent_id)
        .await?
        .expect("the authoritative Decision remains readable");
    assert_eq!(
        reloaded.decision.canonical_bytes(),
        original.decision.canonical_bytes()
    );

    restarted.close().await;
    fixture.database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn missing_exact_risk_artifact_fails_closed_with_a_stable_code() -> Result<(), Box<dyn Error>>
{
    let fixture = ReplayFixture::create("missing_risk", false).await?;
    let before_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE event_type = 'OriginalReplayCompleted'",
    )
    .fetch_one(&fixture.database.pool)
    .await?;

    let error = fixture
        .store
        .replay_original(OriginalReplayRequest {
            replay_id: "01J0000000000000000000RP02".into(),
            organization_id: ORGANIZATION_ID.into(),
            intent_id: fixture.finalized.decision.intent_id.clone(),
            actor_id: OPERATOR_ID.into(),
            occurred_at: at("2026-08-08T12:00:03Z"),
        })
        .await
        .expect_err("a current/default Rule Set must never substitute for a missing exact archive");

    assert_eq!(
        error.code(),
        conformance().stable_errors.missing_risk_artifact
    );
    assert!(matches!(error, ReplayError::RiskArtifactMissing));
    let after_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE event_type = 'OriginalReplayCompleted'",
    )
    .fetch_one(&fixture.database.pool)
    .await?;
    assert_eq!(after_events, before_events);

    fixture.store.close().await;
    fixture.database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn replay_authorization_is_checked_before_artifact_discovery() -> Result<(), Box<dyn Error>> {
    let fixture = ReplayFixture::create("unauthorized", false).await?;
    let error = fixture
        .store
        .replay_original(OriginalReplayRequest {
            replay_id: "01J0000000000000000000RP05".into(),
            organization_id: ORGANIZATION_ID.into(),
            intent_id: fixture.finalized.decision.intent_id.clone(),
            actor_id: "unknown-operator".into(),
            occurred_at: at("2026-08-08T12:00:03Z"),
        })
        .await
        .expect_err("an unbound actor must learn nothing about missing artifacts");

    assert_eq!(
        error.code(),
        conformance().stable_errors.authorization_denied
    );
    assert!(matches!(error, ReplayError::AuthorizationDenied));
    let replay_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE event_type = 'OriginalReplayCompleted'",
    )
    .fetch_one(&fixture.database.pool)
    .await?;
    assert_eq!(replay_events, 0);

    fixture.store.close().await;
    fixture.database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn tampered_context_snapshot_fails_closed_with_a_stable_code() -> Result<(), Box<dyn Error>> {
    let fixture = ReplayFixture::create("tampered_context", true).await?;
    sqlx::query(
        "ALTER TABLE evaluation_contexts DISABLE TRIGGER evaluation_contexts_protect_mutation",
    )
    .execute(&fixture.database.pool)
    .await?;
    sqlx::query(
        "UPDATE evaluation_contexts SET canonical_context_bytes = canonical_context_bytes || decode('00', 'hex') WHERE organization_id = $1",
    )
    .bind(ORGANIZATION_ID)
    .execute(&fixture.database.pool)
    .await?;
    sqlx::query(
        "ALTER TABLE evaluation_contexts ENABLE TRIGGER evaluation_contexts_protect_mutation",
    )
    .execute(&fixture.database.pool)
    .await?;

    let error = fixture
        .store
        .replay_original(OriginalReplayRequest {
            replay_id: "01J0000000000000000000RP03".into(),
            organization_id: ORGANIZATION_ID.into(),
            intent_id: fixture.finalized.decision.intent_id.clone(),
            actor_id: OPERATOR_ID.into(),
            occurred_at: at("2026-08-08T12:00:03Z"),
        })
        .await
        .expect_err("a modified immutable snapshot must stop replay");

    assert_eq!(error.code(), conformance().stable_errors.tampered_context);
    assert!(matches!(error, ReplayError::InputTampered));
    let replay_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE event_type = 'OriginalReplayCompleted'",
    )
    .fetch_one(&fixture.database.pool)
    .await?;
    assert_eq!(replay_events, 0);

    fixture.store.close().await;
    fixture.database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn tampered_risk_artifact_fails_closed_with_a_stable_code() -> Result<(), Box<dyn Error>> {
    let fixture = ReplayFixture::create("tampered_risk", true).await?;
    sqlx::query("ALTER TABLE risk_rule_sets DISABLE TRIGGER risk_rule_sets_protect_mutation")
        .execute(&fixture.database.pool)
        .await?;
    sqlx::query(
        "UPDATE risk_rule_sets SET canonical_rule_set_bytes = canonical_rule_set_bytes || decode('00', 'hex') WHERE organization_id = $1",
    )
    .bind(ORGANIZATION_ID)
    .execute(&fixture.database.pool)
    .await?;
    sqlx::query("ALTER TABLE risk_rule_sets ENABLE TRIGGER risk_rule_sets_protect_mutation")
        .execute(&fixture.database.pool)
        .await?;

    let error = fixture
        .store
        .replay_original(OriginalReplayRequest {
            replay_id: "01J0000000000000000000RP04".into(),
            organization_id: ORGANIZATION_ID.into(),
            intent_id: fixture.finalized.decision.intent_id.clone(),
            actor_id: OPERATOR_ID.into(),
            occurred_at: at("2026-08-08T12:00:03Z"),
        })
        .await
        .expect_err("modified Rule Set bytes must stop replay");

    assert_eq!(
        error.code(),
        conformance().stable_errors.tampered_risk_artifact
    );
    assert!(matches!(error, ReplayError::InputTampered));
    let replay_events: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE event_type = 'OriginalReplayCompleted'",
    )
    .fetch_one(&fixture.database.pool)
    .await?;
    assert_eq!(replay_events, 0);

    fixture.store.close().await;
    fixture.database.destroy().await?;
    Ok(())
}

struct ReplayFixture {
    database: TestDatabase,
    store: Store,
    finalized: atf_store::FinalizedDecision,
}

impl ReplayFixture {
    async fn create(label: &str, archive_risk: bool) -> Result<Self, Box<dyn Error>> {
        let database = TestDatabase::create(label).await?;
        let store = Store::connect(&database.url).await?;
        let agent_key = SigningKey::from_bytes(&[42; 32]);
        seed_authority(&store, &database.pool, &agent_key).await?;

        let policy = policy_bundle()?;
        let publisher_key = SigningKey::from_bytes(&[19; 32]);
        store
            .install_policy_bundle(
                &policy,
                &policy_proof(&policy, &publisher_key),
                &publisher_key.verifying_key().to_bytes(),
                OPERATOR_ID,
                at("2026-08-08T11:30:00Z"),
            )
            .await?;
        let risk = RiskRuleSet::default();
        if archive_risk {
            store
                .install_risk_rule_set(
                    ORGANIZATION_ID,
                    ENVIRONMENT,
                    &risk,
                    OPERATOR_ID,
                    at("2026-08-08T11:31:00Z"),
                )
                .await?;
        }

        let intent = intent();
        let admitted = store
            .authenticate_and_admit(signed_admission(intent.clone(), &agent_key))
            .await?;
        let history = store.load_verified_audit_chain(ORGANIZATION_ID).await?;
        let tail = history.last().expect("authority/admission created history");
        let context = EvaluationContext::new(EvaluationContextInput {
            evaluation_id: "01J0000000000000000000EV01".into(),
            intent_id: intent.intent_id.clone(),
            intent_hash: intent.canonical_hash(),
            evaluation_time: at("2026-08-08T12:00:01Z"),
            environment: ENVIRONMENT.into(),
            profile_id: "atf.agent-commerce.payment".into(),
            profile_version: "1.0".into(),
            policy: VersionedArtifactReference::available(
                policy.bundle_id(),
                policy.policy_version(),
                policy.bundle_hash(),
            )?,
            risk: VersionedArtifactReference::available(
                risk.engine_version(),
                risk.version(),
                risk.rule_set_hash(),
            )?,
            context_snapshot_id: "01J0000000000000000000SN01".into(),
            agent_context: intent.context.clone(),
            evidence: Vec::new(),
            evidence_trust_policy: EvidenceTrustPolicyReference::not_configured(
                "TRUST_POLICY_NOT_CONFIGURED",
            )?,
            history: RepositorySnapshot::new(
                format!("audit-chain:{ORGANIZATION_ID}:{}", tail.sequence),
                u64::try_from(tail.sequence)?,
                tail.event_hash.clone(),
            )?,
            market_data: ExternalSnapshotReference::unavailable(
                "MARKET_DATA_SNAPSHOT_UNAVAILABLE",
            )?,
            simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED")?,
        })?;
        store
            .persist_evaluation_context(EvaluationContextPersistence {
                organization_id: ORGANIZATION_ID.into(),
                expected_intent_hash: intent.canonical_hash(),
                evaluator_lease: admitted.evaluator_lease.clone(),
                context: context.clone(),
            })
            .await?;

        let policy_result = policy.evaluate(&intent, &context)?;
        let history_events = history.iter().map(|event| &event.event).collect::<Vec<_>>();
        let risk_result = atf_risk::evaluate_context(&intent, &risk, &context, history_events)?;
        let decision = decide(DecisionInput {
            decision_id: "01J0000000000000000000DE01".into(),
            intent: &intent,
            evaluation_context: &context,
            policy: PolicyDecisionInput::Evaluated(&policy_result),
            risk: RiskDecisionInput::Evaluated(&risk_result),
        })?;
        let finalized = store
            .finalize_decision(FinalizationInput {
                organization_id: ORGANIZATION_ID.into(),
                intent_id: intent.intent_id.clone(),
                expected_intent_hash: intent.canonical_hash(),
                expected_lifecycle_version: admitted.admitted.lifecycle.version,
                evaluator_lease: admitted.evaluator_lease,
                evaluation: evaluation_input(&context, &policy_result, &risk_result),
                decision,
                decided_at: at("2026-08-08T12:00:02Z"),
            })
            .await?;

        Ok(Self {
            database,
            store,
            finalized,
        })
    }
}

async fn seed_authority(
    store: &Store,
    pool: &PgPool,
    agent_key: &SigningKey,
) -> Result<(), Box<dyn Error>> {
    sqlx::query("INSERT INTO organizations (organization_id) VALUES ($1)")
        .bind(ORGANIZATION_ID)
        .execute(pool)
        .await?;
    store
        .provision_operator(
            OperatorRegistration {
                operator_id: OPERATOR_ID.into(),
                issuer_id: "test-idp".into(),
                subject_fingerprint: operator_subject_fingerprint(
                    "https://issuer.example.test",
                    "replay-subject",
                )?,
                principal_kind: OperatorKind::Human,
                audit_organization_id: ORGANIZATION_ID.into(),
                created_at: at("2026-08-08T08:00:00Z"),
            },
            "db-admin",
            at("2026-08-08T08:01:00Z"),
        )
        .await?;
    store
        .grant_operator_role(
            OPERATOR_ID,
            ORGANIZATION_ID,
            OperatorRole::OrgAdmin,
            "db-admin",
            "REPLAY_TEST_AUTHORITY",
            at("2026-08-08T08:02:00Z"),
        )
        .await?;
    store
        .provision_agent(agent_record(), "db-admin", at("2026-08-08T09:00:00Z"))
        .await?;
    store
        .register_identity_key(
            ORGANIZATION_ID,
            IdentityKeyRecord::from_public_key_bytes(
                AGENT_ID.into(),
                KEY_ID.into(),
                agent_key.verifying_key().as_bytes(),
                at("2026-08-08T09:01:00Z"),
                Some(at("2026-08-09T00:00:00Z")),
                None,
            )?,
            "db-admin",
            at("2026-08-08T09:02:00Z"),
        )
        .await?;
    Ok(())
}

fn policy_bundle() -> Result<PolicyBundle, Box<dyn Error>> {
    Ok(PolicyBundle::from_dir(
        &policy_fixture_dir(),
        &PolicyBundleLoadContext {
            organization_id: ORGANIZATION_ID.into(),
            environment: ENVIRONMENT.into(),
            evaluated_at: at("2026-08-08T12:00:01Z"),
        },
    )?)
}

fn policy_fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies/examples")
}

fn policy_proof(bundle: &PolicyBundle, key: &SigningKey) -> PolicyBundleSignature {
    let message = policy_bundle_signature_message("publisher-2026", bundle.bundle_hash()).unwrap();
    PolicyBundleSignature::from_parts(
        "publisher-2026".into(),
        bundle.bundle_hash().into(),
        key.sign(&message).to_bytes(),
    )
    .unwrap()
}

fn counterfactual_rule_set() -> Result<RiskRuleSet, Box<dyn Error>> {
    let mut document: serde_json::Value =
        serde_json::from_str(include_str!("../../../risk-rules/default.json"))?;
    document["rule_set_version"] = serde_json::json!("risk-rules-2.0.0");
    document["rules"]["single_amount_cap"]["enabled"] = serde_json::json!(true);
    document["rules"]["single_amount_cap"]["severity"] = serde_json::json!("critical");
    document["rules"]["single_amount_cap"]["max_amount"] = serde_json::json!("10.00");
    Ok(RiskRuleSet::from_json(&document.to_string())?)
}

fn intent() -> TransactionIntent {
    TransactionIntent {
        spec_version: "1.0".into(),
        intent_id: "01J0000000000000000000IN01".into(),
        idempotency_key: "idem-replay-original".into(),
        created_at: at("2026-08-08T11:55:00Z"),
        expires_at: at("2026-08-08T12:05:00Z"),
        principal: Principal {
            organization_id: ORGANIZATION_ID.into(),
            user_id: Some("user-1".into()),
            agent_id: AGENT_ID.into(),
            agent_version: Some("1.0.0".into()),
            strategy_id: None,
        },
        mandate: Mandate {
            mandate_id: "mandate-1".into(),
            task_id: Some("task-1".into()),
            purpose: "Original Replay test".into(),
            budget_id: Some("budget-1".into()),
            human_authorized: true,
        },
        action: Action {
            category: "payment".into(),
            operation: "purchase_api_resource".into(),
        },
        resource: Resource {
            protocol: "x402".into(),
            venue: Some("vendor-1".into()),
            resource_id: "dataset-1".into(),
            resource_type: Some("dataset".into()),
        },
        transaction: Transaction {
            network: "eip155:8453".into(),
            asset: "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".into(),
            amount: Amount::from_str("12.50").unwrap(),
            destination: Some("eip155:8453:0x1111111111111111111111111111111111111111".into()),
            contract: None,
            calldata_hash: None,
            max_fee: Some(Amount::from_str("0.10").unwrap()),
            slippage_bps: None,
            leverage: None,
        },
        context: serde_json::json!({}),
        metadata: serde_json::json!({}),
    }
}

fn agent_record() -> AgentRecord {
    AgentRecord {
        agent_id: AGENT_ID.into(),
        organization_id: ORGANIZATION_ID.into(),
        owner_user_id: "owner-1".into(),
        agent_type: "research".into(),
        model_provider: "test".into(),
        model_name: "deterministic".into(),
        agent_version: "1.0.0".into(),
        code_hash: "a".repeat(64),
        deployment_environment: ENVIRONMENT.into(),
        allowed_tools: vec!["market-data".into()],
        allowed_adapters: vec!["x402".into()],
        default_budget: Some(Amount::from_str("20.00").unwrap()),
        risk_tier: "standard".into(),
        status: AgentStatus::Active,
        created_at: at("2026-08-08T08:30:00Z"),
        expires_at: Some(at("2026-08-09T00:00:00Z")),
    }
}

fn signed_admission(intent: TransactionIntent, key: &SigningKey) -> AuthenticatedAdmissionInput {
    let envelope = IdentityEnvelope {
        domain: "ATF_INTENT_V1".into(),
        organization_id: ORGANIZATION_ID.into(),
        agent_id: AGENT_ID.into(),
        key_id: KEY_ID.into(),
        intent_hash: intent.canonical_hash(),
        issued_at: at("2026-08-08T11:59:00Z"),
        expires_at: at("2026-08-08T12:04:00Z"),
        nonce: "nonce-replay-test-0001".into(),
        audience: AUDIENCE.into(),
        environment: ENVIRONMENT.into(),
    };
    AuthenticatedAdmissionInput {
        signature: key.sign(&envelope.canonical_bytes()).to_bytes(),
        intent,
        envelope,
        audience: AUDIENCE.into(),
        environment: ENVIRONMENT.into(),
        received_at: at("2026-08-08T12:00:00Z"),
        lease_duration: Duration::from_secs(60),
    }
}

fn evaluation_input(
    context: &EvaluationContext,
    policy: &atf_policy::PolicyOutcome,
    risk: &RiskEvaluation,
) -> EvaluationInput {
    EvaluationInput {
        evaluation_id: context.evaluation_id().into(),
        evaluation_context_hash: context.evaluation_context_hash().into(),
        evaluated_at: context.evaluation_time(),
        policy: PolicyEvaluatedPayload {
            outcome: RequiredModuleOutcome::Succeeded {
                result: match policy.decision {
                    atf_policy::PolicyDecision::Permit => AuditPolicyOutcome::Permit,
                    atf_policy::PolicyDecision::Forbid => AuditPolicyOutcome::Forbid,
                },
            },
            policy_ids: policy.policy_ids.clone(),
        },
        risk: RiskEvaluatedPayload {
            risk_rule_set_version: Some(risk.rule_set_version.clone()),
            risk_rule_set_hash: Some(risk.rule_set_hash.clone()),
            outcome: OptionalModuleOutcome::Succeeded {
                result: risk
                    .findings
                    .iter()
                    .map(|finding| RiskFindingEvidence {
                        code: finding.code.clone(),
                        severity: match finding.severity {
                            Severity::Info => RiskSeverity::Info,
                            Severity::Medium => RiskSeverity::Medium,
                            Severity::High => RiskSeverity::High,
                            Severity::Critical => RiskSeverity::Critical,
                        },
                    })
                    .collect(),
            },
        },
        simulation: SimulationCompletedPayload {
            outcome: OptionalModuleOutcome::NotRun {
                reason_code: "SIMULATOR_NOT_IMPLEMENTED".into(),
            },
        },
    }
}

fn at(value: &str) -> Timestamp {
    Timestamp::from_str(value).unwrap()
}

struct TestDatabase {
    admin: PgConnection,
    pool: PgPool,
    name: String,
    url: String,
}

impl TestDatabase {
    async fn create(label: &str) -> Result<Self, Box<dyn Error>> {
        let admin_url = env::var("ATF_TEST_DATABASE_URL")
            .expect("ATF_TEST_DATABASE_URL must allow create/drop database");
        let admin_options = PgConnectOptions::from_str(&admin_url)?;
        let name = format!("atf_ds026_{label}_{}", unique_suffix());
        let quoted_name = quote_identifier(&name);
        let mut admin = PgConnection::connect_with(&admin_options).await?;
        admin
            .execute(format!("CREATE DATABASE {quoted_name}").as_str())
            .await?;
        let options = admin_options.database(&name);
        let url = options.to_url_lossy().to_string();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(options)
            .await?;
        atf_store::migrate_pool(&pool).await?;
        Ok(Self {
            admin,
            pool,
            name,
            url,
        })
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
        .expect("clock after epoch")
        .as_nanos();
    format!("{}_{nanos}", process::id())
}

fn quote_identifier(identifier: &str) -> String {
    assert!(identifier
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || character == '_'));
    format!("\"{identifier}\"")
}
