use crate::audit::{load_verified_in_transaction, AuditReferences, StoredAuditEvent};
use crate::evaluation::load_verified_context_in_transaction;
use crate::idempotency::{
    complete_in_transaction as complete_idempotency, verify_admission_binding,
    verify_completed_binding, verify_lease_for_finalization,
};
use crate::lifecycle::{
    append_event as append_lifecycle_event, state_from_str as lifecycle_state_from_str,
    validate_finalization_input, verify_replay as verify_lifecycle_replay,
    CONTRACT_VERSION as LIFECYCLE_CONTRACT_VERSION,
};
use crate::models::{
    AdmittedIntent, FinalizationInput, FinalizedDecision, StoredEvaluation, StoredLifecycle,
};
use crate::{Store, StoreError};
use atf_audit::{
    AuditPayload, DecisionBindingEvidence, DecisionRecordedPayload, EventType,
    OptionalModuleOutcome,
};
use atf_core::{sort_json_keys, EvaluationContext, Timestamp};
use atf_decision::Decision;
use atf_intent::TransactionIntent;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};

const EVALUATION_SCHEMA_VERSION: u32 = 2;
const LEGACY_EVALUATION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, FromRow)]
pub(crate) struct IntentRow {
    organization_id: String,
    intent_id: String,
    idempotency_key: String,
    spec_version: String,
    canonical_intent: Value,
    canonical_intent_bytes: Vec<u8>,
    intent_hash: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    received_at: DateTime<Utc>,
    lifecycle_state: String,
    lifecycle_version: i64,
    lifecycle_contract_version: i32,
    lifecycle_event_id: Option<String>,
    lifecycle_updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct FinalizationRow {
    evaluation_id: String,
    evaluation_intent_id: String,
    canonical_evaluation: Value,
    canonical_evaluation_bytes: Vec<u8>,
    evaluation_hash: String,
    evaluation_context_hash: Option<String>,
    evaluated_at: DateTime<Utc>,
    decision_id: String,
    decision_intent_id: String,
    decision_evaluation_id: String,
    canonical_decision: Value,
    canonical_decision_bytes: Vec<u8>,
    decision_hash: String,
    decided_at: DateTime<Utc>,
}

pub(crate) struct VerifiedIntent {
    pub(crate) intent: TransactionIntent,
    pub(crate) intent_hash: String,
    pub(crate) received_at: Timestamp,
    pub(crate) lifecycle: StoredLifecycle,
}

impl Store {
    /// Load an Intent only after verifying its immutable canonical bytes/hash
    /// and the organization's complete Audit chain contains exactly one
    /// matching `IntentReceived` event.
    pub async fn load_admitted_intent(
        &self,
        organization_id: &str,
        intent_id: &str,
    ) -> Result<Option<AdmittedIntent>, StoreError> {
        let mut transaction = self.pool.begin().await?;
        set_read_snapshot(&mut transaction).await?;

        let Some(row) =
            load_intent_row(&mut transaction, organization_id, intent_id, false).await?
        else {
            transaction.commit().await?;
            return Ok(None);
        };
        let verified = verify_intent_row(organization_id, row)?;
        verify_admission_binding(
            &mut transaction,
            organization_id,
            intent_id,
            &verified.intent_hash,
        )
        .await?;
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        verify_lifecycle_replay(
            organization_id,
            &verified.intent,
            &verified.lifecycle,
            &chain,
        )?;
        let audit_event = exactly_one_admission_event(
            chain.clone(),
            organization_id,
            intent_id,
            &verified.intent_hash,
            verified.received_at,
        )?;
        let identity = crate::nonce::load_initial_identity_evidence(
            &mut transaction,
            organization_id,
            intent_id,
            &verified.intent_hash,
            &chain,
        )
        .await?;

        transaction.commit().await?;
        Ok(Some(AdmittedIntent {
            organization_id: organization_id.to_owned(),
            intent: verified.intent,
            intent_hash: verified.intent_hash,
            received_at: verified.received_at,
            lifecycle: verified.lifecycle,
            audit_event,
            identity,
        }))
    }

    /// Load a materialized lifecycle only after replaying all typed state
    /// evidence for contract-version-1 Intents in the same snapshot.
    pub async fn load_intent_lifecycle(
        &self,
        organization_id: &str,
        intent_id: &str,
    ) -> Result<Option<StoredLifecycle>, StoreError> {
        let mut transaction = self.pool.begin().await?;
        set_read_snapshot(&mut transaction).await?;
        let Some(row) =
            load_intent_row(&mut transaction, organization_id, intent_id, false).await?
        else {
            transaction.commit().await?;
            return Ok(None);
        };
        let verified = verify_intent_row(organization_id, row)?;
        verify_admission_binding(
            &mut transaction,
            organization_id,
            intent_id,
            &verified.intent_hash,
        )
        .await?;
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        verify_lifecycle_replay(
            organization_id,
            &verified.intent,
            &verified.lifecycle,
            &chain,
        )?;
        transaction.commit().await?;
        Ok(Some(verified.lifecycle))
    }

    /// Atomically persist Evaluation, Decision, and the foreign-key-bound
    /// `DecisionRecorded` evidence. Policy/Risk must have completed before
    /// calling this operation; no evaluator work is run under this lock.
    pub async fn finalize_decision(
        &self,
        input: FinalizationInput,
    ) -> Result<FinalizedDecision, StoreError> {
        validate_finalization_input(&input)?;
        let evaluated_at = normalize_timestamp(input.evaluation.evaluated_at);
        let decided_at = normalize_timestamp(input.decided_at);

        let mut transaction = self.pool.begin().await?;
        set_write_timeouts(&mut transaction).await?;
        verify_lease_for_finalization(&mut transaction, &input).await?;

        let row = load_intent_row(
            &mut transaction,
            &input.organization_id,
            &input.intent_id,
            true,
        )
        .await?
        .ok_or_else(|| StoreError::IntentNotFound {
            organization_id: input.organization_id.clone(),
            intent_id: input.intent_id.clone(),
        })?;
        let verified_intent = verify_intent_row(&input.organization_id, row)?;
        if verified_intent.intent_hash != input.expected_intent_hash {
            return Err(StoreError::IntentHashMismatch {
                organization_id: input.organization_id,
                intent_id: input.intent_id,
                expected: input.expected_intent_hash,
                stored: verified_intent.intent_hash,
            });
        }
        if verified_intent.lifecycle.contract_version != LIFECYCLE_CONTRACT_VERSION {
            return Err(StoreError::InvalidRepositoryInput {
                reason: format!(
                    "Intent `{}` uses compatibility lifecycle contract version {}; it cannot be advanced by the typed writer",
                    input.intent_id, verified_intent.lifecycle.contract_version
                ),
            });
        }
        if verified_intent.lifecycle.version != input.expected_lifecycle_version {
            return Err(StoreError::LifecycleConflict {
                organization_id: input.organization_id,
                intent_id: input.intent_id,
                expected_version: input.expected_lifecycle_version,
                stored_version: verified_intent.lifecycle.version,
                stored_state: verified_intent.lifecycle.state.to_string(),
            });
        }
        let existing_chain =
            load_verified_in_transaction(&mut transaction, &input.organization_id).await?;
        verify_lifecycle_replay(
            &input.organization_id,
            &verified_intent.intent,
            &verified_intent.lifecycle,
            &existing_chain,
        )?;
        let identity = crate::nonce::load_initial_identity_evidence(
            &mut transaction,
            &input.organization_id,
            &input.intent_id,
            &verified_intent.intent_hash,
            &existing_chain,
        )
        .await?;
        let evaluation_context = load_verified_context_in_transaction(
            &mut transaction,
            &input.organization_id,
            &input.evaluation.evaluation_id,
            &verified_intent.intent,
            &existing_chain,
        )
        .await?;
        validate_context_binding(&input, &evaluation_context.context)?;

        let already_finalized: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS (
                SELECT 1
                FROM decisions
                WHERE organization_id = $1 AND intent_id = $2
            )
            "#,
        )
        .bind(&input.organization_id)
        .bind(&input.intent_id)
        .fetch_one(&mut *transaction)
        .await?;
        if already_finalized {
            return Err(StoreError::DecisionConflict {
                organization_id: input.organization_id,
                intent_id: input.intent_id,
            });
        }

        let evaluation = StoredEvaluation {
            schema_version: EVALUATION_SCHEMA_VERSION,
            evaluation_id: input.evaluation.evaluation_id.clone(),
            intent_id: input.intent_id.clone(),
            intent_hash: verified_intent.intent_hash.clone(),
            evaluation_context_hash: Some(input.evaluation.evaluation_context_hash.clone()),
            evaluated_at,
            evidence: serde_json::json!({
                "identity": AuditPayload::IdentityVerified(
                    identity
                ).to_data(),
                "policy": AuditPayload::PolicyEvaluated(input.evaluation.policy.clone()).to_data(),
                "risk": AuditPayload::RiskEvaluated(input.evaluation.risk.clone()).to_data(),
                "simulation": AuditPayload::SimulationCompleted(
                    input.evaluation.simulation.clone()
                ).to_data(),
            }),
        };
        let (canonical_evaluation, canonical_evaluation_bytes, evaluation_hash) =
            canonical_document(&evaluation)?;

        sqlx::query(
            r#"
            INSERT INTO evaluations (
                organization_id,
                evaluation_id,
                intent_id,
                canonical_evaluation,
                canonical_evaluation_bytes,
                evaluation_hash,
                evaluation_context_hash,
                evaluated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(&input.organization_id)
        .bind(&evaluation.evaluation_id)
        .bind(&input.intent_id)
        .bind(&canonical_evaluation)
        .bind(&canonical_evaluation_bytes)
        .bind(&evaluation_hash)
        .bind(&input.evaluation.evaluation_context_hash)
        .bind(evaluated_at.as_datetime())
        .execute(&mut *transaction)
        .await
        .map_err(|error| map_finalization_insert_error(error, &input))?;

        input
            .decision
            .verify_binding(&verified_intent.intent, &evaluation_context.context)
            .map_err(|error| StoreError::DecisionBindingMismatch {
                reason: error.to_string(),
            })?;
        let canonical_decision_bytes = input.decision.canonical_bytes();
        let canonical_decision: Value = serde_json::from_slice(&canonical_decision_bytes)?;
        let decision_hash = input.decision.decision_hash.clone();
        sqlx::query(
            r#"
            INSERT INTO decisions (
                organization_id,
                decision_id,
                intent_id,
                evaluation_id,
                canonical_decision,
                canonical_decision_bytes,
                decision_hash,
                decided_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(&input.organization_id)
        .bind(&input.decision.decision_id)
        .bind(&input.intent_id)
        .bind(&evaluation.evaluation_id)
        .bind(&canonical_decision)
        .bind(&canonical_decision_bytes)
        .bind(&decision_hash)
        .bind(decided_at.as_datetime())
        .execute(&mut *transaction)
        .await
        .map_err(|error| map_finalization_insert_error(error, &input))?;

        let mut lifecycle = verified_intent.lifecycle.clone();
        let phase_reference = || AuditReferences {
            evaluation_id: Some(evaluation.evaluation_id.clone()),
            decision_id: None,
        };
        append_lifecycle_event(
            &mut transaction,
            &input.organization_id,
            &input.intent_id,
            evaluated_at,
            AuditPayload::PolicyEvaluated(input.evaluation.policy.clone()),
            phase_reference(),
            &mut lifecycle,
        )
        .await?;
        append_lifecycle_event(
            &mut transaction,
            &input.organization_id,
            &input.intent_id,
            evaluated_at,
            AuditPayload::RiskEvaluated(input.evaluation.risk.clone()),
            phase_reference(),
            &mut lifecycle,
        )
        .await?;
        append_lifecycle_event(
            &mut transaction,
            &input.organization_id,
            &input.intent_id,
            evaluated_at,
            AuditPayload::SimulationCompleted(input.evaluation.simulation.clone()),
            phase_reference(),
            &mut lifecycle,
        )
        .await?;
        let audit_event = append_lifecycle_event(
            &mut transaction,
            &input.organization_id,
            &input.intent_id,
            decided_at,
            AuditPayload::DecisionRecorded(DecisionRecordedPayload {
                organization_id: input.organization_id.clone(),
                agent_id: verified_intent.intent.principal.agent_id.clone(),
                intent_hash: verified_intent.intent_hash.clone(),
                evaluation_id: evaluation.evaluation_id.clone(),
                evaluation_hash: evaluation_hash.clone(),
                decision_id: input.decision.decision_id.clone(),
                decision_hash: decision_hash.clone(),
                decision: input.decision.decision,
                action_category: verified_intent.intent.action.category.clone(),
                resource_id: verified_intent.intent.resource.resource_id.clone(),
                amount: verified_intent.intent.transaction.amount,
                destination: verified_intent.intent.transaction.destination.clone(),
                binding: Some(Box::new(decision_binding_evidence(&input.decision))),
            }),
            AuditReferences {
                evaluation_id: Some(evaluation.evaluation_id.clone()),
                decision_id: Some(input.decision.decision_id.clone()),
            },
            &mut lifecycle,
        )
        .await?;

        let updated = sqlx::query(
            r#"
            UPDATE intents
            SET lifecycle_state = $4,
                lifecycle_version = $5,
                lifecycle_event_id = $6,
                lifecycle_updated_at = $7
            WHERE organization_id = $1
              AND intent_id = $2
              AND lifecycle_version = $3
              AND lifecycle_contract_version = 1
            "#,
        )
        .bind(&input.organization_id)
        .bind(&input.intent_id)
        .bind(input.expected_lifecycle_version)
        .bind(lifecycle.state.as_str())
        .bind(lifecycle.version)
        .bind(&lifecycle.last_event_id)
        .bind(lifecycle.updated_at.as_datetime())
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::LifecycleConflict {
                organization_id: input.organization_id,
                intent_id: input.intent_id,
                expected_version: input.expected_lifecycle_version,
                stored_version: verified_intent.lifecycle.version,
                stored_state: verified_intent.lifecycle.state.to_string(),
            });
        }

        complete_idempotency(
            &mut transaction,
            &input,
            &evaluation.evaluation_id,
            &input.decision.decision_id,
            &decision_hash,
        )
        .await?;

        transaction.commit().await?;
        Ok(FinalizedDecision {
            organization_id: input.organization_id,
            intent_hash: verified_intent.intent_hash,
            evaluation_context: Some(evaluation_context.context),
            evaluation,
            evaluation_hash,
            decision: input.decision,
            decision_hash,
            decided_at,
            lifecycle,
            audit_event,
        })
    }

    /// Return a final Decision only when the canonical Intent, Evaluation,
    /// Decision, full Audit chain, and the Decision's bound Audit event all
    /// verify in one repeatable-read snapshot.
    pub async fn load_finalized_decision(
        &self,
        organization_id: &str,
        intent_id: &str,
    ) -> Result<Option<FinalizedDecision>, StoreError> {
        let mut transaction = self.pool.begin().await?;
        set_read_snapshot(&mut transaction).await?;

        let Some(intent_row) =
            load_intent_row(&mut transaction, organization_id, intent_id, false).await?
        else {
            transaction.commit().await?;
            return Ok(None);
        };
        let verified_intent = verify_intent_row(organization_id, intent_row)?;
        let decision_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM decisions WHERE organization_id = $1 AND intent_id = $2",
        )
        .bind(organization_id)
        .bind(intent_id)
        .fetch_one(&mut *transaction)
        .await?;
        if decision_count == 0 {
            transaction.commit().await?;
            return Ok(None);
        }
        if decision_count != 1 {
            return Err(durable_corrupt(
                organization_id,
                format!("Intent `{intent_id}` has more than one final Decision"),
            ));
        }

        let rows: Vec<FinalizationRow> = sqlx::query_as(
            r#"
            SELECT
                e.evaluation_id,
                e.intent_id AS evaluation_intent_id,
                e.canonical_evaluation,
                e.canonical_evaluation_bytes,
                e.evaluation_hash::text AS evaluation_hash,
                e.evaluation_context_hash::text AS evaluation_context_hash,
                e.evaluated_at,
                d.decision_id,
                d.intent_id AS decision_intent_id,
                d.evaluation_id AS decision_evaluation_id,
                d.canonical_decision,
                d.canonical_decision_bytes,
                d.decision_hash::text AS decision_hash,
                d.decided_at
            FROM decisions d
            JOIN evaluations e
              ON e.organization_id = d.organization_id
             AND e.evaluation_id = d.evaluation_id
             AND e.intent_id = d.intent_id
            WHERE d.organization_id = $1 AND d.intent_id = $2
            ORDER BY d.decision_id
            "#,
        )
        .bind(organization_id)
        .bind(intent_id)
        .fetch_all(&mut *transaction)
        .await?;

        if rows.len() != 1 {
            return Err(durable_corrupt(
                organization_id,
                format!(
                    "Intent `{intent_id}` has a Decision without exactly one matching Evaluation"
                ),
            ));
        }
        let row = rows.into_iter().next().expect("one row was checked");
        let (evaluation, evaluation_hash, decision, decision_hash, decided_at) =
            verify_finalization_row(
                organization_id,
                intent_id,
                &verified_intent.intent_hash,
                row,
            )?;

        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let evaluation_context = match evaluation.evaluation_context_hash.as_deref() {
            Some(context_hash) => {
                let stored = load_verified_context_in_transaction(
                    &mut transaction,
                    organization_id,
                    &evaluation.evaluation_id,
                    &verified_intent.intent,
                    &chain,
                )
                .await?;
                if stored.context.evaluation_context_hash() != context_hash
                    || stored.context.evaluation_time() != evaluation.evaluated_at
                {
                    return Err(durable_corrupt(
                        organization_id,
                        format!(
                            "Evaluation `{}` disagrees with its immutable Context",
                            evaluation.evaluation_id
                        ),
                    ));
                }
                decision
                    .verify_binding(&verified_intent.intent, &stored.context)
                    .map_err(|error| {
                        durable_corrupt(
                            organization_id,
                            format!(
                                "Decision `{}` disagrees with its immutable Context: {error}",
                                decision.decision_id
                            ),
                        )
                    })?;
                Some(stored.context)
            }
            None => None,
        };
        verify_lifecycle_replay(
            organization_id,
            &verified_intent.intent,
            &verified_intent.lifecycle,
            &chain,
        )?;
        let audit_event = exactly_one_decision_event(
            chain,
            organization_id,
            intent_id,
            &verified_intent.intent_hash,
            &evaluation,
            &evaluation_hash,
            &decision,
            &decision_hash,
            decided_at,
        )?;
        verify_completed_binding(
            &mut transaction,
            organization_id,
            intent_id,
            &verified_intent.intent_hash,
            &evaluation.evaluation_id,
            &decision.decision_id,
            &decision_hash,
        )
        .await?;

        transaction.commit().await?;
        Ok(Some(FinalizedDecision {
            organization_id: organization_id.to_owned(),
            intent_hash: verified_intent.intent_hash,
            evaluation_context,
            evaluation,
            evaluation_hash,
            decision,
            decision_hash,
            decided_at,
            lifecycle: verified_intent.lifecycle,
            audit_event,
        }))
    }
}

pub(crate) async fn set_write_timeouts(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), StoreError> {
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '10s'")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

pub(crate) async fn set_read_snapshot(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), StoreError> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '30s'")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

pub(crate) async fn load_intent_row(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    intent_id: &str,
    for_update: bool,
) -> Result<Option<IntentRow>, StoreError> {
    let statement = if for_update {
        r#"
        SELECT
            organization_id,
            intent_id,
            idempotency_key,
            spec_version,
            canonical_intent,
            canonical_intent_bytes,
            intent_hash::text AS intent_hash,
            created_at,
            expires_at,
            received_at,
            lifecycle_state,
            lifecycle_version,
            lifecycle_contract_version,
            lifecycle_event_id,
            lifecycle_updated_at
        FROM intents
        WHERE organization_id = $1 AND intent_id = $2
        FOR UPDATE
        "#
    } else {
        r#"
        SELECT
            organization_id,
            intent_id,
            idempotency_key,
            spec_version,
            canonical_intent,
            canonical_intent_bytes,
            intent_hash::text AS intent_hash,
            created_at,
            expires_at,
            received_at,
            lifecycle_state,
            lifecycle_version,
            lifecycle_contract_version,
            lifecycle_event_id,
            lifecycle_updated_at
        FROM intents
        WHERE organization_id = $1 AND intent_id = $2
        "#
    };

    sqlx::query_as(statement)
        .bind(organization_id)
        .bind(intent_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(StoreError::Database)
}

pub(crate) fn normalize_intent(intent: TransactionIntent) -> Result<TransactionIntent, StoreError> {
    let bytes = intent.canonical_bytes();
    serde_json::from_slice(&bytes).map_err(StoreError::Json)
}

pub(crate) fn normalize_timestamp(timestamp: Timestamp) -> Timestamp {
    timestamp
        .to_string()
        .parse()
        .expect("Timestamp's canonical Display is always valid RFC 3339")
}

fn canonical_document<T: Serialize>(value: &T) -> Result<(Value, Vec<u8>, String), StoreError> {
    let canonical = sort_json_keys(serde_json::to_value(value)?);
    if !canonical.is_object() {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "canonical durable documents must be JSON objects".into(),
        });
    }
    let bytes = serde_json::to_vec(&canonical)?;
    let hash = atf_core::sha256_hex(&bytes);
    Ok((canonical, bytes, hash))
}

pub(crate) fn verify_intent_row(
    organization_id: &str,
    row: IntentRow,
) -> Result<VerifiedIntent, StoreError> {
    let intent: TransactionIntent =
        serde_json::from_slice(&row.canonical_intent_bytes).map_err(|error| {
            durable_corrupt(
                organization_id,
                format!("Intent canonical bytes cannot be decoded: {error}"),
            )
        })?;
    let canonical = intent.canonical_value();
    let bytes = intent.canonical_bytes();
    let hash = intent.canonical_hash();
    let lifecycle_state = lifecycle_state_from_str(&row.lifecycle_state).ok_or_else(|| {
        durable_corrupt(
            organization_id,
            format!(
                "Intent `{}` has unknown lifecycle state `{}`",
                row.intent_id, row.lifecycle_state
            ),
        )
    })?;
    if row.lifecycle_version <= 0 || !matches!(row.lifecycle_contract_version, 0 | 1) {
        return Err(durable_corrupt(
            organization_id,
            format!(
                "Intent `{}` has invalid lifecycle version metadata",
                row.intent_id
            ),
        ));
    }
    if row.lifecycle_contract_version == LIFECYCLE_CONTRACT_VERSION
        && row.lifecycle_event_id.is_none()
    {
        return Err(durable_corrupt(
            organization_id,
            format!(
                "Intent `{}` lacks its state-producing Audit event pointer",
                row.intent_id
            ),
        ));
    }
    let lifecycle = StoredLifecycle {
        state: lifecycle_state,
        version: row.lifecycle_version,
        contract_version: row.lifecycle_contract_version,
        last_event_id: row.lifecycle_event_id.clone(),
        updated_at: Timestamp::from_datetime(row.lifecycle_updated_at),
    };
    let columns_match = row.organization_id == organization_id
        && row.intent_id == intent.intent_id
        && row.idempotency_key == intent.idempotency_key
        && row.spec_version == intent.spec_version
        && sort_json_keys(row.canonical_intent) == canonical
        && row.canonical_intent_bytes == bytes
        && row.intent_hash == hash
        && Timestamp::from_datetime(row.created_at) == intent.created_at
        && Timestamp::from_datetime(row.expires_at) == intent.expires_at
        && intent.principal.organization_id == organization_id;
    if !columns_match {
        return Err(durable_corrupt(
            organization_id,
            format!(
                "Intent `{}` canonical document, hash, or redundant columns disagree",
                row.intent_id
            ),
        ));
    }

    Ok(VerifiedIntent {
        intent,
        intent_hash: hash,
        received_at: Timestamp::from_datetime(row.received_at),
        lifecycle,
    })
}

fn verify_finalization_row(
    organization_id: &str,
    intent_id: &str,
    intent_hash: &str,
    row: FinalizationRow,
) -> Result<(StoredEvaluation, String, Decision, String, Timestamp), StoreError> {
    let evaluation: StoredEvaluation = serde_json::from_slice(&row.canonical_evaluation_bytes)
        .map_err(|error| {
            durable_corrupt(
                organization_id,
                format!("Evaluation canonical bytes cannot be decoded: {error}"),
            )
        })?;
    let (canonical_evaluation, evaluation_bytes, evaluation_hash) =
        canonical_document(&evaluation)?;
    let supported_schema = matches!(
        (
            evaluation.schema_version,
            &evaluation.evaluation_context_hash
        ),
        (LEGACY_EVALUATION_SCHEMA_VERSION, None) | (EVALUATION_SCHEMA_VERSION, Some(_))
    );
    let evaluation_matches = supported_schema
        && evaluation.evaluation_id == row.evaluation_id
        && evaluation.intent_id == intent_id
        && evaluation.intent_hash == intent_hash
        && row.evaluation_intent_id == intent_id
        && sort_json_keys(row.canonical_evaluation) == canonical_evaluation
        && row.canonical_evaluation_bytes == evaluation_bytes
        && row.evaluation_hash == evaluation_hash
        && row.evaluation_context_hash == evaluation.evaluation_context_hash
        && Timestamp::from_datetime(row.evaluated_at) == evaluation.evaluated_at;
    if !evaluation_matches {
        return Err(durable_corrupt(
            organization_id,
            format!(
                "Evaluation `{}` is not canonically bound to Intent `{intent_id}`",
                row.evaluation_id
            ),
        ));
    }

    let decision: Decision =
        serde_json::from_slice(&row.canonical_decision_bytes).map_err(|error| {
            durable_corrupt(
                organization_id,
                format!("Decision canonical bytes cannot be decoded: {error}"),
            )
        })?;
    decision.verify_hash().map_err(|error| {
        durable_corrupt(
            organization_id,
            format!("Decision canonical hash is invalid: {error}"),
        )
    })?;
    let decision_bytes = decision.canonical_bytes();
    let canonical_decision: Value = serde_json::from_slice(&decision_bytes)?;
    let decision_hash = decision.decision_hash.clone();
    let decision_matches = decision.decision_id == row.decision_id
        && decision.intent_id == intent_id
        && row.decision_intent_id == intent_id
        && row.decision_evaluation_id == evaluation.evaluation_id
        && sort_json_keys(row.canonical_decision) == canonical_decision
        && row.canonical_decision_bytes == decision_bytes
        && row.decision_hash == decision_hash;
    if !decision_matches {
        return Err(durable_corrupt(
            organization_id,
            format!(
                "Decision `{}` is not canonically bound to its Intent/Evaluation",
                row.decision_id
            ),
        ));
    }

    Ok((
        evaluation,
        evaluation_hash,
        decision,
        decision_hash,
        Timestamp::from_datetime(row.decided_at),
    ))
}

fn validate_context_binding(
    input: &FinalizationInput,
    context: &EvaluationContext,
) -> Result<(), StoreError> {
    let basic_binding = context.evaluation_id() == input.evaluation.evaluation_id
        && context.intent_id() == input.intent_id
        && context.intent_hash() == input.expected_intent_hash
        && context.evaluation_time() == input.evaluation.evaluated_at
        && context.evaluation_context_hash() == input.evaluation.evaluation_context_hash;
    if !basic_binding {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "finalization does not match its immutable Evaluation Context".into(),
        });
    }

    let risk_binding = match context.risk().available_parts() {
        Some((_, version, hash)) => {
            input.evaluation.risk.risk_rule_set_version.as_deref() == Some(version)
                && input.evaluation.risk.risk_rule_set_hash.as_deref() == Some(hash)
        }
        None => {
            input.evaluation.risk.risk_rule_set_version.is_none()
                && input.evaluation.risk.risk_rule_set_hash.is_none()
                && matches!(
                    input.evaluation.risk.outcome,
                    OptionalModuleOutcome::Error { .. } | OptionalModuleOutcome::NotRun { .. }
                )
        }
    };
    if !risk_binding {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "Risk output identity disagrees with its Evaluation Context".into(),
        });
    }

    let history_binding = match &input.evaluation.risk.outcome {
        OptionalModuleOutcome::Succeeded { .. } | OptionalModuleOutcome::Error { .. } => input
            .evaluation
            .risk
            .history
            .as_ref()
            .is_some_and(|history| history.repository() == context.history()),
        OptionalModuleOutcome::NotRun { .. } => input.evaluation.risk.history.is_none(),
    };
    if !history_binding {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "Risk history evidence disagrees with its Evaluation Context".into(),
        });
    }

    let simulation_binding = matches!(
        &input.evaluation.simulation.outcome,
        OptionalModuleOutcome::NotRun { reason_code }
            if reason_code == context.simulation().reason_code()
    );
    if !simulation_binding {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "Simulation output disagrees with its Evaluation Context".into(),
        });
    }
    Ok(())
}

fn exactly_one_admission_event(
    chain: Vec<StoredAuditEvent>,
    organization_id: &str,
    intent_id: &str,
    intent_hash: &str,
    received_at: Timestamp,
) -> Result<StoredAuditEvent, StoreError> {
    let mut matches = chain.into_iter().filter(|stored| {
        stored.event.event_type == EventType::IntentReceived
            && stored.event.intent_id.as_deref() == Some(intent_id)
            && stored.event.occurred_at == received_at
            && stored.evaluation_id.is_none()
            && stored.decision_id.is_none()
            && data_string(&stored.event.data, "intent_hash") == Some(intent_hash)
    });
    let Some(event) = matches.next() else {
        return Err(StoreError::IncompleteAdmissionEvidence {
            organization_id: organization_id.to_owned(),
            intent_id: intent_id.to_owned(),
        });
    };
    if matches.next().is_some() {
        return Err(StoreError::IncompleteAdmissionEvidence {
            organization_id: organization_id.to_owned(),
            intent_id: intent_id.to_owned(),
        });
    }
    Ok(event)
}

#[allow(clippy::too_many_arguments)]
fn exactly_one_decision_event(
    chain: Vec<StoredAuditEvent>,
    organization_id: &str,
    intent_id: &str,
    intent_hash: &str,
    evaluation: &StoredEvaluation,
    evaluation_hash: &str,
    decision: &Decision,
    decision_hash: &str,
    decided_at: Timestamp,
) -> Result<StoredAuditEvent, StoreError> {
    let decision_kind = decision_kind_name(decision)?;
    let mut matches = chain.into_iter().filter(|stored| {
        stored.event.event_type == EventType::DecisionRecorded
            && stored.event.intent_id.as_deref() == Some(intent_id)
            && stored.evaluation_id.as_deref() == Some(evaluation.evaluation_id.as_str())
            && stored.decision_id.as_deref() == Some(decision.decision_id.as_str())
            && stored.event.occurred_at == decided_at
            && data_string(&stored.event.data, "intent_hash") == Some(intent_hash)
            && data_string(&stored.event.data, "organization_id") == Some(organization_id)
            && data_string(&stored.event.data, "evaluation_id")
                == Some(evaluation.evaluation_id.as_str())
            && data_string(&stored.event.data, "evaluation_hash") == Some(evaluation_hash)
            && data_string(&stored.event.data, "decision_id") == Some(decision.decision_id.as_str())
            && data_string(&stored.event.data, "decision") == Some(decision_kind.as_str())
            && data_string(&stored.event.data, "decision_hash") == Some(decision_hash)
            && stored.event.data.get("binding")
                == Some(
                    &serde_json::to_value(decision_binding_evidence(decision))
                        .expect("Decision binding evidence serialization cannot fail"),
                )
    });
    let Some(event) = matches.next() else {
        return Err(StoreError::IncompleteDecisionEvidence {
            organization_id: organization_id.to_owned(),
            intent_id: intent_id.to_owned(),
        });
    };
    if matches.next().is_some() {
        return Err(StoreError::IncompleteDecisionEvidence {
            organization_id: organization_id.to_owned(),
            intent_id: intent_id.to_owned(),
        });
    }
    Ok(event)
}

fn decision_binding_evidence(decision: &Decision) -> DecisionBindingEvidence {
    DecisionBindingEvidence {
        decision_version: decision.decision_version.clone(),
        profile: decision.profile.clone(),
        policy: decision.policy.clone(),
        risk: decision.risk.clone(),
        evaluation_context_hash: decision.evaluation_context_hash.clone(),
        context_snapshot_hash: decision.context_snapshot_hash.clone(),
        simulation: decision.simulation.clone(),
        evaluation_time: decision.evaluation_time,
        expires_at: decision.expires_at,
        required_approvals: decision.required_approvals.clone(),
        obligations: decision.obligations.clone(),
        execution_constraints: decision.execution_constraints.clone(),
    }
}

fn data_string<'a>(data: &'a Value, key: &str) -> Option<&'a str> {
    data.get(key).and_then(Value::as_str)
}

fn decision_kind_name(decision: &Decision) -> Result<String, StoreError> {
    serde_json::to_value(decision.decision)?
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| StoreError::InvalidRepositoryInput {
            reason: "Decision kind must serialize as a string".into(),
        })
}

pub(crate) fn map_admission_insert_error(
    error: sqlx::Error,
    intent: &TransactionIntent,
) -> StoreError {
    if has_database_code(&error, "23505") {
        StoreError::IntentConflict {
            organization_id: intent.principal.organization_id.clone(),
            intent_id: intent.intent_id.clone(),
            idempotency_key: intent.idempotency_key.clone(),
        }
    } else if has_database_code(&error, "23503") {
        StoreError::OrganizationNotFound {
            organization_id: intent.principal.organization_id.clone(),
        }
    } else {
        StoreError::Database(error)
    }
}

fn map_finalization_insert_error(error: sqlx::Error, input: &FinalizationInput) -> StoreError {
    if has_database_code(&error, "23505") {
        StoreError::FinalizationConflict {
            organization_id: input.organization_id.clone(),
            intent_id: input.intent_id.clone(),
        }
    } else {
        StoreError::Database(error)
    }
}

fn has_database_code(error: &sqlx::Error, expected: &str) -> bool {
    error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .as_deref()
        == Some(expected)
}

fn durable_corrupt(organization_id: &str, reason: impl Into<String>) -> StoreError {
    StoreError::DurableStateCorrupt {
        organization_id: organization_id.to_owned(),
        reason: reason.into(),
    }
}
