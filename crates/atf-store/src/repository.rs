use crate::audit::{
    append_in_transaction, load_verified_in_transaction, AuditReferences, StoredAuditEvent,
};
use crate::models::{
    AdmissionInput, AdmittedIntent, FinalizationInput, FinalizedDecision, StoredEvaluation,
};
use crate::{Store, StoreError};
use atf_audit::{EventType, NewAuditEvent};
use atf_core::{sort_json_keys, Timestamp};
use atf_decision::Decision;
use atf_intent::TransactionIntent;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};

const EVALUATION_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, FromRow)]
struct IntentRow {
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
}

#[derive(Debug, FromRow)]
struct FinalizationRow {
    evaluation_id: String,
    evaluation_intent_id: String,
    canonical_evaluation: Value,
    canonical_evaluation_bytes: Vec<u8>,
    evaluation_hash: String,
    evaluated_at: DateTime<Utc>,
    decision_id: String,
    decision_intent_id: String,
    decision_evaluation_id: String,
    canonical_decision: Value,
    canonical_decision_bytes: Vec<u8>,
    decision_hash: String,
    decided_at: DateTime<Utc>,
}

struct VerifiedIntent {
    intent: TransactionIntent,
    intent_hash: String,
    received_at: Timestamp,
}

impl Store {
    /// Persist an immutable canonical Intent and its first Audit event in one
    /// short transaction. This operation does not evaluate Policy or Risk.
    pub async fn admit_intent(&self, input: AdmissionInput) -> Result<AdmittedIntent, StoreError> {
        let intent = normalize_intent(input.intent)?;
        let received_at = normalize_timestamp(input.received_at);
        let organization_id = intent.principal.organization_id.clone();
        let canonical_intent = intent.canonical_value();
        let canonical_intent_bytes = intent.canonical_bytes();
        let intent_hash = intent.canonical_hash();

        let mut transaction = self.pool.begin().await?;
        set_write_timeouts(&mut transaction).await?;

        sqlx::query(
            r#"
            INSERT INTO intents (
                organization_id,
                intent_id,
                idempotency_key,
                spec_version,
                canonical_intent,
                canonical_intent_bytes,
                intent_hash,
                created_at,
                expires_at,
                received_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(&organization_id)
        .bind(&intent.intent_id)
        .bind(&intent.idempotency_key)
        .bind(&intent.spec_version)
        .bind(&canonical_intent)
        .bind(&canonical_intent_bytes)
        .bind(&intent_hash)
        .bind(intent.created_at.as_datetime())
        .bind(intent.expires_at.as_datetime())
        .bind(received_at.as_datetime())
        .execute(&mut *transaction)
        .await
        .map_err(|error| map_admission_insert_error(error, &intent))?;

        let event = NewAuditEvent::new(
            EventType::IntentReceived,
            received_at,
            Some(intent.intent_id.clone()),
            serde_json::json!({
                "agent_id": &intent.principal.agent_id,
                "amount": intent.transaction.amount.to_string(),
                "idempotency_key": &intent.idempotency_key,
                "intent_hash": &intent_hash,
                "organization_id": &organization_id,
                "resource_id": &intent.resource.resource_id,
            }),
        );
        let audit_event = append_in_transaction(
            &mut transaction,
            &organization_id,
            event,
            AuditReferences::default(),
        )
        .await?;

        transaction.commit().await?;
        Ok(AdmittedIntent {
            organization_id,
            intent,
            intent_hash,
            received_at,
            audit_event,
        })
    }

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
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let audit_event = exactly_one_admission_event(
            chain,
            organization_id,
            intent_id,
            &verified.intent_hash,
            verified.received_at,
        )?;

        transaction.commit().await?;
        Ok(Some(AdmittedIntent {
            organization_id: organization_id.to_owned(),
            intent: verified.intent,
            intent_hash: verified.intent_hash,
            received_at: verified.received_at,
            audit_event,
        }))
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
            evaluated_at,
            evidence: input.evaluation.evidence.clone(),
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
                evaluated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(&input.organization_id)
        .bind(&evaluation.evaluation_id)
        .bind(&input.intent_id)
        .bind(&canonical_evaluation)
        .bind(&canonical_evaluation_bytes)
        .bind(&evaluation_hash)
        .bind(evaluated_at.as_datetime())
        .execute(&mut *transaction)
        .await
        .map_err(|error| map_finalization_insert_error(error, &input))?;

        let (canonical_decision, canonical_decision_bytes, decision_hash) =
            canonical_document(&input.decision)?;
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

        let decision_name = decision_kind_name(&input.decision)?;
        let event = NewAuditEvent::new(
            EventType::DecisionRecorded,
            decided_at,
            Some(input.intent_id.clone()),
            serde_json::json!({
                "action_category": &verified_intent.intent.action.category,
                "agent_id": &verified_intent.intent.principal.agent_id,
                "amount": verified_intent.intent.transaction.amount.to_string(),
                "decision": decision_name,
                "decision_hash": &decision_hash,
                "decision_id": &input.decision.decision_id,
                "destination": &verified_intent.intent.transaction.destination,
                "evaluation_hash": &evaluation_hash,
                "evaluation_id": &evaluation.evaluation_id,
                "intent_hash": &verified_intent.intent_hash,
                "organization_id": &input.organization_id,
                "resource_id": &verified_intent.intent.resource.resource_id,
            }),
        );
        let audit_event = append_in_transaction(
            &mut transaction,
            &input.organization_id,
            event,
            AuditReferences {
                evaluation_id: Some(evaluation.evaluation_id.clone()),
                decision_id: Some(input.decision.decision_id.clone()),
            },
        )
        .await?;

        transaction.commit().await?;
        Ok(FinalizedDecision {
            organization_id: input.organization_id,
            intent_hash: verified_intent.intent_hash,
            evaluation,
            evaluation_hash,
            decision: input.decision,
            decision_hash,
            decided_at,
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

        transaction.commit().await?;
        Ok(Some(FinalizedDecision {
            organization_id: organization_id.to_owned(),
            intent_hash: verified_intent.intent_hash,
            evaluation,
            evaluation_hash,
            decision,
            decision_hash,
            decided_at,
            audit_event,
        }))
    }
}

async fn set_write_timeouts(transaction: &mut Transaction<'_, Postgres>) -> Result<(), StoreError> {
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '10s'")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn set_read_snapshot(transaction: &mut Transaction<'_, Postgres>) -> Result<(), StoreError> {
    sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '30s'")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

async fn load_intent_row(
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
            received_at
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
            received_at
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

fn normalize_intent(intent: TransactionIntent) -> Result<TransactionIntent, StoreError> {
    let bytes = intent.canonical_bytes();
    serde_json::from_slice(&bytes).map_err(StoreError::Json)
}

fn normalize_timestamp(timestamp: Timestamp) -> Timestamp {
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

fn validate_finalization_input(input: &FinalizationInput) -> Result<(), StoreError> {
    if input.decision.intent_id != input.intent_id {
        return Err(StoreError::DecisionBindingMismatch {
            reason: format!(
                "Decision names `{}` but finalization requested `{}`",
                input.decision.intent_id, input.intent_id
            ),
        });
    }
    if !input.evaluation.evidence.is_object() {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "Evaluation evidence must be a JSON object".into(),
        });
    }
    Ok(())
}

fn verify_intent_row(organization_id: &str, row: IntentRow) -> Result<VerifiedIntent, StoreError> {
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
    let evaluation_matches = evaluation.schema_version == EVALUATION_SCHEMA_VERSION
        && evaluation.evaluation_id == row.evaluation_id
        && evaluation.intent_id == intent_id
        && evaluation.intent_hash == intent_hash
        && row.evaluation_intent_id == intent_id
        && sort_json_keys(row.canonical_evaluation) == canonical_evaluation
        && row.canonical_evaluation_bytes == evaluation_bytes
        && row.evaluation_hash == evaluation_hash
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
    let (canonical_decision, decision_bytes, decision_hash) = canonical_document(&decision)?;
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

fn map_admission_insert_error(error: sqlx::Error, intent: &TransactionIntent) -> StoreError {
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
