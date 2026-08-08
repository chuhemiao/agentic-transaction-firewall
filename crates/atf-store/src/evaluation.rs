use atf_audit::{AuditPayload, ContextEnrichedPayload, NewAuditEvent};
use atf_core::{sort_json_keys, EvaluationContext, IntentLifecycleState, Timestamp};
use atf_intent::{validate_profile, TransactionIntent};
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};

use crate::audit::{append_in_transaction, load_verified_in_transaction, AuditReferences};
use crate::idempotency::verify_active_lease;
use crate::models::{EvaluationContextPersistence, StoredEvaluationContext};
use crate::repository::{
    load_intent_row, set_read_snapshot, set_write_timeouts, verify_intent_row,
};
use crate::{Store, StoreError, StoredAuditEvent};

const CONTEXT_VERSION: &str = "1";

#[derive(Debug, FromRow)]
pub(crate) struct EvaluationContextRow {
    organization_id: String,
    evaluation_id: String,
    intent_id: String,
    intent_hash: String,
    evaluation_context_version: String,
    environment: String,
    canonical_context: Value,
    canonical_context_bytes: Vec<u8>,
    evaluation_context_hash: String,
    evaluation_time: DateTime<Utc>,
    recorded_event_id: String,
    recorded_at: DateTime<Utc>,
}

impl Store {
    /// Persist one immutable input snapshot and its typed Audit evidence before
    /// any Policy/Risk output is computed.
    pub async fn persist_evaluation_context(
        &self,
        input: EvaluationContextPersistence,
    ) -> Result<StoredEvaluationContext, StoreError> {
        validate_persistence_input(&input)?;
        let mut transaction = self.pool.begin().await?;
        set_write_timeouts(&mut transaction).await?;
        verify_active_lease(
            &mut transaction,
            &input.organization_id,
            input.context.intent_id(),
            &input.expected_intent_hash,
            &input.evaluator_lease,
        )
        .await?;

        let intent_row = load_intent_row(
            &mut transaction,
            &input.organization_id,
            input.context.intent_id(),
            true,
        )
        .await?
        .ok_or_else(|| StoreError::IntentNotFound {
            organization_id: input.organization_id.clone(),
            intent_id: input.context.intent_id().into(),
        })?;
        let intent = verify_intent_row(&input.organization_id, intent_row)?;
        if intent.intent_hash != input.expected_intent_hash
            || intent.intent_hash != input.context.intent_hash()
        {
            return Err(StoreError::IntentHashMismatch {
                organization_id: input.organization_id,
                intent_id: input.context.intent_id().into(),
                expected: input.expected_intent_hash,
                stored: intent.intent_hash,
            });
        }
        validate_new_context_intent_binding(&input.context, &intent.intent)?;
        if intent.lifecycle.state != IntentLifecycleState::IdentityVerified {
            return Err(StoreError::LifecycleConflict {
                organization_id: input.organization_id,
                intent_id: input.context.intent_id().into(),
                expected_version: intent.lifecycle.version,
                stored_version: intent.lifecycle.version,
                stored_state: intent.lifecycle.state.to_string(),
            });
        }
        if input.context.evaluation_time() < intent.received_at {
            return Err(StoreError::InvalidRepositoryInput {
                reason: "evaluation_time cannot precede durable Intent admission".into(),
            });
        }

        let chain = load_verified_in_transaction(&mut transaction, &input.organization_id).await?;
        verify_history_snapshot(&input.organization_id, &input.context, &chain)?;

        if let Some(row) = load_context_by_intent(
            &mut transaction,
            &input.organization_id,
            input.context.intent_id(),
            true,
        )
        .await?
        {
            let stored = verify_context_row(&input.organization_id, row, &chain)?;
            if stored.context.evaluation_id() == input.context.evaluation_id()
                && stored.context.evaluation_context_hash()
                    == input.context.evaluation_context_hash()
                && stored.context.canonical_bytes() == input.context.canonical_bytes()
            {
                transaction.commit().await?;
                return Ok(stored);
            }
            return Err(StoreError::EvaluationContextConflict {
                organization_id: input.organization_id,
                intent_id: input.context.intent_id().into(),
            });
        }

        let event = NewAuditEvent::from_payload(
            input.context.evaluation_time(),
            Some(input.context.intent_id().into()),
            AuditPayload::ContextEnriched(ContextEnrichedPayload {
                context_hash: input.context.evaluation_context_hash().into(),
                source_ids: input.context.context_source_ids(),
            }),
        )?;
        let recorded_at: DateTime<Utc> = sqlx::query_scalar(
            r#"
            INSERT INTO evaluation_contexts (
                organization_id,
                evaluation_id,
                intent_id,
                intent_hash,
                evaluation_context_version,
                environment,
                canonical_context,
                canonical_context_bytes,
                evaluation_context_hash,
                evaluation_time,
                recorded_event_id
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING recorded_at
            "#,
        )
        .bind(&input.organization_id)
        .bind(input.context.evaluation_id())
        .bind(input.context.intent_id())
        .bind(input.context.intent_hash())
        .bind(CONTEXT_VERSION)
        .bind(input.context.environment())
        .bind(sort_json_keys(serde_json::to_value(&input.context)?))
        .bind(input.context.canonical_bytes())
        .bind(input.context.evaluation_context_hash())
        .bind(input.context.evaluation_time().as_datetime())
        .bind(&event.event_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| map_context_insert_error(error, &input))?;
        let audit_event = append_in_transaction(
            &mut transaction,
            &input.organization_id,
            event,
            AuditReferences::default(),
        )
        .await?;
        transaction.commit().await?;

        Ok(StoredEvaluationContext {
            organization_id: input.organization_id,
            context: input.context,
            recorded_at: Timestamp::from_datetime(recorded_at),
            audit_event,
        })
    }

    /// Load a context only after canonical bytes/hash, redundant columns,
    /// immutable Intent/history bindings and typed Audit evidence all verify in
    /// one repeatable-read snapshot.
    pub async fn load_evaluation_context(
        &self,
        organization_id: &str,
        evaluation_id: &str,
    ) -> Result<Option<StoredEvaluationContext>, StoreError> {
        let mut transaction = self.pool.begin().await?;
        set_read_snapshot(&mut transaction).await?;
        let Some(row) =
            load_context_by_id(&mut transaction, organization_id, evaluation_id, false).await?
        else {
            transaction.commit().await?;
            return Ok(None);
        };
        let intent_row = load_intent_row(&mut transaction, organization_id, &row.intent_id, false)
            .await?
            .ok_or_else(|| corrupt(organization_id, "Evaluation Context Intent disappeared"))?;
        let intent = verify_intent_row(organization_id, intent_row)?;
        if intent.intent_hash != row.intent_hash {
            return Err(corrupt(
                organization_id,
                "Evaluation Context Intent hash disagrees with durable Intent",
            ));
        }
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let stored = verify_context_row(organization_id, row, &chain)?;
        verify_durable_context_intent_binding(organization_id, &stored.context, &intent.intent)?;
        transaction.commit().await?;
        Ok(Some(stored))
    }

    pub async fn load_evaluation_context_for_intent(
        &self,
        organization_id: &str,
        intent_id: &str,
    ) -> Result<Option<StoredEvaluationContext>, StoreError> {
        let mut transaction = self.pool.begin().await?;
        set_read_snapshot(&mut transaction).await?;
        let Some(row) =
            load_context_by_intent(&mut transaction, organization_id, intent_id, false).await?
        else {
            transaction.commit().await?;
            return Ok(None);
        };
        let intent_row = load_intent_row(&mut transaction, organization_id, intent_id, false)
            .await?
            .ok_or_else(|| corrupt(organization_id, "Evaluation Context Intent disappeared"))?;
        let intent = verify_intent_row(organization_id, intent_row)?;
        if intent.intent_hash != row.intent_hash {
            return Err(corrupt(
                organization_id,
                "Evaluation Context Intent hash disagrees with durable Intent",
            ));
        }
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let stored = verify_context_row(organization_id, row, &chain)?;
        verify_durable_context_intent_binding(organization_id, &stored.context, &intent.intent)?;
        transaction.commit().await?;
        Ok(Some(stored))
    }
}

pub(crate) async fn load_verified_context_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    evaluation_id: &str,
    intent: &TransactionIntent,
    chain: &[StoredAuditEvent],
) -> Result<StoredEvaluationContext, StoreError> {
    let row = load_context_by_id(transaction, organization_id, evaluation_id, false)
        .await?
        .ok_or_else(|| StoreError::EvaluationContextNotFound {
            organization_id: organization_id.into(),
            evaluation_id: evaluation_id.into(),
        })?;
    let stored = verify_context_row(organization_id, row, chain)?;
    verify_durable_context_intent_binding(organization_id, &stored.context, intent)?;
    Ok(stored)
}

fn validate_new_context_intent_binding(
    context: &EvaluationContext,
    intent: &TransactionIntent,
) -> Result<(), StoreError> {
    let profile = validate_profile(intent).map_err(|error| StoreError::InvalidRepositoryInput {
        reason: format!("Evaluation Context Intent Profile is invalid: {error}"),
    })?;
    if context.profile_id() != profile.id()
        || context.profile_version() != profile.version()
        || context.verify_agent_context(&intent.context).is_err()
    {
        return Err(StoreError::InvalidRepositoryInput {
            reason:
                "Evaluation Context profile or Agent context disagrees with its immutable Intent"
                    .into(),
        });
    }
    Ok(())
}

fn verify_durable_context_intent_binding(
    organization_id: &str,
    context: &EvaluationContext,
    intent: &TransactionIntent,
) -> Result<(), StoreError> {
    let profile = validate_profile(intent).map_err(|error| {
        corrupt(
            organization_id,
            format!("Evaluation Context Intent Profile is invalid: {error}"),
        )
    })?;
    if context.profile_id() != profile.id()
        || context.profile_version() != profile.version()
        || context.verify_agent_context(&intent.context).is_err()
    {
        return Err(corrupt(
            organization_id,
            "Evaluation Context profile or Agent context disagrees with its immutable Intent",
        ));
    }
    Ok(())
}

fn validate_persistence_input(input: &EvaluationContextPersistence) -> Result<(), StoreError> {
    if !input.context.is_newly_constructed() {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "only a context constructed from verified inputs can be persisted".into(),
        });
    }
    if input.organization_id.is_empty()
        || input.organization_id.trim() != input.organization_id
        || input.organization_id.len() > 256
    {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "organization_id must be 1..256 trimmed bytes".into(),
        });
    }
    if input.organization_id != input.evaluator_lease.organization_id
        || input.context.intent_id() != input.evaluator_lease.intent_id
    {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "Evaluation Context scope disagrees with its evaluator lease".into(),
        });
    }
    if input.context.intent_hash() != input.expected_intent_hash {
        return Err(StoreError::IntentHashMismatch {
            organization_id: input.organization_id.clone(),
            intent_id: input.context.intent_id().into(),
            expected: input.expected_intent_hash.clone(),
            stored: input.evaluator_lease.intent_hash.clone(),
        });
    }
    input
        .context
        .verify_hash(input.context.evaluation_context_hash())?;
    Ok(())
}

fn verify_context_row(
    organization_id: &str,
    row: EvaluationContextRow,
    chain: &[StoredAuditEvent],
) -> Result<StoredEvaluationContext, StoreError> {
    let context = EvaluationContext::from_persisted(
        &row.canonical_context_bytes,
        &row.evaluation_context_hash,
    )
    .map_err(|error| {
        corrupt(
            organization_id,
            format!("Evaluation Context is invalid: {error}"),
        )
    })?;
    let canonical_context = sort_json_keys(serde_json::to_value(&context)?);
    let columns_match = row.organization_id == organization_id
        && row.evaluation_context_version == CONTEXT_VERSION
        && row.evaluation_id == context.evaluation_id()
        && row.intent_id == context.intent_id()
        && row.intent_hash == context.intent_hash()
        && row.environment == context.environment()
        && row.canonical_context == canonical_context
        && row.canonical_context_bytes == context.canonical_bytes()
        && row.evaluation_context_hash == context.evaluation_context_hash()
        && Timestamp::from_datetime(row.evaluation_time) == context.evaluation_time();
    if !columns_match {
        return Err(corrupt(
            organization_id,
            format!(
                "Evaluation Context `{}` redundant columns or canonical bytes disagree",
                row.evaluation_id
            ),
        ));
    }
    verify_history_snapshot(organization_id, &context, chain)?;

    let matching = chain
        .iter()
        .filter(|stored| stored.event.event_id == row.recorded_event_id)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(corrupt(
            organization_id,
            format!(
                "Evaluation Context `{}` lacks exactly one recorded Audit event",
                row.evaluation_id
            ),
        ));
    }
    let audit_event = matching[0];
    let payload = audit_event.event.typed_payload().map_err(|error| {
        corrupt(
            organization_id,
            format!("Evaluation Context Audit payload is invalid: {error}"),
        )
    })?;
    let expected_sources = context.context_source_ids();
    let audit_matches = audit_event.event.event_type == atf_audit::EventType::ContextEnriched
        && audit_event.event.intent_id.as_deref() == Some(context.intent_id())
        && audit_event.event.occurred_at == context.evaluation_time()
        && audit_event.evaluation_id.is_none()
        && audit_event.decision_id.is_none()
        && matches!(
            payload,
            AuditPayload::ContextEnriched(ContextEnrichedPayload {
                context_hash,
                source_ids,
            }) if context_hash == context.evaluation_context_hash()
                && source_ids == expected_sources
        );
    if !audit_matches {
        return Err(corrupt(
            organization_id,
            format!(
                "Evaluation Context `{}` Audit evidence disagrees",
                row.evaluation_id
            ),
        ));
    }

    Ok(StoredEvaluationContext {
        organization_id: organization_id.into(),
        context,
        recorded_at: Timestamp::from_datetime(row.recorded_at),
        audit_event: audit_event.clone(),
    })
}

fn verify_history_snapshot(
    organization_id: &str,
    context: &EvaluationContext,
    chain: &[StoredAuditEvent],
) -> Result<(), StoreError> {
    let history = context.history();
    let sequence = usize::try_from(history.through_sequence()).map_err(|_| {
        corrupt(
            organization_id,
            "Evaluation Context history sequence exceeds this platform",
        )
    })?;
    if sequence == 0 || sequence > chain.len() {
        return Err(corrupt(
            organization_id,
            "Evaluation Context history snapshot is outside the verified Audit chain",
        ));
    }
    let event = &chain[sequence - 1];
    let expected_id = format!(
        "audit-chain:{organization_id}:{}",
        history.through_sequence()
    );
    if event.sequence != i64::try_from(history.through_sequence()).unwrap_or(i64::MAX)
        || event.event_hash != history.snapshot_hash()
        || history.snapshot_id() != expected_id
    {
        return Err(corrupt(
            organization_id,
            "Evaluation Context history snapshot does not match its verified Audit boundary",
        ));
    }
    Ok(())
}

async fn load_context_by_id(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    evaluation_id: &str,
    for_update: bool,
) -> Result<Option<EvaluationContextRow>, StoreError> {
    load_context(
        transaction,
        "evaluation_id",
        organization_id,
        evaluation_id,
        for_update,
    )
    .await
}

async fn load_context_by_intent(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    intent_id: &str,
    for_update: bool,
) -> Result<Option<EvaluationContextRow>, StoreError> {
    load_context(
        transaction,
        "intent_id",
        organization_id,
        intent_id,
        for_update,
    )
    .await
}

async fn load_context(
    transaction: &mut Transaction<'_, Postgres>,
    lookup_column: &str,
    organization_id: &str,
    lookup_value: &str,
    for_update: bool,
) -> Result<Option<EvaluationContextRow>, StoreError> {
    let lock = if for_update { " FOR UPDATE" } else { "" };
    let statement = format!(
        r#"
        SELECT
            organization_id,
            evaluation_id,
            intent_id,
            intent_hash::text AS intent_hash,
            evaluation_context_version,
            environment,
            canonical_context,
            canonical_context_bytes,
            evaluation_context_hash::text AS evaluation_context_hash,
            evaluation_time,
            recorded_event_id,
            recorded_at
        FROM evaluation_contexts
        WHERE organization_id = $1 AND {lookup_column} = $2{lock}
        "#,
    );
    sqlx::query_as(&statement)
        .bind(organization_id)
        .bind(lookup_value)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(StoreError::Database)
}

fn map_context_insert_error(
    error: sqlx::Error,
    input: &EvaluationContextPersistence,
) -> StoreError {
    match error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .as_deref()
    {
        Some("23505") => StoreError::EvaluationContextConflict {
            organization_id: input.organization_id.clone(),
            intent_id: input.context.intent_id().into(),
        },
        _ => StoreError::Database(error),
    }
}

fn corrupt(organization_id: &str, reason: impl Into<String>) -> StoreError {
    StoreError::DurableStateCorrupt {
        organization_id: organization_id.into(),
        reason: reason.into(),
    }
}
