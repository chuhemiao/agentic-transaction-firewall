use crate::models::{
    EvaluatorLease, FinalizationInput, IdempotencyReservation, IdempotencyResult, IdempotencyState,
};
use crate::{Store, StoreError};
use atf_core::Timestamp;
use atf_decision::DecisionKind;
use atf_intent::TransactionIntent;
use chrono::{DateTime, Utc};
use sqlx::{FromRow, Postgres, Transaction};
use std::time::Duration;

const MAX_LEASE_MILLIS: u64 = 5 * 60 * 1_000;

#[derive(Debug, FromRow)]
pub(crate) struct IdempotencyRow {
    organization_id: String,
    idempotency_key: String,
    intent_id: String,
    intent_hash: String,
    state: String,
    lease_owner: String,
    lease_generation: i64,
    lease_expires_at: DateTime<Utc>,
    result_evaluation_id: Option<String>,
    result_decision_id: Option<String>,
    result_decision_hash: Option<String>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    completed_at: Option<DateTime<Utc>>,
}

pub(crate) async fn reserve_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    intent: &TransactionIntent,
    intent_hash: &str,
    lease_duration: Duration,
) -> Result<EvaluatorLease, StoreError> {
    let lease_millis = lease_millis(lease_duration)?;
    let organization_id = &intent.principal.organization_id;
    let lease_owner = atf_core::new_ulid();
    let inserted: Option<IdempotencyRow> = sqlx::query_as(
        r#"
        INSERT INTO idempotency_reservations (
            organization_id,
            idempotency_key,
            intent_id,
            intent_hash,
            state,
            lease_owner,
            lease_generation,
            lease_expires_at
        ) VALUES (
            $1, $2, $3, $4, 'IN_PROGRESS', $5, 1,
            clock_timestamp() + ($6::bigint * interval '1 millisecond')
        )
        ON CONFLICT (organization_id, idempotency_key) DO NOTHING
        RETURNING
            organization_id,
            idempotency_key,
            intent_id,
            intent_hash::text AS intent_hash,
            state,
            lease_owner,
            lease_generation,
            lease_expires_at,
            result_evaluation_id,
            result_decision_id,
            result_decision_hash::text AS result_decision_hash,
            created_at,
            updated_at,
            completed_at
        "#,
    )
    .bind(organization_id)
    .bind(&intent.idempotency_key)
    .bind(&intent.intent_id)
    .bind(intent_hash)
    .bind(&lease_owner)
    .bind(lease_millis)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|error| map_reservation_insert_error(error, organization_id))?;

    let row = match inserted {
        Some(row) => row,
        None => {
            let existing = load_by_key(transaction, organization_id, &intent.idempotency_key, true)
                .await?
                .ok_or_else(|| corrupt(organization_id, "conflicting reservation disappeared"))?;
            return classify_existing(existing, intent_hash);
        }
    };
    let reservation = reservation_from_row(&row, organization_id, &intent.idempotency_key)?;
    if reservation.state != IdempotencyState::InProgress || reservation.result.is_some() {
        return Err(corrupt(
            organization_id,
            "a newly inserted reservation is not in progress",
        ));
    }

    Ok(EvaluatorLease {
        organization_id: row.organization_id,
        idempotency_key: row.idempotency_key,
        intent_id: row.intent_id,
        intent_hash: row.intent_hash,
        owner: row.lease_owner,
        generation: row.lease_generation,
        expires_at: Timestamp::from_datetime(row.lease_expires_at),
    })
}

impl Store {
    pub async fn load_idempotency_reservation(
        &self,
        organization_id: &str,
        idempotency_key: &str,
    ) -> Result<Option<IdempotencyReservation>, StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '30s'")
            .execute(&mut *transaction)
            .await?;
        let row = load_by_key(&mut transaction, organization_id, idempotency_key, false).await?;
        let reservation = row
            .as_ref()
            .map(|row| reservation_from_row(row, organization_id, idempotency_key))
            .transpose()?;
        transaction.commit().await?;
        Ok(reservation)
    }

    /// Reclaim only an expired in-progress reservation. PostgreSQL's clock is
    /// authoritative and the incremented generation fences the old evaluator.
    pub async fn reclaim_expired_idempotency(
        &self,
        organization_id: &str,
        idempotency_key: &str,
        expected_intent_hash: &str,
        lease_duration: Duration,
    ) -> Result<EvaluatorLease, StoreError> {
        let lease_millis = lease_millis(lease_duration)?;
        let lease_owner = atf_core::new_ulid();
        let mut transaction = self.pool.begin().await?;
        set_write_timeouts(&mut transaction).await?;
        let reclaimed: Option<IdempotencyRow> = sqlx::query_as(
            r#"
            UPDATE idempotency_reservations
            SET lease_owner = $4,
                lease_generation = lease_generation + 1,
                lease_expires_at = clock_timestamp()
                    + ($5::bigint * interval '1 millisecond'),
                updated_at = clock_timestamp()
            WHERE organization_id = $1
              AND idempotency_key = $2
              AND intent_hash = $3
              AND state = 'IN_PROGRESS'
              AND lease_expires_at <= clock_timestamp()
            RETURNING
                organization_id,
                idempotency_key,
                intent_id,
                intent_hash::text AS intent_hash,
                state,
                lease_owner,
                lease_generation,
                lease_expires_at,
                result_evaluation_id,
                result_decision_id,
                result_decision_hash::text AS result_decision_hash,
                created_at,
                updated_at,
                completed_at
            "#,
        )
        .bind(organization_id)
        .bind(idempotency_key)
        .bind(expected_intent_hash)
        .bind(&lease_owner)
        .bind(lease_millis)
        .fetch_optional(&mut *transaction)
        .await?;

        let row = match reclaimed {
            Some(row) => row,
            None => {
                let existing =
                    load_by_key(&mut transaction, organization_id, idempotency_key, true)
                        .await?
                        .ok_or_else(|| StoreError::IdempotencyNotFound {
                            organization_id: organization_id.to_owned(),
                            idempotency_key: idempotency_key.to_owned(),
                        })?;
                return classify_existing(existing, expected_intent_hash);
            }
        };
        let reservation = reservation_from_row(&row, organization_id, idempotency_key)?;
        if reservation.state != IdempotencyState::InProgress
            || reservation.intent_hash != expected_intent_hash
            || reservation.lease_generation <= 1
        {
            return Err(corrupt(
                organization_id,
                format!("idempotency key `{idempotency_key}` was reclaimed inconsistently"),
            ));
        }
        let lease = lease_from_row(row);
        transaction.commit().await?;
        Ok(lease)
    }

    /// Extend the current active lease without changing its fencing
    /// generation. A stale, expired, reclaimed, or completed lease fails.
    pub async fn renew_evaluator_lease(
        &self,
        lease: &EvaluatorLease,
        lease_duration: Duration,
    ) -> Result<EvaluatorLease, StoreError> {
        let lease_millis = lease_millis(lease_duration)?;
        let mut transaction = self.pool.begin().await?;
        set_write_timeouts(&mut transaction).await?;
        let renewed: Option<IdempotencyRow> = sqlx::query_as(
            r#"
            UPDATE idempotency_reservations
            SET lease_expires_at = GREATEST(
                    lease_expires_at,
                    clock_timestamp() + ($7::bigint * interval '1 millisecond')
                ),
                updated_at = clock_timestamp()
            WHERE organization_id = $1
              AND idempotency_key = $2
              AND intent_id = $3
              AND intent_hash = $4
              AND state = 'IN_PROGRESS'
              AND lease_owner = $5
              AND lease_generation = $6
              AND lease_expires_at > clock_timestamp()
            RETURNING
                organization_id,
                idempotency_key,
                intent_id,
                intent_hash::text AS intent_hash,
                state,
                lease_owner,
                lease_generation,
                lease_expires_at,
                result_evaluation_id,
                result_decision_id,
                result_decision_hash::text AS result_decision_hash,
                created_at,
                updated_at,
                completed_at
            "#,
        )
        .bind(&lease.organization_id)
        .bind(&lease.idempotency_key)
        .bind(&lease.intent_id)
        .bind(&lease.intent_hash)
        .bind(&lease.owner)
        .bind(lease.generation)
        .bind(lease_millis)
        .fetch_optional(&mut *transaction)
        .await?;
        let row = renewed.ok_or_else(|| lease_lost_from_token(lease))?;
        let reservation =
            reservation_from_row(&row, &lease.organization_id, &lease.idempotency_key)?;
        if reservation.state != IdempotencyState::InProgress
            || reservation.lease_generation != lease.generation
        {
            return Err(lease_lost_from_token(lease));
        }
        let renewed = lease_from_row(row);
        transaction.commit().await?;
        Ok(renewed)
    }
}

pub(crate) async fn verify_lease_for_finalization(
    transaction: &mut Transaction<'_, Postgres>,
    input: &FinalizationInput,
) -> Result<(), StoreError> {
    verify_active_lease(
        transaction,
        &input.organization_id,
        &input.intent_id,
        &input.expected_intent_hash,
        &input.evaluator_lease,
    )
    .await?;
    if input.evaluator_lease.generation > 1 && input.decision.decision != DecisionKind::Error {
        return Err(StoreError::RecoveredWorkMustFailClosed {
            organization_id: input.organization_id.clone(),
            intent_id: input.intent_id.clone(),
        });
    }
    Ok(())
}

pub(crate) async fn verify_active_lease(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    intent_id: &str,
    expected_intent_hash: &str,
    lease: &EvaluatorLease,
) -> Result<(), StoreError> {
    if expected_intent_hash != lease.intent_hash {
        return Err(StoreError::IntentHashMismatch {
            organization_id: organization_id.to_owned(),
            intent_id: intent_id.to_owned(),
            expected: expected_intent_hash.to_owned(),
            stored: lease.intent_hash.clone(),
        });
    }
    let row = load_by_intent(transaction, organization_id, intent_id, true)
        .await?
        .ok_or_else(|| lease_lost_from_token(lease))?;
    let reservation = reservation_from_row(&row, organization_id, &row.idempotency_key)?;
    let active: bool = sqlx::query_scalar("SELECT $1::timestamptz > clock_timestamp()")
        .bind(row.lease_expires_at)
        .fetch_one(&mut **transaction)
        .await?;
    let matches = reservation.state == IdempotencyState::InProgress
        && reservation.organization_id == lease.organization_id
        && reservation.idempotency_key == lease.idempotency_key
        && reservation.intent_id == lease.intent_id
        && reservation.intent_hash == lease.intent_hash
        && reservation.organization_id == organization_id
        && reservation.intent_id == intent_id
        && reservation.intent_hash == expected_intent_hash
        && row.lease_owner == lease.owner
        && row.lease_generation == lease.generation
        && active;
    if !matches {
        return Err(lease_lost_from_token(lease));
    }
    Ok(())
}

pub(crate) async fn complete_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    input: &FinalizationInput,
    evaluation_id: &str,
    decision_id: &str,
    decision_hash: &str,
) -> Result<IdempotencyReservation, StoreError> {
    let lease = &input.evaluator_lease;
    let row: Option<IdempotencyRow> = sqlx::query_as(
        r#"
        UPDATE idempotency_reservations
        SET state = 'COMPLETED',
            result_evaluation_id = $7,
            result_decision_id = $8,
            result_decision_hash = $9,
            updated_at = clock_timestamp(),
            completed_at = clock_timestamp()
        WHERE organization_id = $1
          AND idempotency_key = $2
          AND intent_id = $3
          AND intent_hash = $4
          AND state = 'IN_PROGRESS'
          AND lease_owner = $5
          AND lease_generation = $6
          AND lease_expires_at > clock_timestamp()
        RETURNING
            organization_id,
            idempotency_key,
            intent_id,
            intent_hash::text AS intent_hash,
            state,
            lease_owner,
            lease_generation,
            lease_expires_at,
            result_evaluation_id,
            result_decision_id,
            result_decision_hash::text AS result_decision_hash,
            created_at,
            updated_at,
            completed_at
        "#,
    )
    .bind(&lease.organization_id)
    .bind(&lease.idempotency_key)
    .bind(&lease.intent_id)
    .bind(&lease.intent_hash)
    .bind(&lease.owner)
    .bind(lease.generation)
    .bind(evaluation_id)
    .bind(decision_id)
    .bind(decision_hash)
    .fetch_optional(&mut **transaction)
    .await?;
    let row = row.ok_or_else(|| lease_lost_from_token(&input.evaluator_lease))?;
    let reservation = reservation_from_row(
        &row,
        &input.organization_id,
        &input.evaluator_lease.idempotency_key,
    )?;
    let result = reservation.result.as_ref().ok_or_else(|| {
        corrupt(
            &input.organization_id,
            "completed reservation lacks a result",
        )
    })?;
    if reservation.state != IdempotencyState::Completed
        || result.evaluation_id != evaluation_id
        || result.decision_id != decision_id
        || result.decision_hash != decision_hash
    {
        return Err(corrupt(
            &input.organization_id,
            "completed idempotency result does not match finalization",
        ));
    }
    Ok(reservation)
}

pub(crate) async fn verify_admission_binding(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    intent_id: &str,
    intent_hash: &str,
) -> Result<(), StoreError> {
    let row = load_by_intent(transaction, organization_id, intent_id, false)
        .await?
        .ok_or_else(|| StoreError::IncompleteAdmissionEvidence {
            organization_id: organization_id.to_owned(),
            intent_id: intent_id.to_owned(),
        })?;
    let reservation = reservation_from_row(&row, organization_id, &row.idempotency_key)?;
    if reservation.intent_hash != intent_hash {
        return Err(StoreError::IncompleteAdmissionEvidence {
            organization_id: organization_id.to_owned(),
            intent_id: intent_id.to_owned(),
        });
    }
    Ok(())
}

pub(crate) async fn verify_completed_binding(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    intent_id: &str,
    intent_hash: &str,
    evaluation_id: &str,
    decision_id: &str,
    decision_hash: &str,
) -> Result<(), StoreError> {
    let row = load_by_intent(transaction, organization_id, intent_id, false)
        .await?
        .ok_or_else(|| incomplete_decision(organization_id, intent_id))?;
    let reservation = reservation_from_row(&row, organization_id, &row.idempotency_key)?;
    let Some(result) = reservation.result else {
        return Err(incomplete_decision(organization_id, intent_id));
    };
    if reservation.state != IdempotencyState::Completed
        || reservation.intent_hash != intent_hash
        || result.evaluation_id != evaluation_id
        || result.decision_id != decision_id
        || result.decision_hash != decision_hash
    {
        return Err(incomplete_decision(organization_id, intent_id));
    }
    Ok(())
}

async fn load_by_key(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    idempotency_key: &str,
    for_update: bool,
) -> Result<Option<IdempotencyRow>, StoreError> {
    let statement = if for_update {
        format!("{} FOR UPDATE", SELECT_BY_KEY)
    } else {
        SELECT_BY_KEY.to_owned()
    };
    sqlx::query_as(&statement)
        .bind(organization_id)
        .bind(idempotency_key)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(StoreError::Database)
}

async fn load_by_intent(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    intent_id: &str,
    for_update: bool,
) -> Result<Option<IdempotencyRow>, StoreError> {
    let statement = if for_update {
        format!("{} FOR UPDATE", SELECT_BY_INTENT)
    } else {
        SELECT_BY_INTENT.to_owned()
    };
    sqlx::query_as(&statement)
        .bind(organization_id)
        .bind(intent_id)
        .fetch_optional(&mut **transaction)
        .await
        .map_err(StoreError::Database)
}

const SELECT_BY_KEY: &str = r#"
    SELECT
        organization_id,
        idempotency_key,
        intent_id,
        intent_hash::text AS intent_hash,
        state,
        lease_owner,
        lease_generation,
        lease_expires_at,
        result_evaluation_id,
        result_decision_id,
        result_decision_hash::text AS result_decision_hash,
        created_at,
        updated_at,
        completed_at
    FROM idempotency_reservations
    WHERE organization_id = $1 AND idempotency_key = $2
"#;

const SELECT_BY_INTENT: &str = r#"
    SELECT
        organization_id,
        idempotency_key,
        intent_id,
        intent_hash::text AS intent_hash,
        state,
        lease_owner,
        lease_generation,
        lease_expires_at,
        result_evaluation_id,
        result_decision_id,
        result_decision_hash::text AS result_decision_hash,
        created_at,
        updated_at,
        completed_at
    FROM idempotency_reservations
    WHERE organization_id = $1 AND intent_id = $2
"#;

fn classify_existing(
    row: IdempotencyRow,
    submitted_hash: &str,
) -> Result<EvaluatorLease, StoreError> {
    let reservation = reservation_from_row(&row, &row.organization_id, &row.idempotency_key)?;
    if reservation.intent_hash != submitted_hash {
        return Err(StoreError::IdempotencyConflict {
            organization_id: reservation.organization_id,
            idempotency_key: reservation.idempotency_key,
            submitted_hash: submitted_hash.to_owned(),
            stored_hash: reservation.intent_hash,
        });
    }
    match reservation.state {
        IdempotencyState::InProgress => Err(StoreError::IdempotencyInProgress {
            organization_id: reservation.organization_id,
            idempotency_key: reservation.idempotency_key,
            intent_id: reservation.intent_id,
            lease_expires_at: reservation.lease_expires_at,
        }),
        IdempotencyState::Completed => {
            let decision_id = reservation
                .result
                .ok_or_else(|| {
                    corrupt(
                        &reservation.organization_id,
                        "completed reservation lacks a result",
                    )
                })?
                .decision_id;
            Err(StoreError::IdempotencyCompleted {
                organization_id: reservation.organization_id,
                idempotency_key: reservation.idempotency_key,
                intent_id: reservation.intent_id,
                decision_id,
            })
        }
    }
}

fn reservation_from_row(
    row: &IdempotencyRow,
    expected_organization_id: &str,
    expected_idempotency_key: &str,
) -> Result<IdempotencyReservation, StoreError> {
    let state = match row.state.as_str() {
        "IN_PROGRESS" => IdempotencyState::InProgress,
        "COMPLETED" => IdempotencyState::Completed,
        _ => {
            return Err(corrupt(
                expected_organization_id,
                format!("idempotency key `{expected_idempotency_key}` has an unknown state"),
            ))
        }
    };
    if row.organization_id != expected_organization_id
        || row.idempotency_key != expected_idempotency_key
        || row.lease_generation <= 0
    {
        return Err(corrupt(
            expected_organization_id,
            format!("idempotency key `{expected_idempotency_key}` has invalid binding metadata"),
        ));
    }
    let result = match (
        &row.result_evaluation_id,
        &row.result_decision_id,
        &row.result_decision_hash,
    ) {
        (Some(evaluation_id), Some(decision_id), Some(decision_hash)) => Some(IdempotencyResult {
            evaluation_id: evaluation_id.clone(),
            decision_id: decision_id.clone(),
            decision_hash: decision_hash.clone(),
        }),
        (None, None, None) => None,
        _ => {
            return Err(corrupt(
                expected_organization_id,
                format!("idempotency key `{expected_idempotency_key}` has a partial result"),
            ))
        }
    };
    let completed_at = row.completed_at.map(Timestamp::from_datetime);
    if (state == IdempotencyState::InProgress && (result.is_some() || completed_at.is_some()))
        || (state == IdempotencyState::Completed && (result.is_none() || completed_at.is_none()))
    {
        return Err(corrupt(
            expected_organization_id,
            format!("idempotency key `{expected_idempotency_key}` has inconsistent state"),
        ));
    }

    Ok(IdempotencyReservation {
        organization_id: row.organization_id.clone(),
        idempotency_key: row.idempotency_key.clone(),
        intent_id: row.intent_id.clone(),
        intent_hash: row.intent_hash.clone(),
        state,
        lease_generation: row.lease_generation,
        lease_expires_at: Timestamp::from_datetime(row.lease_expires_at),
        result,
        created_at: Timestamp::from_datetime(row.created_at),
        updated_at: Timestamp::from_datetime(row.updated_at),
        completed_at,
    })
}

fn lease_from_row(row: IdempotencyRow) -> EvaluatorLease {
    EvaluatorLease {
        organization_id: row.organization_id,
        idempotency_key: row.idempotency_key,
        intent_id: row.intent_id,
        intent_hash: row.intent_hash,
        owner: row.lease_owner,
        generation: row.lease_generation,
        expires_at: Timestamp::from_datetime(row.lease_expires_at),
    }
}

fn lease_millis(duration: Duration) -> Result<i64, StoreError> {
    if duration < Duration::from_millis(1)
        || duration > Duration::from_millis(MAX_LEASE_MILLIS)
        || duration.subsec_nanos() % 1_000_000 != 0
    {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "evaluator lease duration must be an exact number of milliseconds between 1 millisecond and 5 minutes".into(),
        });
    }
    i64::try_from(duration.as_millis()).map_err(|_| StoreError::InvalidRepositoryInput {
        reason: "evaluator lease duration is out of range".into(),
    })
}

fn map_reservation_insert_error(error: sqlx::Error, organization_id: &str) -> StoreError {
    if error
        .as_database_error()
        .and_then(|database_error| database_error.code())
        .as_deref()
        == Some("23503")
    {
        StoreError::OrganizationNotFound {
            organization_id: organization_id.to_owned(),
        }
    } else {
        StoreError::Database(error)
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

fn lease_lost_from_token(lease: &EvaluatorLease) -> StoreError {
    StoreError::EvaluatorLeaseLost {
        organization_id: lease.organization_id.clone(),
        idempotency_key: lease.idempotency_key.clone(),
        intent_id: lease.intent_id.clone(),
        generation: lease.generation,
    }
}

fn incomplete_decision(organization_id: &str, intent_id: &str) -> StoreError {
    StoreError::IncompleteDecisionEvidence {
        organization_id: organization_id.to_owned(),
        intent_id: intent_id.to_owned(),
    }
}

fn corrupt(organization_id: &str, reason: impl Into<String>) -> StoreError {
    StoreError::DurableStateCorrupt {
        organization_id: organization_id.to_owned(),
        reason: reason.into(),
    }
}
