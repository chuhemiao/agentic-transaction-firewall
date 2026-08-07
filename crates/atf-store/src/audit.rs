use crate::{Store, StoreError};
use atf_audit::{AuditEvent, EventType, NewAuditEvent};
use atf_core::Timestamp;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};

const AUDIT_EVENT_SCHEMA_VERSION: i32 = 1;

#[derive(Debug, Default)]
pub(crate) struct AuditReferences {
    pub evaluation_id: Option<String>,
    pub decision_id: Option<String>,
}

/// A durable Audit event together with its store-owned chain position and
/// hash. Callers provide neither of those values when appending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAuditEvent {
    pub organization_id: String,
    pub sequence: i64,
    pub event_hash: String,
    pub event: AuditEvent,
    pub evaluation_id: Option<String>,
    pub decision_id: Option<String>,
}

#[derive(Debug, FromRow)]
struct AuditEventRow {
    sequence: i64,
    event_id: String,
    event_type: String,
    schema_version: i32,
    occurred_at: DateTime<Utc>,
    intent_id: Option<String>,
    evaluation_id: Option<String>,
    decision_id: Option<String>,
    previous_event_hash: Option<String>,
    event_hash: String,
    canonical_event: Value,
    canonical_event_bytes: Vec<u8>,
}

impl Store {
    /// Append one event while serializing only this organization's chain.
    /// PostgreSQL is the sole authority; there is no process-local fallback.
    pub async fn append_audit_event(
        &self,
        organization_id: &str,
        event: NewAuditEvent,
    ) -> Result<StoredAuditEvent, StoreError> {
        if event.event_type.has_lifecycle_effect() {
            return Err(StoreError::InvalidAuditEvent {
                reason: "Intent lifecycle events require an atomic state transaction",
            });
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET LOCAL lock_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '10s'")
            .execute(&mut *transaction)
            .await?;

        let stored = append_in_transaction(
            &mut transaction,
            organization_id,
            event,
            AuditReferences::default(),
        )
        .await?;
        transaction.commit().await?;
        Ok(stored)
    }

    /// Reload and fully verify one organization's committed chain, including
    /// canonical bytes/hash, redundant columns, contiguous order, predecessor
    /// links, and the durable head row.
    pub async fn load_verified_audit_chain(
        &self,
        organization_id: &str,
    ) -> Result<Vec<StoredAuditEvent>, StoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '30s'")
            .execute(&mut *transaction)
            .await?;

        let verified = load_verified_in_transaction(&mut transaction, organization_id).await?;
        transaction.commit().await?;
        Ok(verified)
    }
}

pub(crate) async fn append_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    event: NewAuditEvent,
    references: AuditReferences,
) -> Result<StoredAuditEvent, StoreError> {
    let event = event.normalized();
    validate_new_event(&event)?;
    validate_references(&event, &references)?;

    sqlx::query(
        r#"
        INSERT INTO audit_chain_heads (organization_id)
        VALUES ($1)
        ON CONFLICT (organization_id) DO NOTHING
        "#,
    )
    .bind(organization_id)
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_head_insert_error(error, organization_id))?;

    let (last_sequence, last_event_hash): (i64, Option<String>) = sqlx::query_as(
        r#"
        SELECT last_sequence, last_event_hash::text
        FROM audit_chain_heads
        WHERE organization_id = $1
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .fetch_one(&mut **transaction)
    .await?;

    verify_locked_head(
        transaction,
        organization_id,
        last_sequence,
        last_event_hash.as_deref(),
    )
    .await?;

    let sequence = last_sequence.checked_add(1).ok_or_else(|| {
        corrupt(
            organization_id,
            "chain sequence overflowed the signed 64-bit store representation",
        )
    })?;
    let event = event.chain(last_event_hash);
    let canonical_event = event.canonical_value();
    let canonical_event_bytes = event.canonical_bytes();
    let event_hash = event.canonical_hash();
    let event_type = event_type_name(event.event_type)?;

    sqlx::query(
        r#"
        INSERT INTO audit_events (
            organization_id,
            sequence,
            event_id,
            event_type,
            schema_version,
            occurred_at,
            intent_id,
            evaluation_id,
            decision_id,
            previous_event_hash,
            event_hash,
            canonical_event,
            canonical_event_bytes
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        "#,
    )
    .bind(organization_id)
    .bind(sequence)
    .bind(&event.event_id)
    .bind(&event_type)
    .bind(AUDIT_EVENT_SCHEMA_VERSION)
    .bind(event.occurred_at.as_datetime())
    .bind(&event.intent_id)
    .bind(&references.evaluation_id)
    .bind(&references.decision_id)
    .bind(&event.prev_event_hash)
    .bind(&event_hash)
    .bind(&canonical_event)
    .bind(&canonical_event_bytes)
    .execute(&mut **transaction)
    .await?;

    let updated = sqlx::query(
        r#"
        UPDATE audit_chain_heads
        SET last_sequence = $2,
            last_event_hash = $3,
            updated_at = statement_timestamp()
        WHERE organization_id = $1
        "#,
    )
    .bind(organization_id)
    .bind(sequence)
    .bind(&event_hash)
    .execute(&mut **transaction)
    .await?;
    if updated.rows_affected() != 1 {
        return Err(corrupt(
            organization_id,
            "locked chain head disappeared before it could be advanced",
        ));
    }

    Ok(StoredAuditEvent {
        organization_id: organization_id.to_owned(),
        sequence,
        event_hash,
        event,
        evaluation_id: references.evaluation_id,
        decision_id: references.decision_id,
    })
}

pub(crate) async fn load_verified_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
) -> Result<Vec<StoredAuditEvent>, StoreError> {
    let organization_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM organizations WHERE organization_id = $1)",
    )
    .bind(organization_id)
    .fetch_one(&mut **transaction)
    .await?;
    if !organization_exists {
        return Err(StoreError::OrganizationNotFound {
            organization_id: organization_id.to_owned(),
        });
    }

    let head: Option<(i64, Option<String>)> = sqlx::query_as(
        r#"
        SELECT last_sequence, last_event_hash::text
        FROM audit_chain_heads
        WHERE organization_id = $1
        "#,
    )
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await?;

    let rows: Vec<AuditEventRow> = sqlx::query_as(
        r#"
        SELECT
            sequence,
            event_id,
            event_type,
            schema_version,
            occurred_at,
            intent_id,
            evaluation_id,
            decision_id,
            previous_event_hash::text AS previous_event_hash,
            event_hash::text AS event_hash,
            canonical_event,
            canonical_event_bytes
        FROM audit_events
        WHERE organization_id = $1
        ORDER BY sequence
        "#,
    )
    .bind(organization_id)
    .fetch_all(&mut **transaction)
    .await?;

    verify_rows(organization_id, head, rows)
}

async fn verify_locked_head(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    last_sequence: i64,
    last_event_hash: Option<&str>,
) -> Result<(), StoreError> {
    let tail: Option<AuditEventRow> = sqlx::query_as(
        r#"
        SELECT
            sequence,
            event_id,
            event_type,
            schema_version,
            occurred_at,
            intent_id,
            evaluation_id,
            decision_id,
            previous_event_hash::text AS previous_event_hash,
            event_hash::text AS event_hash,
            canonical_event,
            canonical_event_bytes
        FROM audit_events
        WHERE organization_id = $1
        ORDER BY sequence DESC
        LIMIT 1
        "#,
    )
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await?;

    match (last_sequence, last_event_hash, tail) {
        (0, None, None) => {}
        (head_sequence, Some(head_hash), Some(tail))
            if head_sequence == tail.sequence && head_hash == tail.event_hash =>
        {
            verify_row_contents(organization_id, &tail)?;
        }
        _ => {
            return Err(corrupt(
                organization_id,
                "locked chain head does not match the last committed event",
            ));
        }
    }
    Ok(())
}

fn verify_rows(
    organization_id: &str,
    head: Option<(i64, Option<String>)>,
    rows: Vec<AuditEventRow>,
) -> Result<Vec<StoredAuditEvent>, StoreError> {
    let mut events = Vec::with_capacity(rows.len());
    let mut expected_previous_hash: Option<String> = None;

    for (expected_sequence, row) in (1_i64..).zip(rows) {
        if row.sequence != expected_sequence {
            return Err(corrupt(
                organization_id,
                format!(
                    "expected sequence {expected_sequence}, found {}",
                    row.sequence
                ),
            ));
        }
        let event = verify_row_contents(organization_id, &row)?;
        if row.previous_event_hash != expected_previous_hash {
            return Err(corrupt(
                organization_id,
                format!("sequence {} has the wrong predecessor", row.sequence),
            ));
        }
        expected_previous_hash = Some(row.event_hash.clone());
        events.push(StoredAuditEvent {
            organization_id: organization_id.to_owned(),
            sequence: row.sequence,
            event_hash: row.event_hash,
            event,
            evaluation_id: row.evaluation_id,
            decision_id: row.decision_id,
        });
    }

    let expected_head = if events.is_empty() {
        (0, None)
    } else {
        (
            events.last().expect("non-empty chain has a tail").sequence,
            expected_previous_hash,
        )
    };
    match head {
        None if events.is_empty() => {}
        Some(actual_head) if actual_head == expected_head => {}
        _ => {
            return Err(corrupt(
                organization_id,
                "chain head does not match the fully verified event sequence",
            ));
        }
    }

    Ok(events)
}

fn verify_row_contents(
    organization_id: &str,
    row: &AuditEventRow,
) -> Result<AuditEvent, StoreError> {
    if row.schema_version != AUDIT_EVENT_SCHEMA_VERSION {
        return Err(corrupt(
            organization_id,
            format!(
                "sequence {} uses unsupported Audit schema version {}",
                row.sequence, row.schema_version
            ),
        ));
    }

    let event: AuditEvent =
        serde_json::from_value(row.canonical_event.clone()).map_err(|error| {
            corrupt(
                organization_id,
                format!(
                    "sequence {} canonical event cannot be decoded: {error}",
                    row.sequence
                ),
            )
        })?;
    let event_type = event_type_name(event.event_type)?;
    let columns_match = row.canonical_event == event.canonical_value()
        && row.canonical_event_bytes == event.canonical_bytes()
        && row.event_id == event.event_id
        && row.event_type == event_type
        && Timestamp::from_datetime(row.occurred_at) == event.occurred_at
        && row.intent_id == event.intent_id
        && row.previous_event_hash == event.prev_event_hash;
    if !columns_match {
        return Err(corrupt(
            organization_id,
            format!(
                "sequence {} canonical event, bytes, or redundant columns disagree",
                row.sequence
            ),
        ));
    }
    if row.event_hash != event.canonical_hash() {
        return Err(corrupt(
            organization_id,
            format!("sequence {} has the wrong event hash", row.sequence),
        ));
    }
    Ok(event)
}

fn validate_new_event(event: &NewAuditEvent) -> Result<(), StoreError> {
    if event.event_id.trim() != event.event_id
        || event.event_id.is_empty()
        || event.event_id.len() > 128
    {
        return Err(StoreError::InvalidAuditEvent {
            reason: "event_id must be 1..128 trimmed bytes",
        });
    }
    if !event.data.is_object() {
        return Err(StoreError::InvalidAuditEvent {
            reason: "data must be a JSON object",
        });
    }
    Ok(())
}

fn validate_references(
    event: &NewAuditEvent,
    references: &AuditReferences,
) -> Result<(), StoreError> {
    if references.evaluation_id.is_some() && event.intent_id.is_none() {
        return Err(StoreError::InvalidAuditEvent {
            reason: "evaluation_id requires intent_id",
        });
    }
    if references.decision_id.is_some() && references.evaluation_id.is_none() {
        return Err(StoreError::InvalidAuditEvent {
            reason: "decision_id requires evaluation_id and intent_id",
        });
    }
    Ok(())
}

fn event_type_name(event_type: EventType) -> Result<String, StoreError> {
    let value = serde_json::to_value(event_type)?;
    value
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or(StoreError::InvalidAuditEvent {
            reason: "event_type must serialize as a string",
        })
}

fn map_head_insert_error(error: sqlx::Error, organization_id: &str) -> StoreError {
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

fn corrupt(organization_id: &str, reason: impl Into<String>) -> StoreError {
    StoreError::AuditChainCorrupt {
        organization_id: organization_id.to_owned(),
        reason: reason.into(),
    }
}
