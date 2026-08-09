use crate::operator::authorize_audit_read_and_load_chain;
use crate::{Store, StoreError};
use atf_audit::{AuditEvent, EventType, NewAuditEvent};
use atf_core::{sha256_hex, sort_json_keys, Timestamp};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};

const AUDIT_EVENT_SCHEMA_VERSION: i32 = 1;
const AUDIT_QUERY_CURSOR_VERSION: u8 = 1;
const AUDIT_QUERY_HASH_DOMAIN: &[u8] = b"ATF_AUDIT_QUERY_V1\0";
const MAX_QUERY_IDENTIFIER_BYTES: usize = 128;
pub const DEFAULT_AUDIT_QUERY_PAGE_SIZE: u16 = 50;
pub const MAX_AUDIT_QUERY_PAGE_SIZE: u16 = 100;

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

/// Closed, organization-bound filters and page boundary for one Audit read.
/// All filters are conjunctive and time bounds are inclusive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditQuery {
    organization_id: String,
    intent_id: Option<String>,
    agent_id: Option<String>,
    event_type: Option<EventType>,
    occurred_from: Option<Timestamp>,
    occurred_to: Option<Timestamp>,
    limit: u16,
    cursor: Option<AuditQueryCursor>,
}

/// Opaque transport cursor payload. Canonical bytes bind every filter plus
/// the immutable organization-chain prefix selected by the first page.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditQueryCursor {
    schema_version: u8,
    organization_id: String,
    query_hash: String,
    after_sequence: i64,
    through_sequence: i64,
    through_event_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAuditChainSnapshot {
    pub through_sequence: i64,
    pub through_event_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditQueryPage {
    pub organization_id: String,
    pub chain: VerifiedAuditChainSnapshot,
    pub events: Vec<StoredAuditEvent>,
    pub limit: u16,
    pub next_cursor: Option<AuditQueryCursor>,
}

#[derive(Debug, Serialize)]
struct AuditQueryBinding<'a> {
    organization_id: &'a str,
    intent_id: Option<&'a str>,
    agent_id: Option<&'a str>,
    event_type: Option<EventType>,
    occurred_from: Option<Timestamp>,
    occurred_to: Option<Timestamp>,
}

#[derive(Debug, FromRow)]
pub(crate) struct AuditEventRow {
    pub(crate) sequence: i64,
    pub(crate) event_id: String,
    pub(crate) event_type: String,
    pub(crate) schema_version: i32,
    pub(crate) occurred_at: DateTime<Utc>,
    pub(crate) intent_id: Option<String>,
    pub(crate) evaluation_id: Option<String>,
    pub(crate) decision_id: Option<String>,
    pub(crate) previous_event_hash: Option<String>,
    pub(crate) event_hash: String,
    pub(crate) canonical_event: Value,
    pub(crate) canonical_event_bytes: Vec<u8>,
}

/// One atomic PostgreSQL snapshot of the chain head and its events. The
/// nullable event columns preserve an empty chain, while repeating the head
/// alongside every event keeps both sides of verification in one statement
/// snapshot even inside a `READ COMMITTED` write transaction.
#[derive(Debug, FromRow)]
struct AuditChainReadRow {
    head_sequence: Option<i64>,
    head_event_hash: Option<String>,
    sequence: Option<i64>,
    event_id: Option<String>,
    event_type: Option<String>,
    schema_version: Option<i32>,
    occurred_at: Option<DateTime<Utc>>,
    intent_id: Option<String>,
    evaluation_id: Option<String>,
    decision_id: Option<String>,
    previous_event_hash: Option<String>,
    event_hash: Option<String>,
    canonical_event: Option<Value>,
    canonical_event_bytes: Option<Vec<u8>>,
}

impl AuditQuery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: impl Into<String>,
        intent_id: Option<String>,
        agent_id: Option<String>,
        event_type: Option<EventType>,
        occurred_from: Option<Timestamp>,
        occurred_to: Option<Timestamp>,
        limit: u16,
        cursor: Option<AuditQueryCursor>,
    ) -> Result<Self, StoreError> {
        let query = Self {
            organization_id: organization_id.into(),
            intent_id,
            agent_id,
            event_type,
            occurred_from,
            occurred_to,
            limit,
            cursor,
        };
        query.validate()?;
        Ok(query)
    }

    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    fn validate(&self) -> Result<(), StoreError> {
        validate_query_identifier("organization_id", &self.organization_id)?;
        if let Some(intent_id) = &self.intent_id {
            validate_query_identifier("intent_id", intent_id)?;
        }
        if let Some(agent_id) = &self.agent_id {
            validate_query_identifier("agent_id", agent_id)?;
        }
        for (field, timestamp) in [
            ("occurred_from", self.occurred_from),
            ("occurred_to", self.occurred_to),
        ] {
            if timestamp
                .is_some_and(|value| value.as_datetime().timestamp_subsec_nanos() % 1_000_000 != 0)
            {
                return Err(invalid_query(format!(
                    "{field} must use canonical millisecond precision"
                )));
            }
        }
        if self
            .occurred_from
            .zip(self.occurred_to)
            .is_some_and(|(from, to)| from > to)
        {
            return Err(invalid_query("occurred_from must not exceed occurred_to"));
        }
        if !(1..=MAX_AUDIT_QUERY_PAGE_SIZE).contains(&self.limit) {
            return Err(invalid_query(format!(
                "Audit query limit must be within 1..={MAX_AUDIT_QUERY_PAGE_SIZE}"
            )));
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
            if cursor.organization_id != self.organization_id
                || cursor.query_hash != self.binding_hash()?
            {
                return Err(invalid_query(
                    "Audit cursor does not match the organization or filters",
                ));
            }
        }
        Ok(())
    }

    fn binding_hash(&self) -> Result<String, StoreError> {
        let binding = AuditQueryBinding {
            organization_id: &self.organization_id,
            intent_id: self.intent_id.as_deref(),
            agent_id: self.agent_id.as_deref(),
            event_type: self.event_type,
            occurred_from: self.occurred_from,
            occurred_to: self.occurred_to,
        };
        let value = serde_json::to_value(binding)?;
        let canonical = serde_json::to_vec(&sort_json_keys(value))?;
        let mut bytes = Vec::with_capacity(AUDIT_QUERY_HASH_DOMAIN.len() + canonical.len());
        bytes.extend_from_slice(AUDIT_QUERY_HASH_DOMAIN);
        bytes.extend_from_slice(&canonical);
        Ok(sha256_hex(&bytes))
    }

    fn matches(&self, stored: &StoredAuditEvent) -> bool {
        self.intent_id
            .as_deref()
            .is_none_or(|intent_id| stored.event.intent_id.as_deref() == Some(intent_id))
            && self.agent_id.as_deref().is_none_or(|agent_id| {
                stored.event.data.get("agent_id").and_then(Value::as_str) == Some(agent_id)
            })
            && self
                .event_type
                .is_none_or(|event_type| stored.event.event_type == event_type)
            && self
                .occurred_from
                .is_none_or(|from| stored.event.occurred_at >= from)
            && self
                .occurred_to
                .is_none_or(|to| stored.event.occurred_at <= to)
    }
}

impl AuditQueryCursor {
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, StoreError> {
        let cursor: Self = serde_json::from_slice(bytes)
            .map_err(|_| invalid_query("Audit cursor is not valid canonical JSON"))?;
        cursor.validate()?;
        if cursor.canonical_bytes()? != bytes {
            return Err(invalid_query("Audit cursor bytes are not canonical"));
        }
        Ok(cursor)
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StoreError> {
        let value = serde_json::to_value(self)?;
        Ok(serde_json::to_vec(&sort_json_keys(value))?)
    }

    fn validate(&self) -> Result<(), StoreError> {
        if self.schema_version != AUDIT_QUERY_CURSOR_VERSION {
            return Err(invalid_query("Audit cursor version is unsupported"));
        }
        validate_query_identifier("cursor.organization_id", &self.organization_id)?;
        validate_sha256("cursor.query_hash", &self.query_hash)?;
        if self.after_sequence < 0
            || self.through_sequence < 0
            || self.after_sequence > self.through_sequence
        {
            return Err(invalid_query("Audit cursor sequence range is invalid"));
        }
        match (self.through_sequence, &self.through_event_hash) {
            (0, None) if self.after_sequence == 0 => Ok(()),
            (sequence, Some(hash)) if sequence > 0 => {
                validate_sha256("cursor.through_event_hash", hash)
            }
            _ => Err(invalid_query(
                "Audit cursor chain sequence and hash are inconsistent",
            )),
        }
    }
}

impl Store {
    /// Append one event while serializing only this organization's chain.
    /// PostgreSQL is the sole authority; there is no process-local fallback.
    pub async fn append_audit_event(
        &self,
        organization_id: &str,
        event: NewAuditEvent,
    ) -> Result<StoredAuditEvent, StoreError> {
        if event.event_type.requires_atomic_state_transaction() {
            return Err(StoreError::InvalidAuditEvent {
                reason: "lifecycle events require an atomic state transaction",
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

    /// Reauthorize the current durable Operator role, verify the complete
    /// declared organization chain, then return one bounded stable page from
    /// that immutable prefix. Authorization and chain verification share one
    /// repeatable-read snapshot.
    pub async fn query_verified_audit_events(
        &self,
        operator_id: &str,
        query: AuditQuery,
    ) -> Result<AuditQueryPage, StoreError> {
        query.validate()?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '30s'")
            .execute(&mut *transaction)
            .await?;

        let chain = authorize_audit_read_and_load_chain(
            &mut transaction,
            operator_id,
            query.organization_id(),
        )
        .await?;
        let current_snapshot = VerifiedAuditChainSnapshot {
            through_sequence: chain.last().map_or(0, |event| event.sequence),
            through_event_hash: chain.last().map(|event| event.event_hash.clone()),
        };
        let (after_sequence, snapshot) = match &query.cursor {
            Some(cursor) => {
                verify_cursor_snapshot(cursor, &chain)?;
                (
                    cursor.after_sequence,
                    VerifiedAuditChainSnapshot {
                        through_sequence: cursor.through_sequence,
                        through_event_hash: cursor.through_event_hash.clone(),
                    },
                )
            }
            None => (0, current_snapshot),
        };

        let take = usize::from(query.limit) + 1;
        let mut matching: Vec<StoredAuditEvent> = chain
            .into_iter()
            .filter(|event| {
                event.sequence > after_sequence
                    && event.sequence <= snapshot.through_sequence
                    && query.matches(event)
            })
            .take(take)
            .collect();
        let has_more = matching.len() > usize::from(query.limit);
        if has_more {
            matching.pop();
        }
        let next_cursor = if has_more {
            let last_sequence = matching
                .last()
                .expect("a page with more results contains its requested limit")
                .sequence;
            Some(AuditQueryCursor {
                schema_version: AUDIT_QUERY_CURSOR_VERSION,
                organization_id: query.organization_id.clone(),
                query_hash: query.binding_hash()?,
                after_sequence: last_sequence,
                through_sequence: snapshot.through_sequence,
                through_event_hash: snapshot.through_event_hash.clone(),
            })
        } else {
            None
        };

        transaction.commit().await?;
        Ok(AuditQueryPage {
            organization_id: query.organization_id,
            chain: snapshot,
            events: matching,
            limit: query.limit,
            next_cursor,
        })
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

    let snapshot: Vec<AuditChainReadRow> = sqlx::query_as(
        r#"
        WITH organization_head AS (
            SELECT
                last_sequence AS head_sequence,
                last_event_hash::text AS head_event_hash
            FROM audit_chain_heads
            WHERE organization_id = $1
        ), organization_events AS (
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
        )
        SELECT
            head.head_sequence,
            head.head_event_hash,
            event.sequence,
            event.event_id,
            event.event_type,
            event.schema_version,
            event.occurred_at,
            event.intent_id,
            event.evaluation_id,
            event.decision_id,
            event.previous_event_hash,
            event.event_hash,
            event.canonical_event,
            event.canonical_event_bytes
        FROM organization_head AS head
        FULL OUTER JOIN organization_events AS event ON TRUE
        ORDER BY event.sequence
        "#,
    )
    .bind(organization_id)
    .fetch_all(&mut **transaction)
    .await?;

    let head = snapshot.first().and_then(AuditChainReadRow::head);
    if snapshot.iter().any(|row| row.head() != head) {
        return Err(corrupt(
            organization_id,
            "one Audit snapshot returned inconsistent chain heads",
        ));
    }
    let rows = snapshot
        .into_iter()
        .filter_map(|row| row.into_event_row(organization_id).transpose())
        .collect::<Result<Vec<_>, _>>()?;

    verify_rows(organization_id, head, rows)
}

impl AuditChainReadRow {
    fn head(&self) -> Option<(i64, Option<String>)> {
        self.head_sequence
            .map(|sequence| (sequence, self.head_event_hash.clone()))
    }

    fn into_event_row(self, organization_id: &str) -> Result<Option<AuditEventRow>, StoreError> {
        let Some(sequence) = self.sequence else {
            return Ok(None);
        };
        let missing = |column: &str| {
            corrupt(
                organization_id,
                format!("Audit sequence {sequence} is missing required column `{column}`"),
            )
        };
        Ok(Some(AuditEventRow {
            sequence,
            event_id: self.event_id.ok_or_else(|| missing("event_id"))?,
            event_type: self.event_type.ok_or_else(|| missing("event_type"))?,
            schema_version: self
                .schema_version
                .ok_or_else(|| missing("schema_version"))?,
            occurred_at: self.occurred_at.ok_or_else(|| missing("occurred_at"))?,
            intent_id: self.intent_id,
            evaluation_id: self.evaluation_id,
            decision_id: self.decision_id,
            previous_event_hash: self.previous_event_hash,
            event_hash: self.event_hash.ok_or_else(|| missing("event_hash"))?,
            canonical_event: self
                .canonical_event
                .ok_or_else(|| missing("canonical_event"))?,
            canonical_event_bytes: self
                .canonical_event_bytes
                .ok_or_else(|| missing("canonical_event_bytes"))?,
        }))
    }
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

pub(crate) fn verify_row_contents(
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

fn verify_cursor_snapshot(
    cursor: &AuditQueryCursor,
    chain: &[StoredAuditEvent],
) -> Result<(), StoreError> {
    cursor.validate()?;
    if cursor.through_sequence == 0 {
        return Ok(());
    }
    let index = usize::try_from(cursor.through_sequence - 1)
        .map_err(|_| invalid_query("Audit cursor sequence cannot index the chain"))?;
    let matches = chain.get(index).is_some_and(|event| {
        event.sequence == cursor.through_sequence
            && cursor.through_event_hash.as_deref() == Some(event.event_hash.as_str())
    });
    if matches {
        Ok(())
    } else {
        Err(invalid_query(
            "Audit cursor snapshot is not a prefix of the verified organization chain",
        ))
    }
}

fn validate_query_identifier(field: &str, value: &str) -> Result<(), StoreError> {
    if !(1..=MAX_QUERY_IDENTIFIER_BYTES).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err(invalid_query(format!(
            "{field} must be 1..={MAX_QUERY_IDENTIFIER_BYTES} canonical ASCII bytes"
        )));
    }
    Ok(())
}

fn validate_sha256(field: &str, value: &str) -> Result<(), StoreError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid_query(format!(
            "{field} must be a lowercase SHA-256 hex digest"
        )));
    }
    Ok(())
}

fn invalid_query(reason: impl Into<String>) -> StoreError {
    StoreError::InvalidRepositoryInput {
        reason: reason.into(),
    }
}

fn corrupt(organization_id: &str, reason: impl Into<String>) -> StoreError {
    StoreError::AuditChainCorrupt {
        organization_id: organization_id.to_owned(),
        reason: reason.into(),
    }
}
