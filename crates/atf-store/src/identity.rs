use atf_audit::{
    AgentRegisteredPayload, AgentStatusChangedPayload, AuditPayload, EventType,
    IdentityKeyRegisteredPayload, IdentityKeyRevokedPayload, NewAuditEvent,
};
use atf_core::Timestamp;
use atf_identity::{
    AgentRecord, AgentStatus, EnvelopeVerificationContext, IdentityEnvelope, IdentityError,
    IdentityKeyRecord, IdentityRegistry, VerifiedIdentity,
};
use atf_intent::TransactionIntent;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};

use crate::audit::{append_in_transaction, load_verified_in_transaction, AuditReferences};
use crate::{Store, StoreError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredAgent {
    pub record: AgentRecord,
    pub lifecycle_version: i64,
    pub last_event_id: String,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredIdentityKey {
    pub organization_id: String,
    pub record: IdentityKeyRecord,
    pub key_record_hash: String,
    pub lifecycle_version: i64,
    pub last_event_id: String,
    pub registered_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentitySnapshot {
    agent: StoredAgent,
    key: StoredIdentityKey,
}

impl IdentitySnapshot {
    pub fn agent(&self) -> &StoredAgent {
        &self.agent
    }

    pub fn key(&self) -> &StoredIdentityKey {
        &self.key
    }

    pub fn verify_envelope(
        &self,
        intent: &TransactionIntent,
        envelope: &IdentityEnvelope,
        signature_bytes: &[u8; 64],
        context: &EnvelopeVerificationContext<'_>,
    ) -> Result<VerifiedIdentity, IdentityError> {
        let mut registry = IdentityRegistry::new();
        registry.register_agent(self.agent.record.clone())?;
        registry.register_key(self.key.record.clone())?;
        registry.verify_envelope(intent, envelope, signature_bytes, context)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalIdentityKey {
    organization_id: String,
    agent_id: String,
    key_id: String,
    algorithm: String,
    public_key_hex: String,
    activates_at: Timestamp,
    expires_at: Option<Timestamp>,
    revoked_at: Option<Timestamp>,
}

#[derive(Debug, FromRow)]
struct AgentRow {
    organization_id: String,
    agent_id: String,
    canonical_record: Value,
    canonical_record_bytes: Vec<u8>,
    record_hash: String,
    status: String,
    lifecycle_version: i64,
    last_event_id: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct IdentityKeyRow {
    organization_id: String,
    agent_id: String,
    key_id: String,
    algorithm: String,
    public_key: Vec<u8>,
    public_key_fingerprint: String,
    canonical_record: Value,
    canonical_record_bytes: Vec<u8>,
    key_record_hash: String,
    activates_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
    lifecycle_version: i64,
    last_event_id: String,
    registered_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl Store {
    pub async fn provision_agent(
        &self,
        record: AgentRecord,
        actor_id: &str,
        occurred_at: Timestamp,
    ) -> Result<StoredAgent, StoreError> {
        record
            .validate()
            .map_err(|error| invalid(error.to_string()))?;
        validate_identifier("actor_id", actor_id)?;
        validate_timestamp("occurred_at", occurred_at)?;
        if occurred_at < record.created_at
            || record
                .expires_at
                .is_some_and(|expires_at| expires_at <= occurred_at)
        {
            return Err(invalid(
                "occurred_at must fall within the Agent registration lifetime",
            ));
        }

        let mut transaction = self.pool.begin().await?;
        set_mutation_timeouts(&mut transaction).await?;
        ensure_organization(&mut transaction, &record.organization_id).await?;

        let record_hash = record.canonical_hash();
        let payload = AuditPayload::AgentRegistered(AgentRegisteredPayload {
            organization_id: record.organization_id.clone(),
            agent_id: record.agent_id.clone(),
            status: status_name(record.status).to_owned(),
            record_hash: record_hash.clone(),
            lifecycle_version: 1,
            actor_id: actor_id.to_owned(),
        });
        let event = NewAuditEvent::from_payload(occurred_at, None, payload)?;
        let stored_event = append_in_transaction(
            &mut transaction,
            &record.organization_id,
            event,
            AuditReferences::default(),
        )
        .await?;

        let canonical_record = atf_core::sort_json_keys(serde_json::to_value(&record)?);
        let canonical_record_bytes = record.canonical_bytes();
        let inserted = sqlx::query(
            r#"
            INSERT INTO agents (
                organization_id, agent_id, canonical_record,
                canonical_record_bytes, record_hash, status,
                lifecycle_version, last_event_id, created_at,
                expires_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, 1, $7, $8, $9, $10)
            ON CONFLICT (organization_id, agent_id) DO NOTHING
            "#,
        )
        .bind(&record.organization_id)
        .bind(&record.agent_id)
        .bind(&canonical_record)
        .bind(&canonical_record_bytes)
        .bind(&record_hash)
        .bind(status_name(record.status))
        .bind(&stored_event.event.event_id)
        .bind(record.created_at.as_datetime())
        .bind(record.expires_at.map(|value| value.as_datetime()))
        .bind(occurred_at.as_datetime())
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(StoreError::AgentConflict {
                organization_id: record.organization_id,
                agent_id: record.agent_id,
            });
        }

        transaction.commit().await?;
        Ok(StoredAgent {
            record,
            lifecycle_version: 1,
            last_event_id: stored_event.event.event_id,
            updated_at: occurred_at,
        })
    }

    pub async fn load_agent(
        &self,
        organization_id: &str,
        agent_id: &str,
    ) -> Result<StoredAgent, StoreError> {
        validate_identifier("organization_id", organization_id)?;
        validate_identifier("agent_id", agent_id)?;

        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '30s'")
            .execute(&mut *transaction)
            .await?;

        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let row = fetch_agent(&mut transaction, organization_id, agent_id).await?;
        let stored = verify_agent_row(row, &chain)?;
        transaction.commit().await?;
        Ok(stored)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn set_agent_status(
        &self,
        organization_id: &str,
        agent_id: &str,
        status: AgentStatus,
        actor_id: &str,
        reason_code: &str,
        occurred_at: Timestamp,
    ) -> Result<StoredAgent, StoreError> {
        validate_identifier("organization_id", organization_id)?;
        validate_identifier("agent_id", agent_id)?;
        validate_identifier("actor_id", actor_id)?;
        validate_identifier("reason_code", reason_code)?;
        validate_timestamp("occurred_at", occurred_at)?;

        let mut transaction = self.pool.begin().await?;
        set_mutation_timeouts(&mut transaction).await?;
        let row = fetch_agent_for_update(&mut transaction, organization_id, agent_id).await?;
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let current = verify_agent_row(row, &chain)?;
        current.record.status.validate_transition_to(status)?;
        if occurred_at < current.updated_at {
            return Err(invalid(
                "occurred_at cannot precede the current Agent lifecycle version",
            ));
        }

        let mut record = current.record.clone();
        let previous_status = record.status;
        record.status = status;
        record.validate()?;
        let lifecycle_version = current
            .lifecycle_version
            .checked_add(1)
            .ok_or_else(|| invalid("Agent lifecycle version overflow"))?;
        let audit_version = u64::try_from(lifecycle_version)
            .map_err(|_| invalid("Agent lifecycle version is outside the Audit representation"))?;
        let record_hash = record.canonical_hash();
        let payload = AuditPayload::AgentStatusChanged(AgentStatusChangedPayload {
            organization_id: organization_id.to_owned(),
            agent_id: agent_id.to_owned(),
            previous_status: status_name(previous_status).to_owned(),
            status: status_name(status).to_owned(),
            record_hash: record_hash.clone(),
            lifecycle_version: audit_version,
            actor_id: actor_id.to_owned(),
            reason_code: reason_code.to_owned(),
        });
        let event = NewAuditEvent::from_payload(occurred_at, None, payload)?;
        let stored_event = append_in_transaction(
            &mut transaction,
            organization_id,
            event,
            AuditReferences::default(),
        )
        .await?;

        let canonical_record = atf_core::sort_json_keys(serde_json::to_value(&record)?);
        let updated = sqlx::query(
            r#"
            UPDATE agents
            SET canonical_record = $4,
                canonical_record_bytes = $5,
                record_hash = $6,
                status = $7,
                lifecycle_version = $8,
                last_event_id = $9,
                updated_at = $10
            WHERE organization_id = $1
              AND agent_id = $2
              AND lifecycle_version = $3
            "#,
        )
        .bind(organization_id)
        .bind(agent_id)
        .bind(current.lifecycle_version)
        .bind(&canonical_record)
        .bind(record.canonical_bytes())
        .bind(&record_hash)
        .bind(status_name(status))
        .bind(lifecycle_version)
        .bind(&stored_event.event.event_id)
        .bind(occurred_at.as_datetime())
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::IdentityStateCorrupt {
                organization_id: organization_id.to_owned(),
                agent_id: agent_id.to_owned(),
                reason: "locked Agent lifecycle version changed before update".into(),
            });
        }

        transaction.commit().await?;
        Ok(StoredAgent {
            record,
            lifecycle_version,
            last_event_id: stored_event.event.event_id,
            updated_at: occurred_at,
        })
    }

    pub async fn register_identity_key(
        &self,
        organization_id: &str,
        record: IdentityKeyRecord,
        actor_id: &str,
        occurred_at: Timestamp,
    ) -> Result<StoredIdentityKey, StoreError> {
        validate_identifier("organization_id", organization_id)?;
        validate_identifier("actor_id", actor_id)?;
        validate_timestamp("occurred_at", occurred_at)?;
        record.validate()?;
        if record.revoked_at.is_some() {
            return Err(invalid("a newly registered identity key cannot be revoked"));
        }

        let mut transaction = self.pool.begin().await?;
        set_mutation_timeouts(&mut transaction).await?;
        let agent_row =
            fetch_agent_for_update(&mut transaction, organization_id, &record.agent_id).await?;
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let agent = verify_agent_row(agent_row, &chain)?;
        if matches!(
            agent.record.status,
            AgentStatus::Revoked | AgentStatus::Expired
        ) {
            return Err(invalid("terminal Agents cannot receive identity keys"));
        }
        if record.activates_at < agent.record.created_at
            || agent.record.expires_at.is_some_and(|agent_expiry| {
                record
                    .expires_at
                    .is_none_or(|key_expiry| key_expiry > agent_expiry)
            })
            || agent
                .record
                .expires_at
                .is_some_and(|agent_expiry| occurred_at >= agent_expiry)
        {
            return Err(invalid(
                "identity key validity must be contained by the Agent lifetime",
            ));
        }

        let canonical_key = canonical_key(organization_id, &record);
        let canonical_record = atf_core::sort_json_keys(serde_json::to_value(&canonical_key)?);
        let canonical_record_bytes = serde_json::to_vec(&canonical_record)?;
        let key_record_hash = atf_core::sha256_hex(&canonical_record_bytes);
        let public_key_fingerprint = record.public_key_fingerprint();
        let payload = AuditPayload::IdentityKeyRegistered(IdentityKeyRegisteredPayload {
            organization_id: organization_id.to_owned(),
            agent_id: record.agent_id.clone(),
            key_id: record.key_id.clone(),
            algorithm: "ED25519".into(),
            public_key_fingerprint: public_key_fingerprint.clone(),
            key_record_hash: key_record_hash.clone(),
            activates_at: record.activates_at,
            expires_at: record.expires_at,
            lifecycle_version: 1,
            actor_id: actor_id.to_owned(),
        });
        let event = NewAuditEvent::from_payload(occurred_at, None, payload)?;
        let stored_event = append_in_transaction(
            &mut transaction,
            organization_id,
            event,
            AuditReferences::default(),
        )
        .await?;

        let inserted = sqlx::query(
            r#"
            INSERT INTO identity_keys (
                organization_id, agent_id, key_id, algorithm,
                public_key, public_key_fingerprint, canonical_record,
                canonical_record_bytes, key_record_hash, activates_at,
                expires_at, revoked_at, lifecycle_version, last_event_id,
                registered_at, updated_at
            ) VALUES (
                $1, $2, $3, 'ED25519', $4, $5, $6, $7, $8,
                $9, $10, NULL, 1, $11, $12, $12
            )
            ON CONFLICT (organization_id, agent_id, key_id) DO NOTHING
            "#,
        )
        .bind(organization_id)
        .bind(&record.agent_id)
        .bind(&record.key_id)
        .bind(record.public_key_bytes().as_slice())
        .bind(&public_key_fingerprint)
        .bind(&canonical_record)
        .bind(&canonical_record_bytes)
        .bind(&key_record_hash)
        .bind(record.activates_at.as_datetime())
        .bind(record.expires_at.map(|value| value.as_datetime()))
        .bind(&stored_event.event.event_id)
        .bind(occurred_at.as_datetime())
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(StoreError::IdentityKeyConflict {
                organization_id: organization_id.to_owned(),
                agent_id: record.agent_id,
                key_id: record.key_id,
            });
        }

        transaction.commit().await?;
        Ok(StoredIdentityKey {
            organization_id: organization_id.to_owned(),
            record,
            key_record_hash,
            lifecycle_version: 1,
            last_event_id: stored_event.event.event_id,
            registered_at: occurred_at,
            updated_at: occurred_at,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn revoke_identity_key(
        &self,
        organization_id: &str,
        agent_id: &str,
        key_id: &str,
        actor_id: &str,
        reason_code: &str,
        occurred_at: Timestamp,
    ) -> Result<StoredIdentityKey, StoreError> {
        validate_identifier("organization_id", organization_id)?;
        validate_identifier("agent_id", agent_id)?;
        validate_identifier("key_id", key_id)?;
        validate_identifier("actor_id", actor_id)?;
        validate_identifier("reason_code", reason_code)?;
        validate_timestamp("occurred_at", occurred_at)?;

        let mut transaction = self.pool.begin().await?;
        set_mutation_timeouts(&mut transaction).await?;
        let row = fetch_key_for_update(&mut transaction, organization_id, agent_id, key_id).await?;
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let current = verify_key_row(row, &chain)?;
        if current.record.revoked_at.is_some() {
            return Err(invalid("identity key is already revoked"));
        }
        if occurred_at < current.updated_at {
            return Err(invalid(
                "occurred_at cannot precede the current identity key lifecycle version",
            ));
        }

        let mut record = current.record.clone();
        record.revoked_at = Some(occurred_at);
        record.validate()?;
        let lifecycle_version = current
            .lifecycle_version
            .checked_add(1)
            .ok_or_else(|| invalid("identity key lifecycle version overflow"))?;
        let audit_version = u64::try_from(lifecycle_version).map_err(|_| {
            invalid("identity key lifecycle version is outside the Audit representation")
        })?;
        let canonical_key = canonical_key(organization_id, &record);
        let canonical_record = atf_core::sort_json_keys(serde_json::to_value(&canonical_key)?);
        let canonical_record_bytes = serde_json::to_vec(&canonical_record)?;
        let key_record_hash = atf_core::sha256_hex(&canonical_record_bytes);
        let public_key_fingerprint = record.public_key_fingerprint();
        let payload = AuditPayload::IdentityKeyRevoked(IdentityKeyRevokedPayload {
            organization_id: organization_id.to_owned(),
            agent_id: agent_id.to_owned(),
            key_id: key_id.to_owned(),
            public_key_fingerprint,
            key_record_hash: key_record_hash.clone(),
            revoked_at: occurred_at,
            lifecycle_version: audit_version,
            actor_id: actor_id.to_owned(),
            reason_code: reason_code.to_owned(),
        });
        let event = NewAuditEvent::from_payload(occurred_at, None, payload)?;
        let stored_event = append_in_transaction(
            &mut transaction,
            organization_id,
            event,
            AuditReferences::default(),
        )
        .await?;

        let updated = sqlx::query(
            r#"
            UPDATE identity_keys
            SET canonical_record = $5,
                canonical_record_bytes = $6,
                key_record_hash = $7,
                revoked_at = $8,
                lifecycle_version = $9,
                last_event_id = $10,
                updated_at = $8
            WHERE organization_id = $1
              AND agent_id = $2
              AND key_id = $3
              AND lifecycle_version = $4
            "#,
        )
        .bind(organization_id)
        .bind(agent_id)
        .bind(key_id)
        .bind(current.lifecycle_version)
        .bind(&canonical_record)
        .bind(&canonical_record_bytes)
        .bind(&key_record_hash)
        .bind(occurred_at.as_datetime())
        .bind(lifecycle_version)
        .bind(&stored_event.event.event_id)
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::IdentityStateCorrupt {
                organization_id: organization_id.to_owned(),
                agent_id: agent_id.to_owned(),
                reason: "locked identity key lifecycle version changed before update".into(),
            });
        }

        transaction.commit().await?;
        Ok(StoredIdentityKey {
            organization_id: organization_id.to_owned(),
            record,
            key_record_hash,
            lifecycle_version,
            last_event_id: stored_event.event.event_id,
            registered_at: current.registered_at,
            updated_at: occurred_at,
        })
    }

    pub async fn load_identity_snapshot(
        &self,
        organization_id: &str,
        agent_id: &str,
        key_id: &str,
    ) -> Result<IdentitySnapshot, StoreError> {
        validate_identifier("organization_id", organization_id)?;
        validate_identifier("agent_id", agent_id)?;
        validate_identifier("key_id", key_id)?;

        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '30s'")
            .execute(&mut *transaction)
            .await?;
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let agent = verify_agent_row(
            fetch_agent(&mut transaction, organization_id, agent_id).await?,
            &chain,
        )?;
        let key = verify_key_row(
            fetch_key(&mut transaction, organization_id, agent_id, key_id).await?,
            &chain,
        )?;
        transaction.commit().await?;
        Ok(IdentitySnapshot { agent, key })
    }
}

/// Lock and verify the current Agent/exact-Key authority inside a caller's
/// write transaction. Admission uses this to close the verify/revoke race and
/// to reuse the same fully verified Audit snapshot for Nonce classification.
pub(crate) async fn load_identity_snapshot_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    agent_id: &str,
    key_id: &str,
) -> Result<(IdentitySnapshot, Vec<crate::StoredAuditEvent>), StoreError> {
    let agent_row = fetch_agent_for_update(transaction, organization_id, agent_id).await?;
    let key_row = fetch_key_for_update(transaction, organization_id, agent_id, key_id).await?;
    let chain = load_verified_in_transaction(transaction, organization_id).await?;
    let agent = verify_agent_row(agent_row, &chain)?;
    let key = verify_key_row(key_row, &chain)?;
    Ok((IdentitySnapshot { agent, key }, chain))
}

async fn fetch_agent(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    agent_id: &str,
) -> Result<AgentRow, StoreError> {
    sqlx::query_as(
        r#"
        SELECT organization_id, agent_id, canonical_record,
               canonical_record_bytes, record_hash::text AS record_hash,
               status, lifecycle_version, last_event_id,
               created_at, expires_at, updated_at
        FROM agents
        WHERE organization_id = $1 AND agent_id = $2
        "#,
    )
    .bind(organization_id)
    .bind(agent_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| StoreError::AgentNotFound {
        organization_id: organization_id.to_owned(),
        agent_id: agent_id.to_owned(),
    })
}

async fn fetch_agent_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    agent_id: &str,
) -> Result<AgentRow, StoreError> {
    sqlx::query_as(
        r#"
        SELECT organization_id, agent_id, canonical_record,
               canonical_record_bytes, record_hash::text AS record_hash,
               status, lifecycle_version, last_event_id,
               created_at, expires_at, updated_at
        FROM agents
        WHERE organization_id = $1 AND agent_id = $2
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .bind(agent_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| StoreError::AgentNotFound {
        organization_id: organization_id.to_owned(),
        agent_id: agent_id.to_owned(),
    })
}

async fn fetch_key(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    agent_id: &str,
    key_id: &str,
) -> Result<IdentityKeyRow, StoreError> {
    sqlx::query_as(
        r#"
        SELECT organization_id, agent_id, key_id, algorithm,
               public_key, public_key_fingerprint::text AS public_key_fingerprint,
               canonical_record, canonical_record_bytes,
               key_record_hash::text AS key_record_hash,
               activates_at, expires_at, revoked_at, lifecycle_version,
               last_event_id, registered_at, updated_at
        FROM identity_keys
        WHERE organization_id = $1 AND agent_id = $2 AND key_id = $3
        "#,
    )
    .bind(organization_id)
    .bind(agent_id)
    .bind(key_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| StoreError::IdentityKeyNotFound {
        organization_id: organization_id.to_owned(),
        agent_id: agent_id.to_owned(),
        key_id: key_id.to_owned(),
    })
}

async fn fetch_key_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    agent_id: &str,
    key_id: &str,
) -> Result<IdentityKeyRow, StoreError> {
    sqlx::query_as(
        r#"
        SELECT organization_id, agent_id, key_id, algorithm,
               public_key, public_key_fingerprint::text AS public_key_fingerprint,
               canonical_record, canonical_record_bytes,
               key_record_hash::text AS key_record_hash,
               activates_at, expires_at, revoked_at, lifecycle_version,
               last_event_id, registered_at, updated_at
        FROM identity_keys
        WHERE organization_id = $1 AND agent_id = $2 AND key_id = $3
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .bind(agent_id)
    .bind(key_id)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| StoreError::IdentityKeyNotFound {
        organization_id: organization_id.to_owned(),
        agent_id: agent_id.to_owned(),
        key_id: key_id.to_owned(),
    })
}

fn verify_agent_row(
    row: AgentRow,
    chain: &[crate::StoredAuditEvent],
) -> Result<StoredAgent, StoreError> {
    let corrupt = |reason: String| StoreError::IdentityStateCorrupt {
        organization_id: row.organization_id.clone(),
        agent_id: row.agent_id.clone(),
        reason,
    };
    let record: AgentRecord = serde_json::from_value(row.canonical_record.clone())
        .map_err(|error| corrupt(format!("canonical Agent record cannot be decoded: {error}")))?;
    record
        .validate()
        .map_err(|error| corrupt(format!("canonical Agent record is invalid: {error}")))?;
    let canonical_value = atf_core::sort_json_keys(serde_json::to_value(&record)?);
    let columns_match = canonical_value == row.canonical_record
        && record.canonical_bytes() == row.canonical_record_bytes
        && record.canonical_hash() == row.record_hash
        && record.organization_id == row.organization_id
        && record.agent_id == row.agent_id
        && status_name(record.status) == row.status
        && record.created_at == Timestamp::from_datetime(row.created_at)
        && record.expires_at == row.expires_at.map(Timestamp::from_datetime)
        && row.lifecycle_version > 0;
    if !columns_match {
        return Err(corrupt(
            "canonical Agent record, hash, bytes, or redundant columns disagree".into(),
        ));
    }

    let event = chain
        .iter()
        .find(|event| event.event.event_id == row.last_event_id)
        .ok_or_else(|| corrupt("last_event_id is absent from the verified Audit chain".into()))?;
    let payload = event
        .event
        .typed_payload()
        .map_err(|error| corrupt(format!("last Audit payload is invalid: {error}")))?;
    let version = u64::try_from(row.lifecycle_version)
        .map_err(|_| corrupt("lifecycle_version is outside the Audit representation".into()))?;
    let evidence_matches = event.event.occurred_at == Timestamp::from_datetime(row.updated_at)
        && match payload {
            AuditPayload::AgentRegistered(payload) => {
                version == 1
                    && payload.organization_id == row.organization_id
                    && payload.agent_id == row.agent_id
                    && payload.status == row.status
                    && payload.record_hash == row.record_hash
                    && payload.lifecycle_version == version
            }
            AuditPayload::AgentStatusChanged(payload) => {
                payload.organization_id == row.organization_id
                    && payload.agent_id == row.agent_id
                    && payload.status == row.status
                    && payload.record_hash == row.record_hash
                    && payload.lifecycle_version == version
            }
            _ => false,
        };
    if !evidence_matches {
        return Err(corrupt(
            "last Audit event does not bind the current Agent record and version".into(),
        ));
    }
    if !agent_history_matches(&row, chain, &record) {
        return Err(corrupt(
            "Agent lifecycle Audit evidence is missing, discontinuous, or inconsistent".into(),
        ));
    }

    Ok(StoredAgent {
        record,
        lifecycle_version: row.lifecycle_version,
        last_event_id: row.last_event_id,
        updated_at: Timestamp::from_datetime(row.updated_at),
    })
}

fn verify_key_row(
    row: IdentityKeyRow,
    chain: &[crate::StoredAuditEvent],
) -> Result<StoredIdentityKey, StoreError> {
    let corrupt = |reason: String| StoreError::IdentityStateCorrupt {
        organization_id: row.organization_id.clone(),
        agent_id: row.agent_id.clone(),
        reason,
    };
    let record = IdentityKeyRecord::from_public_key_bytes(
        row.agent_id.clone(),
        row.key_id.clone(),
        &row.public_key,
        Timestamp::from_datetime(row.activates_at),
        row.expires_at.map(Timestamp::from_datetime),
        row.revoked_at.map(Timestamp::from_datetime),
    )
    .map_err(|error| corrupt(format!("identity key record is invalid: {error}")))?;
    let canonical_key = canonical_key(&row.organization_id, &record);
    let canonical_record = atf_core::sort_json_keys(serde_json::to_value(&canonical_key)?);
    let canonical_record_bytes = serde_json::to_vec(&canonical_record)?;
    let key_record_hash = atf_core::sha256_hex(&canonical_record_bytes);
    let columns_match = row.algorithm == "ED25519"
        && row.canonical_record == canonical_record
        && row.canonical_record_bytes == canonical_record_bytes
        && row.key_record_hash == key_record_hash
        && row.public_key_fingerprint == record.public_key_fingerprint()
        && row.lifecycle_version > 0;
    if !columns_match {
        return Err(corrupt(
            "canonical identity key, hash, bytes, or redundant columns disagree".into(),
        ));
    }
    let event = chain
        .iter()
        .find(|event| event.event.event_id == row.last_event_id)
        .ok_or_else(|| {
            corrupt("identity key last_event_id is absent from the verified Audit chain".into())
        })?;
    let payload = event
        .event
        .typed_payload()
        .map_err(|error| corrupt(format!("identity key Audit payload is invalid: {error}")))?;
    let version = u64::try_from(row.lifecycle_version)
        .map_err(|_| corrupt("identity key version is outside the Audit representation".into()))?;
    let evidence_matches = event.event.occurred_at == Timestamp::from_datetime(row.updated_at)
        && match payload {
            AuditPayload::IdentityKeyRegistered(payload) => {
                version == 1
                    && row.registered_at == row.updated_at
                    && payload.organization_id == row.organization_id
                    && payload.agent_id == row.agent_id
                    && payload.key_id == row.key_id
                    && payload.algorithm == row.algorithm
                    && payload.public_key_fingerprint == row.public_key_fingerprint
                    && payload.key_record_hash == row.key_record_hash
                    && payload.lifecycle_version == version
            }
            AuditPayload::IdentityKeyRevoked(payload) => {
                payload.organization_id == row.organization_id
                    && payload.agent_id == row.agent_id
                    && payload.key_id == row.key_id
                    && payload.public_key_fingerprint == row.public_key_fingerprint
                    && payload.key_record_hash == row.key_record_hash
                    && record.revoked_at == Some(payload.revoked_at)
                    && payload.lifecycle_version == version
            }
            _ => false,
        };
    if !evidence_matches {
        return Err(corrupt(
            "last Audit event does not bind the current identity key and version".into(),
        ));
    }
    if !key_history_matches(&row, chain, &record) {
        return Err(corrupt(
            "identity key lifecycle Audit evidence is missing, discontinuous, or inconsistent"
                .into(),
        ));
    }

    Ok(StoredIdentityKey {
        organization_id: row.organization_id,
        record,
        key_record_hash: row.key_record_hash,
        lifecycle_version: row.lifecycle_version,
        last_event_id: row.last_event_id,
        registered_at: Timestamp::from_datetime(row.registered_at),
        updated_at: Timestamp::from_datetime(row.updated_at),
    })
}

fn agent_history_matches(
    row: &AgentRow,
    chain: &[crate::StoredAuditEvent],
    current_record: &AgentRecord,
) -> bool {
    let mut version = 0_i64;
    let mut status = None;
    let mut last_event_id = None;

    for stored in chain {
        if !matches!(
            stored.event.event_type,
            EventType::AgentRegistered | EventType::AgentStatusChanged
        ) {
            continue;
        }
        let Ok(payload) = stored.event.typed_payload() else {
            return false;
        };
        match payload {
            AuditPayload::AgentRegistered(payload)
                if payload.organization_id == row.organization_id
                    && payload.agent_id == row.agent_id =>
            {
                let Some(registered_status) = parse_status_name(&payload.status) else {
                    return false;
                };
                let mut registered_record = current_record.clone();
                registered_record.status = registered_status;
                if version != 0
                    || payload.lifecycle_version != 1
                    || payload.record_hash != registered_record.canonical_hash()
                {
                    return false;
                }
                version = 1;
                status = Some(registered_status);
                last_event_id = Some(stored.event.event_id.as_str());
            }
            AuditPayload::AgentStatusChanged(payload)
                if payload.organization_id == row.organization_id
                    && payload.agent_id == row.agent_id =>
            {
                let (Some(previous), Some(next)) = (
                    parse_status_name(&payload.previous_status),
                    parse_status_name(&payload.status),
                ) else {
                    return false;
                };
                let Some(next_version) = version.checked_add(1) else {
                    return false;
                };
                let Ok(audit_version) = u64::try_from(next_version) else {
                    return false;
                };
                let mut version_record = current_record.clone();
                version_record.status = next;
                if status != Some(previous)
                    || previous.validate_transition_to(next).is_err()
                    || payload.lifecycle_version != audit_version
                    || payload.record_hash != version_record.canonical_hash()
                {
                    return false;
                }
                version = next_version;
                status = Some(next);
                last_event_id = Some(stored.event.event_id.as_str());
            }
            _ => {}
        }
    }

    version == row.lifecycle_version
        && status == Some(current_record.status)
        && last_event_id == Some(row.last_event_id.as_str())
}

fn key_history_matches(
    row: &IdentityKeyRow,
    chain: &[crate::StoredAuditEvent],
    current_record: &IdentityKeyRecord,
) -> bool {
    let mut unrevoked_record = current_record.clone();
    unrevoked_record.revoked_at = None;
    let Ok(registered_value) =
        serde_json::to_value(canonical_key(&row.organization_id, &unrevoked_record))
    else {
        return false;
    };
    let registered_canonical = atf_core::sort_json_keys(registered_value);
    let Ok(registered_bytes) = serde_json::to_vec(&registered_canonical) else {
        return false;
    };
    let registered_hash = atf_core::sha256_hex(&registered_bytes);
    let fingerprint = current_record.public_key_fingerprint();
    let mut version = 0_i64;
    let mut last_event_id = None;

    for stored in chain {
        if !matches!(
            stored.event.event_type,
            EventType::IdentityKeyRegistered | EventType::IdentityKeyRevoked
        ) {
            continue;
        }
        let Ok(payload) = stored.event.typed_payload() else {
            return false;
        };
        match payload {
            AuditPayload::IdentityKeyRegistered(payload)
                if payload.organization_id == row.organization_id
                    && payload.agent_id == row.agent_id
                    && payload.key_id == row.key_id =>
            {
                if version != 0
                    || payload.algorithm != "ED25519"
                    || payload.public_key_fingerprint != fingerprint
                    || payload.key_record_hash != registered_hash
                    || payload.activates_at != current_record.activates_at
                    || payload.expires_at != current_record.expires_at
                    || payload.lifecycle_version != 1
                {
                    return false;
                }
                version = 1;
                last_event_id = Some(stored.event.event_id.as_str());
            }
            AuditPayload::IdentityKeyRevoked(payload)
                if payload.organization_id == row.organization_id
                    && payload.agent_id == row.agent_id
                    && payload.key_id == row.key_id =>
            {
                if version != 1
                    || payload.public_key_fingerprint != fingerprint
                    || payload.key_record_hash != row.key_record_hash
                    || current_record.revoked_at != Some(payload.revoked_at)
                    || payload.lifecycle_version != 2
                {
                    return false;
                }
                version = 2;
                last_event_id = Some(stored.event.event_id.as_str());
            }
            _ => {}
        }
    }

    version == row.lifecycle_version && last_event_id == Some(row.last_event_id.as_str())
}

async fn ensure_organization(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
) -> Result<(), StoreError> {
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM organizations WHERE organization_id = $1)",
    )
    .bind(organization_id)
    .fetch_one(&mut **transaction)
    .await?;
    if exists {
        Ok(())
    } else {
        Err(StoreError::OrganizationNotFound {
            organization_id: organization_id.to_owned(),
        })
    }
}

async fn set_mutation_timeouts(
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

fn validate_identifier(field: &'static str, value: &str) -> Result<(), StoreError> {
    if (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        Ok(())
    } else {
        Err(invalid(format!(
            "{field} must be 1..128 canonical ASCII bytes"
        )))
    }
}

fn validate_timestamp(field: &'static str, value: Timestamp) -> Result<(), StoreError> {
    if value.as_datetime().timestamp_subsec_nanos() % 1_000_000 == 0 {
        Ok(())
    } else {
        Err(invalid(format!("{field} must be millisecond aligned")))
    }
}

fn status_name(status: AgentStatus) -> &'static str {
    match status {
        AgentStatus::Active => "ACTIVE",
        AgentStatus::ShadowOnly => "SHADOW_ONLY",
        AgentStatus::Paused => "PAUSED",
        AgentStatus::Revoked => "REVOKED",
        AgentStatus::Expired => "EXPIRED",
    }
}

fn parse_status_name(status: &str) -> Option<AgentStatus> {
    match status {
        "ACTIVE" => Some(AgentStatus::Active),
        "SHADOW_ONLY" => Some(AgentStatus::ShadowOnly),
        "PAUSED" => Some(AgentStatus::Paused),
        "REVOKED" => Some(AgentStatus::Revoked),
        "EXPIRED" => Some(AgentStatus::Expired),
        _ => None,
    }
}

fn canonical_key(organization_id: &str, record: &IdentityKeyRecord) -> CanonicalIdentityKey {
    CanonicalIdentityKey {
        organization_id: organization_id.to_owned(),
        agent_id: record.agent_id.clone(),
        key_id: record.key_id.clone(),
        algorithm: "ED25519".into(),
        public_key_hex: encode_hex(&record.public_key_bytes()),
        activates_at: record.activates_at,
        expires_at: record.expires_at,
        revoked_at: record.revoked_at,
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn invalid(reason: impl Into<String>) -> StoreError {
    StoreError::InvalidRepositoryInput {
        reason: reason.into(),
    }
}
