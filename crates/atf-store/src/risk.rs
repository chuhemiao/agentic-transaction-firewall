use atf_audit::{AuditPayload, NewAuditEvent, RiskRuleSetStoredPayload};
use atf_core::{sort_json_keys, Timestamp};
use atf_risk::RiskRuleSet;
use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};

use crate::audit::{append_in_transaction, load_verified_in_transaction, AuditReferences};
use crate::operator::authorize_policy_change;
use crate::{Store, StoreError, StoredAuditEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRiskRuleSet {
    pub organization_id: String,
    pub environment: String,
    pub engine_version: String,
    pub rule_set_version: String,
    pub rule_set_hash: String,
    pub artifact_hash: String,
    pub installed_by_operator_id: String,
    pub installed_event_id: String,
    pub installed_at: Timestamp,
}

#[derive(Debug, FromRow)]
struct RiskRuleSetRow {
    organization_id: String,
    environment: String,
    engine_version: String,
    rule_set_version: String,
    rule_set_hash: String,
    canonical_rule_set: Value,
    canonical_rule_set_bytes: Vec<u8>,
    artifact_hash: String,
    installed_by_operator_id: String,
    installed_event_id: String,
    installed_at: DateTime<Utc>,
}

impl Store {
    /// Store the exact canonical Rule Set used by Risk. Policy-author or
    /// organization-admin authority and Audit evidence commit atomically.
    pub async fn install_risk_rule_set(
        &self,
        organization_id: &str,
        environment: &str,
        rule_set: &RiskRuleSet,
        actor_id: &str,
        occurred_at: Timestamp,
    ) -> Result<StoredRiskRuleSet, StoreError> {
        validate_scope(organization_id, environment)?;
        validate_timestamp(occurred_at)?;
        let canonical_bytes = rule_set.canonical_bytes();
        let canonical_rule_set: Value = serde_json::from_slice(canonical_bytes)?;
        let artifact_hash = atf_core::sha256_hex(canonical_bytes);

        let mut transaction = self.pool.begin().await?;
        set_mutation_timeouts(&mut transaction).await?;
        authorize_policy_change(&mut transaction, actor_id, organization_id).await?;
        let event = NewAuditEvent::from_payload(
            occurred_at,
            None,
            AuditPayload::RiskRuleSetStored(RiskRuleSetStoredPayload {
                organization_id: organization_id.into(),
                environment: environment.into(),
                engine_version: rule_set.engine_version().into(),
                rule_set_version: rule_set.version().into(),
                rule_set_hash: rule_set.rule_set_hash().into(),
                artifact_hash: artifact_hash.clone(),
                actor_id: actor_id.into(),
            }),
        )?;
        let stored_event = append_in_transaction(
            &mut transaction,
            organization_id,
            event,
            AuditReferences::default(),
        )
        .await?;
        let inserted = sqlx::query(
            r#"
            INSERT INTO risk_rule_sets (
                organization_id, environment, engine_version, rule_set_version,
                rule_set_hash, canonical_rule_set, canonical_rule_set_bytes,
                artifact_hash, installed_by_operator_id, installed_event_id,
                installed_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(organization_id)
        .bind(environment)
        .bind(rule_set.engine_version())
        .bind(rule_set.version())
        .bind(rule_set.rule_set_hash())
        .bind(&canonical_rule_set)
        .bind(canonical_bytes)
        .bind(&artifact_hash)
        .bind(actor_id)
        .bind(&stored_event.event.event_id)
        .bind(occurred_at.as_datetime())
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(StoreError::RiskRuleSetConflict {
                organization_id: organization_id.into(),
                environment: environment.into(),
                engine_version: rule_set.engine_version().into(),
                rule_set_version: rule_set.version().into(),
            });
        }
        transaction.commit().await?;
        Ok(StoredRiskRuleSet {
            organization_id: organization_id.into(),
            environment: environment.into(),
            engine_version: rule_set.engine_version().into(),
            rule_set_version: rule_set.version().into(),
            rule_set_hash: rule_set.rule_set_hash().into(),
            artifact_hash,
            installed_by_operator_id: actor_id.into(),
            installed_event_id: stored_event.event.event_id,
            installed_at: occurred_at,
        })
    }

    pub async fn load_risk_rule_set(
        &self,
        organization_id: &str,
        environment: &str,
        engine_version: &str,
        rule_set_version: &str,
        expected_hash: &str,
    ) -> Result<RiskRuleSet, StoreError> {
        validate_scope(organization_id, environment)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '30s'")
            .execute(&mut *transaction)
            .await?;
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let rule_set = load_risk_rule_set_in_transaction(
            &mut transaction,
            organization_id,
            environment,
            engine_version,
            rule_set_version,
            expected_hash,
            &chain,
        )
        .await?;
        transaction.commit().await?;
        Ok(rule_set)
    }
}

async fn load_risk_rule_set_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    environment: &str,
    engine_version: &str,
    rule_set_version: &str,
    expected_hash: &str,
    chain: &[StoredAuditEvent],
) -> Result<RiskRuleSet, StoreError> {
    let row: RiskRuleSetRow = sqlx::query_as(
        r#"
        SELECT organization_id, environment, engine_version, rule_set_version,
               rule_set_hash::text AS rule_set_hash, canonical_rule_set,
               canonical_rule_set_bytes, artifact_hash::text AS artifact_hash,
               installed_by_operator_id, installed_event_id, installed_at
        FROM risk_rule_sets
        WHERE organization_id = $1 AND environment = $2
          AND engine_version = $3 AND rule_set_version = $4
        "#,
    )
    .bind(organization_id)
    .bind(environment)
    .bind(engine_version)
    .bind(rule_set_version)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| StoreError::RiskRuleSetNotFound {
        organization_id: organization_id.into(),
        environment: environment.into(),
        engine_version: engine_version.into(),
        rule_set_version: rule_set_version.into(),
    })?;
    verify_row(row, expected_hash, chain)
}

fn verify_row(
    row: RiskRuleSetRow,
    expected_hash: &str,
    chain: &[StoredAuditEvent],
) -> Result<RiskRuleSet, StoreError> {
    let fail = |reason: String| StoreError::RiskStateCorrupt {
        organization_id: row.organization_id.clone(),
        environment: row.environment.clone(),
        engine_version: row.engine_version.clone(),
        rule_set_version: row.rule_set_version.clone(),
        reason,
    };
    if atf_core::sha256_hex(&row.canonical_rule_set_bytes) != row.artifact_hash {
        return Err(fail("canonical artifact hash mismatch".into()));
    }
    let canonical_value: Value = serde_json::from_slice(&row.canonical_rule_set_bytes)
        .map_err(|error| fail(format!("canonical bytes are invalid JSON: {error}")))?;
    if canonical_value != row.canonical_rule_set
        || serde_json::to_vec(&sort_json_keys(canonical_value.clone()))
            .map_err(|error| fail(format!("canonical JSON cannot be encoded: {error}")))?
            != row.canonical_rule_set_bytes
    {
        return Err(fail("canonical JSON and bytes disagree".into()));
    }
    let raw = std::str::from_utf8(&row.canonical_rule_set_bytes)
        .map_err(|error| fail(format!("canonical bytes are not UTF-8: {error}")))?;
    let rule_set = RiskRuleSet::from_json(raw)
        .map_err(|error| fail(format!("Rule Set cannot be validated: {error}")))?;
    if rule_set.engine_version() != row.engine_version
        || rule_set.version() != row.rule_set_version
        || rule_set.rule_set_hash() != row.rule_set_hash
        || rule_set.rule_set_hash() != expected_hash
    {
        return Err(fail(
            "Rule Set identity, hash, and redundant columns disagree".into(),
        ));
    }
    let event = chain
        .iter()
        .find(|event| event.event.event_id == row.installed_event_id)
        .ok_or_else(|| fail("install event is absent from Audit chain".into()))?;
    let payload = event
        .event
        .typed_payload()
        .map_err(|error| fail(format!("install Audit payload is invalid: {error}")))?;
    let evidence_matches = event.event.occurred_at == Timestamp::from_datetime(row.installed_at)
        && matches!(payload, AuditPayload::RiskRuleSetStored(ref payload)
            if payload.organization_id == row.organization_id
                && payload.environment == row.environment
                && payload.engine_version == row.engine_version
                && payload.rule_set_version == row.rule_set_version
                && payload.rule_set_hash == row.rule_set_hash
                && payload.artifact_hash == row.artifact_hash
                && payload.actor_id == row.installed_by_operator_id);
    if !evidence_matches {
        return Err(fail(
            "install Audit event does not bind immutable Rule Set state".into(),
        ));
    }
    Ok(rule_set)
}

fn validate_scope(organization_id: &str, environment: &str) -> Result<(), StoreError> {
    for (field, value) in [
        ("organization_id", organization_id),
        ("environment", environment),
    ] {
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().enumerate().all(|(index, byte)| {
                (index != 0 || byte.is_ascii_alphanumeric())
                    && (byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
            })
        {
            return Err(StoreError::InvalidRepositoryInput {
                reason: format!("{field} is not a canonical identifier"),
            });
        }
    }
    Ok(())
}

fn validate_timestamp(value: Timestamp) -> Result<(), StoreError> {
    if value.as_datetime().timestamp_subsec_nanos() % 1_000_000 != 0 {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "Risk Rule Set timestamp must be millisecond aligned".into(),
        });
    }
    Ok(())
}

async fn set_mutation_timeouts(
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<(), StoreError> {
    sqlx::query("SET LOCAL lock_timeout = '5s'")
        .execute(&mut **transaction)
        .await?;
    sqlx::query("SET LOCAL statement_timeout = '15s'")
        .execute(&mut **transaction)
        .await?;
    Ok(())
}
