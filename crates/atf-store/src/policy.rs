use atf_audit::{AuditPayload, NewAuditEvent, PolicyChangedPayload};
use atf_core::Timestamp;
use atf_policy::{
    PolicyBundle, PolicyBundleArtifact, PolicyBundleLoadContext, PolicyBundleSignature,
};
use chrono::{DateTime, Utc};
use sqlx::{FromRow, Postgres, Transaction};

use crate::audit::{append_in_transaction, load_verified_in_transaction, AuditReferences};
use crate::operator::authorize_policy_change;
use crate::{Store, StoreError, StoredAuditEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredPolicyBundle {
    pub organization_id: String,
    pub environment: String,
    pub bundle_id: String,
    pub policy_version: String,
    pub bundle_hash: String,
    pub artifact_hash: String,
    pub publisher_key_id: String,
    pub publisher_public_key_hash: String,
    pub installed_by_operator_id: String,
    pub installed_event_id: String,
    pub installed_at: Timestamp,
}

#[derive(Debug)]
pub struct ActivePolicyBundle {
    pub bundle: PolicyBundle,
    pub previous_policy_version: Option<String>,
    pub previous_bundle_hash: Option<String>,
    pub lifecycle_version: i64,
    pub last_event_id: String,
    pub updated_at: Timestamp,
}

#[derive(Debug, FromRow)]
struct PolicyBundleRow {
    organization_id: String,
    environment: String,
    bundle_id: String,
    policy_version: String,
    bundle_hash: String,
    activates_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    artifact_bytes: Vec<u8>,
    artifact_hash: String,
    publisher_key_id: String,
    publisher_public_key: Vec<u8>,
    publisher_public_key_hash: String,
    signature: Vec<u8>,
    installed_by_operator_id: String,
    installed_event_id: String,
    installed_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct ActivePolicyRow {
    organization_id: String,
    environment: String,
    bundle_id: String,
    policy_version: String,
    bundle_hash: String,
    previous_policy_version: Option<String>,
    previous_bundle_hash: Option<String>,
    lifecycle_version: i64,
    last_event_id: String,
    updated_at: DateTime<Utc>,
}

struct VerifiedPolicyBundle {
    bundle: PolicyBundle,
}

struct VerifiedActivePointer {
    policy_version: String,
    bundle_hash: String,
    previous_policy_version: Option<String>,
    previous_bundle_hash: Option<String>,
    lifecycle_version: i64,
    last_event_id: String,
    updated_at: Timestamp,
}

struct PolicyBundleSelection<'a> {
    organization_id: &'a str,
    environment: &'a str,
    bundle_id: &'a str,
    policy_version: &'a str,
    expected_hash: &'a str,
}

impl Store {
    pub async fn install_policy_bundle(
        &self,
        bundle: &PolicyBundle,
        signature: &PolicyBundleSignature,
        publisher_public_key: &[u8; 32],
        actor_id: &str,
        occurred_at: Timestamp,
    ) -> Result<StoredPolicyBundle, StoreError> {
        validate_timestamp(occurred_at)?;
        if occurred_at >= bundle.expires_at() {
            return Err(invalid("expired Policy Bundles cannot be installed"));
        }
        signature.verify(bundle, publisher_public_key)?;
        let artifact_bytes = bundle.artifact().encode();
        let artifact_hash = atf_core::sha256_hex(&artifact_bytes);
        let publisher_public_key_hash = atf_core::sha256_hex(publisher_public_key);

        let mut transaction = self.pool.begin().await?;
        set_mutation_timeouts(&mut transaction).await?;
        authorize_policy_change(&mut transaction, actor_id, bundle.organization_id()).await?;
        let event = NewAuditEvent::from_payload(
            occurred_at,
            None,
            policy_event(bundle, None, "INSTALLED", None, actor_id),
        )?;
        let stored_event = append_in_transaction(
            &mut transaction,
            bundle.organization_id(),
            event,
            AuditReferences::default(),
        )
        .await?;
        let inserted = sqlx::query(
            r#"
            INSERT INTO policy_bundles (
                organization_id, environment, bundle_id, policy_version,
                bundle_hash, activates_at, expires_at, artifact_bytes,
                artifact_hash, publisher_key_id, publisher_public_key,
                publisher_public_key_hash, signature, installed_by_operator_id,
                installed_event_id, installed_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6, $7, $8,
                $9, $10, $11, $12, $13, $14, $15, $16
            )
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(bundle.organization_id())
        .bind(bundle.environment())
        .bind(bundle.bundle_id())
        .bind(bundle.policy_version())
        .bind(bundle.bundle_hash())
        .bind(bundle.activates_at().as_datetime())
        .bind(bundle.expires_at().as_datetime())
        .bind(&artifact_bytes)
        .bind(&artifact_hash)
        .bind(signature.key_id())
        .bind(publisher_public_key.as_slice())
        .bind(&publisher_public_key_hash)
        .bind(signature.signature_bytes().as_slice())
        .bind(actor_id)
        .bind(&stored_event.event.event_id)
        .bind(occurred_at.as_datetime())
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(StoreError::PolicyBundleConflict {
                organization_id: bundle.organization_id().into(),
                environment: bundle.environment().into(),
                bundle_id: bundle.bundle_id().into(),
                policy_version: bundle.policy_version().into(),
            });
        }
        transaction.commit().await?;
        Ok(StoredPolicyBundle {
            organization_id: bundle.organization_id().into(),
            environment: bundle.environment().into(),
            bundle_id: bundle.bundle_id().into(),
            policy_version: bundle.policy_version().into(),
            bundle_hash: bundle.bundle_hash().into(),
            artifact_hash,
            publisher_key_id: signature.key_id().into(),
            publisher_public_key_hash,
            installed_by_operator_id: actor_id.into(),
            installed_event_id: stored_event.event.event_id,
            installed_at: occurred_at,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn activate_policy_bundle(
        &self,
        organization_id: &str,
        environment: &str,
        bundle_id: &str,
        policy_version: &str,
        actor_id: &str,
        occurred_at: Timestamp,
    ) -> Result<ActivePolicyBundle, StoreError> {
        validate_scope(
            organization_id,
            environment,
            bundle_id,
            Some(policy_version),
        )?;
        validate_timestamp(occurred_at)?;
        let mut transaction = self.pool.begin().await?;
        set_mutation_timeouts(&mut transaction).await?;
        authorize_policy_change(&mut transaction, actor_id, organization_id).await?;
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let target_row = fetch_bundle(
            &mut transaction,
            organization_id,
            environment,
            bundle_id,
            policy_version,
            true,
        )
        .await?;
        let target = verify_bundle_row(target_row, occurred_at, &chain)?;
        let current_row = fetch_active(
            &mut transaction,
            organization_id,
            environment,
            bundle_id,
            true,
        )
        .await?;
        let current = current_row
            .map(|row| verify_active_row(row, &chain))
            .transpose()?;
        if current
            .as_ref()
            .is_some_and(|active| active.bundle_hash == target.bundle.bundle_hash())
        {
            return Err(StoreError::PolicyBundleConflict {
                organization_id: organization_id.into(),
                environment: environment.into(),
                bundle_id: bundle_id.into(),
                policy_version: policy_version.into(),
            });
        }
        if current
            .as_ref()
            .is_some_and(|active| occurred_at < active.updated_at)
        {
            return Err(invalid("occurred_at precedes the active pointer"));
        }
        let lifecycle_version = current.as_ref().map_or(Ok(1), |active| {
            active
                .lifecycle_version
                .checked_add(1)
                .ok_or_else(|| invalid("Policy pointer lifecycle version overflow"))
        })?;
        let previous_policy_version = current.as_ref().map(|active| active.policy_version.clone());
        let previous_bundle_hash = current.as_ref().map(|active| active.bundle_hash.clone());
        change_active_pointer(
            transaction,
            target.bundle,
            previous_policy_version,
            previous_bundle_hash,
            lifecycle_version,
            actor_id,
            occurred_at,
            "ACTIVATED",
            current.is_some(),
        )
        .await
    }

    pub async fn rollback_policy_bundle(
        &self,
        organization_id: &str,
        environment: &str,
        bundle_id: &str,
        actor_id: &str,
        occurred_at: Timestamp,
    ) -> Result<ActivePolicyBundle, StoreError> {
        validate_scope(organization_id, environment, bundle_id, None)?;
        validate_timestamp(occurred_at)?;
        let mut transaction = self.pool.begin().await?;
        set_mutation_timeouts(&mut transaction).await?;
        authorize_policy_change(&mut transaction, actor_id, organization_id).await?;
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let current_row = fetch_active(
            &mut transaction,
            organization_id,
            environment,
            bundle_id,
            true,
        )
        .await?
        .ok_or_else(|| StoreError::ActivePolicyBundleNotFound {
            organization_id: organization_id.into(),
            environment: environment.into(),
            bundle_id: bundle_id.into(),
        })?;
        let current = verify_active_row(current_row, &chain)?;
        if occurred_at < current.updated_at {
            return Err(invalid("occurred_at precedes the active pointer"));
        }
        let previous_policy_version = current.previous_policy_version.clone().ok_or_else(|| {
            StoreError::PolicyRollbackUnavailable {
                organization_id: organization_id.into(),
                environment: environment.into(),
                bundle_id: bundle_id.into(),
            }
        })?;
        let target_row = fetch_bundle(
            &mut transaction,
            organization_id,
            environment,
            bundle_id,
            &previous_policy_version,
            true,
        )
        .await?;
        let target = verify_bundle_row(target_row, occurred_at, &chain)?;
        if Some(target.bundle.bundle_hash()) != current.previous_bundle_hash.as_deref() {
            return Err(corrupt(
                organization_id,
                environment,
                bundle_id,
                "previous pointer version/hash disagree",
            ));
        }
        let lifecycle_version = current
            .lifecycle_version
            .checked_add(1)
            .ok_or_else(|| invalid("Policy pointer lifecycle version overflow"))?;
        change_active_pointer(
            transaction,
            target.bundle,
            Some(current.policy_version),
            Some(current.bundle_hash),
            lifecycle_version,
            actor_id,
            occurred_at,
            "ROLLED_BACK",
            true,
        )
        .await
    }

    pub async fn load_active_policy_bundle(
        &self,
        organization_id: &str,
        environment: &str,
        bundle_id: &str,
        evaluated_at: Timestamp,
    ) -> Result<ActivePolicyBundle, StoreError> {
        validate_scope(organization_id, environment, bundle_id, None)?;
        validate_timestamp(evaluated_at)?;
        let mut transaction = self.pool.begin().await?;
        set_read_transaction(&mut transaction).await?;
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let row = fetch_active(
            &mut transaction,
            organization_id,
            environment,
            bundle_id,
            false,
        )
        .await?
        .ok_or_else(|| StoreError::ActivePolicyBundleNotFound {
            organization_id: organization_id.into(),
            environment: environment.into(),
            bundle_id: bundle_id.into(),
        })?;
        let pointer = verify_active_row(row, &chain)?;
        let row = fetch_bundle(
            &mut transaction,
            organization_id,
            environment,
            bundle_id,
            &pointer.policy_version,
            false,
        )
        .await?;
        let loaded = verify_bundle_row(row, evaluated_at, &chain)?;
        if loaded.bundle.bundle_hash() != pointer.bundle_hash {
            return Err(corrupt(
                organization_id,
                environment,
                bundle_id,
                "active pointer and installed Bundle disagree",
            ));
        }
        transaction.commit().await?;
        Ok(ActivePolicyBundle {
            bundle: loaded.bundle,
            previous_policy_version: pointer.previous_policy_version,
            previous_bundle_hash: pointer.previous_bundle_hash,
            lifecycle_version: pointer.lifecycle_version,
            last_event_id: pointer.last_event_id,
            updated_at: pointer.updated_at,
        })
    }

    pub async fn load_policy_bundle(
        &self,
        organization_id: &str,
        environment: &str,
        bundle_id: &str,
        policy_version: &str,
        expected_hash: &str,
        evaluated_at: Timestamp,
    ) -> Result<PolicyBundle, StoreError> {
        let mut transaction = self.pool.begin().await?;
        set_read_transaction(&mut transaction).await?;
        let chain = load_verified_in_transaction(&mut transaction, organization_id).await?;
        let bundle = load_policy_bundle_in_transaction(
            &mut transaction,
            PolicyBundleSelection {
                organization_id,
                environment,
                bundle_id,
                policy_version,
                expected_hash,
            },
            evaluated_at,
            &chain,
        )
        .await?;
        transaction.commit().await?;
        Ok(bundle)
    }
}

/// Load one immutable signed Bundle by the complete identity captured in an
/// Evaluation Context. Replay must never follow the mutable active pointer.
async fn load_policy_bundle_in_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    selection: PolicyBundleSelection<'_>,
    evaluated_at: Timestamp,
    chain: &[StoredAuditEvent],
) -> Result<PolicyBundle, StoreError> {
    validate_scope(
        selection.organization_id,
        selection.environment,
        selection.bundle_id,
        Some(selection.policy_version),
    )?;
    validate_timestamp(evaluated_at)?;
    let row = fetch_bundle(
        transaction,
        selection.organization_id,
        selection.environment,
        selection.bundle_id,
        selection.policy_version,
        false,
    )
    .await?;
    let verified = verify_bundle_row(row, evaluated_at, chain)?;
    if verified.bundle.bundle_hash() != selection.expected_hash {
        return Err(corrupt(
            selection.organization_id,
            selection.environment,
            selection.bundle_id,
            "requested immutable Bundle hash disagrees with stored artifact",
        ));
    }
    Ok(verified.bundle)
}

#[allow(clippy::too_many_arguments)]
async fn change_active_pointer(
    mut transaction: Transaction<'_, Postgres>,
    bundle: PolicyBundle,
    previous_policy_version: Option<String>,
    previous_bundle_hash: Option<String>,
    lifecycle_version: i64,
    actor_id: &str,
    occurred_at: Timestamp,
    change_kind: &'static str,
    update: bool,
) -> Result<ActivePolicyBundle, StoreError> {
    let audit_version = u64::try_from(lifecycle_version)
        .map_err(|_| invalid("Policy pointer lifecycle version is invalid"))?;
    let event = NewAuditEvent::from_payload(
        occurred_at,
        None,
        policy_event(
            &bundle,
            previous_bundle_hash.clone(),
            change_kind,
            Some(audit_version),
            actor_id,
        ),
    )?;
    let stored_event = append_in_transaction(
        &mut transaction,
        bundle.organization_id(),
        event,
        AuditReferences::default(),
    )
    .await?;
    if update {
        let updated = sqlx::query(
            r#"
            UPDATE active_policy_bundles
            SET policy_version = $4, bundle_hash = $5,
                previous_policy_version = $6, previous_bundle_hash = $7,
                lifecycle_version = $8, last_event_id = $9, updated_at = $10
            WHERE organization_id = $1 AND environment = $2 AND bundle_id = $3
            "#,
        )
        .bind(bundle.organization_id())
        .bind(bundle.environment())
        .bind(bundle.bundle_id())
        .bind(bundle.policy_version())
        .bind(bundle.bundle_hash())
        .bind(&previous_policy_version)
        .bind(&previous_bundle_hash)
        .bind(lifecycle_version)
        .bind(&stored_event.event.event_id)
        .bind(occurred_at.as_datetime())
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::ActivePolicyBundleNotFound {
                organization_id: bundle.organization_id().into(),
                environment: bundle.environment().into(),
                bundle_id: bundle.bundle_id().into(),
            });
        }
    } else {
        sqlx::query(
            r#"
            INSERT INTO active_policy_bundles (
                organization_id, environment, bundle_id, policy_version,
                bundle_hash, previous_policy_version, previous_bundle_hash,
                lifecycle_version, last_event_id, updated_at
            ) VALUES ($1, $2, $3, $4, $5, NULL, NULL, 1, $6, $7)
            "#,
        )
        .bind(bundle.organization_id())
        .bind(bundle.environment())
        .bind(bundle.bundle_id())
        .bind(bundle.policy_version())
        .bind(bundle.bundle_hash())
        .bind(&stored_event.event.event_id)
        .bind(occurred_at.as_datetime())
        .execute(&mut *transaction)
        .await?;
    }
    transaction.commit().await?;
    Ok(ActivePolicyBundle {
        bundle,
        previous_policy_version,
        previous_bundle_hash,
        lifecycle_version,
        last_event_id: stored_event.event.event_id,
        updated_at: occurred_at,
    })
}

fn policy_event(
    bundle: &PolicyBundle,
    previous_policy_bundle_hash: Option<String>,
    change_kind: &'static str,
    lifecycle_version: Option<u64>,
    actor_id: &str,
) -> AuditPayload {
    AuditPayload::PolicyChanged(PolicyChangedPayload {
        organization_id: Some(bundle.organization_id().into()),
        environment: Some(bundle.environment().into()),
        policy_bundle_id: bundle.bundle_id().into(),
        policy_version: Some(bundle.policy_version().into()),
        previous_policy_bundle_hash,
        policy_bundle_hash: bundle.bundle_hash().into(),
        change_kind: Some(change_kind.into()),
        lifecycle_version,
        actor_id: actor_id.into(),
    })
}

async fn fetch_bundle(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    environment: &str,
    bundle_id: &str,
    policy_version: &str,
    for_update: bool,
) -> Result<PolicyBundleRow, StoreError> {
    let suffix = if for_update { "FOR UPDATE" } else { "" };
    let query = format!(
        r#"
        SELECT organization_id, environment, bundle_id, policy_version,
               bundle_hash::text AS bundle_hash, activates_at, expires_at,
               artifact_bytes, artifact_hash::text AS artifact_hash,
               publisher_key_id, publisher_public_key,
               publisher_public_key_hash::text AS publisher_public_key_hash,
               signature, installed_by_operator_id, installed_event_id, installed_at
        FROM policy_bundles
        WHERE organization_id = $1 AND environment = $2
          AND bundle_id = $3 AND policy_version = $4
        {suffix}
        "#
    );
    sqlx::query_as(&query)
        .bind(organization_id)
        .bind(environment)
        .bind(bundle_id)
        .bind(policy_version)
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or_else(|| StoreError::PolicyBundleNotFound {
            organization_id: organization_id.into(),
            environment: environment.into(),
            bundle_id: bundle_id.into(),
            policy_version: policy_version.into(),
        })
}

async fn fetch_active(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    environment: &str,
    bundle_id: &str,
    for_update: bool,
) -> Result<Option<ActivePolicyRow>, StoreError> {
    let suffix = if for_update { "FOR UPDATE" } else { "" };
    let query = format!(
        r#"
        SELECT organization_id, environment, bundle_id, policy_version,
               bundle_hash::text AS bundle_hash, previous_policy_version,
               previous_bundle_hash::text AS previous_bundle_hash,
               lifecycle_version, last_event_id, updated_at
        FROM active_policy_bundles
        WHERE organization_id = $1 AND environment = $2 AND bundle_id = $3
        {suffix}
        "#
    );
    Ok(sqlx::query_as(&query)
        .bind(organization_id)
        .bind(environment)
        .bind(bundle_id)
        .fetch_optional(&mut **transaction)
        .await?)
}

fn verify_bundle_row(
    row: PolicyBundleRow,
    evaluated_at: Timestamp,
    chain: &[StoredAuditEvent],
) -> Result<VerifiedPolicyBundle, StoreError> {
    let fail = |reason: String| {
        corrupt(
            &row.organization_id,
            &row.environment,
            &row.bundle_id,
            reason,
        )
    };
    if atf_core::sha256_hex(&row.artifact_bytes) != row.artifact_hash
        || atf_core::sha256_hex(&row.publisher_public_key) != row.publisher_public_key_hash
    {
        return Err(fail(
            "artifact or publisher public-key hash mismatch".into(),
        ));
    }
    let public_key: [u8; 32] = row
        .publisher_public_key
        .as_slice()
        .try_into()
        .map_err(|_| fail("publisher public key length is invalid".into()))?;
    let signature: [u8; 64] = row
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| fail("signature length is invalid".into()))?;
    let artifact = PolicyBundleArtifact::decode(&row.artifact_bytes)
        .map_err(|error| fail(format!("artifact cannot be decoded: {error}")))?;
    let context = PolicyBundleLoadContext {
        organization_id: row.organization_id.clone(),
        environment: row.environment.clone(),
        evaluated_at,
    };
    let bundle = PolicyBundle::from_artifact(artifact, &context)
        .map_err(|error| fail(format!("artifact cannot be validated: {error}")))?;
    let proof = PolicyBundleSignature::from_parts(
        row.publisher_key_id.clone(),
        row.bundle_hash.clone(),
        signature,
    )
    .map_err(|error| fail(format!("signature proof cannot be decoded: {error}")))?;
    // RFC 8032 verification is performed over ATF's domain-separated message;
    // verify_strict additionally rejects weak/non-canonical edge cases.
    // Sources: https://www.rfc-editor.org/rfc/rfc8032
    // https://docs.rs/ed25519-dalek/3/ed25519_dalek/struct.VerifyingKey.html#method.verify_strict
    proof
        .verify(&bundle, &public_key)
        .map_err(|_| fail("publisher signature verification failed".into()))?;
    let columns_match = bundle.organization_id() == row.organization_id
        && bundle.environment() == row.environment
        && bundle.bundle_id() == row.bundle_id
        && bundle.policy_version() == row.policy_version
        && bundle.bundle_hash() == row.bundle_hash
        && bundle.activates_at() == Timestamp::from_datetime(row.activates_at)
        && bundle.expires_at() == Timestamp::from_datetime(row.expires_at);
    if !columns_match {
        return Err(fail(
            "artifact identity and redundant columns disagree".into(),
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
        && matches!(payload, AuditPayload::PolicyChanged(ref payload)
            if payload.organization_id.as_deref() == Some(&row.organization_id)
                && payload.environment.as_deref() == Some(&row.environment)
                && payload.policy_bundle_id == row.bundle_id
                && payload.policy_version.as_deref() == Some(&row.policy_version)
                && payload.previous_policy_bundle_hash.is_none()
                && payload.policy_bundle_hash == row.bundle_hash
                && payload.change_kind.as_deref() == Some("INSTALLED")
                && payload.lifecycle_version.is_none()
                && payload.actor_id == row.installed_by_operator_id);
    if !evidence_matches {
        return Err(fail(
            "install Audit event does not bind immutable Bundle state".into(),
        ));
    }
    Ok(VerifiedPolicyBundle { bundle })
}

fn verify_active_row(
    row: ActivePolicyRow,
    chain: &[StoredAuditEvent],
) -> Result<VerifiedActivePointer, StoreError> {
    let fail = |reason: String| {
        corrupt(
            &row.organization_id,
            &row.environment,
            &row.bundle_id,
            reason,
        )
    };
    if row.lifecycle_version <= 0
        || (row.previous_policy_version.is_none() != row.previous_bundle_hash.is_none())
        || row.previous_bundle_hash.as_deref() == Some(&row.bundle_hash)
    {
        return Err(fail("active pointer columns are invalid".into()));
    }
    let event = chain
        .iter()
        .find(|event| event.event.event_id == row.last_event_id)
        .ok_or_else(|| fail("pointer event is absent from Audit chain".into()))?;
    let payload = event
        .event
        .typed_payload()
        .map_err(|error| fail(format!("pointer Audit payload is invalid: {error}")))?;
    let version = u64::try_from(row.lifecycle_version)
        .map_err(|_| fail("pointer lifecycle version is invalid".into()))?;
    let evidence_matches = event.event.occurred_at == Timestamp::from_datetime(row.updated_at)
        && matches!(payload, AuditPayload::PolicyChanged(ref payload)
            if payload.organization_id.as_deref() == Some(&row.organization_id)
                && payload.environment.as_deref() == Some(&row.environment)
                && payload.policy_bundle_id == row.bundle_id
                && payload.policy_version.as_deref() == Some(&row.policy_version)
                && payload.previous_policy_bundle_hash == row.previous_bundle_hash
                && payload.policy_bundle_hash == row.bundle_hash
                && matches!(payload.change_kind.as_deref(), Some("ACTIVATED" | "ROLLED_BACK"))
                && payload.lifecycle_version == Some(version));
    if !evidence_matches {
        return Err(fail(
            "pointer Audit event does not bind active state".into(),
        ));
    }

    Ok(VerifiedActivePointer {
        policy_version: row.policy_version,
        bundle_hash: row.bundle_hash,
        previous_policy_version: row.previous_policy_version,
        previous_bundle_hash: row.previous_bundle_hash,
        lifecycle_version: row.lifecycle_version,
        last_event_id: row.last_event_id,
        updated_at: Timestamp::from_datetime(row.updated_at),
    })
}

fn validate_scope(
    organization_id: &str,
    environment: &str,
    bundle_id: &str,
    policy_version: Option<&str>,
) -> Result<(), StoreError> {
    for (field, value, max) in [
        ("organization_id", organization_id, 128),
        ("environment", environment, 128),
        ("bundle_id", bundle_id, 128),
    ] {
        if value.is_empty()
            || value.len() > max
            || !value.bytes().enumerate().all(|(index, byte)| {
                (index != 0 || byte.is_ascii_alphanumeric())
                    && (byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
            })
        {
            return Err(invalid(format!("{field} is not a canonical identifier")));
        }
    }
    if policy_version.is_some_and(|value| {
        value.is_empty()
            || value.len() > 64
            || value.trim() != value
            || value.bytes().any(|byte| byte.is_ascii_control())
    }) {
        return Err(invalid("policy_version is invalid"));
    }
    Ok(())
}

fn validate_timestamp(value: Timestamp) -> Result<(), StoreError> {
    if value.as_datetime().timestamp_subsec_nanos() % 1_000_000 == 0 {
        Ok(())
    } else {
        Err(invalid(
            "Policy mutation timestamp must be millisecond aligned",
        ))
    }
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

async fn set_read_transaction(
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

fn corrupt(
    organization_id: &str,
    environment: &str,
    bundle_id: &str,
    reason: impl Into<String>,
) -> StoreError {
    StoreError::PolicyStateCorrupt {
        organization_id: organization_id.into(),
        environment: environment.into(),
        bundle_id: bundle_id.into(),
        reason: reason.into(),
    }
}

fn invalid(reason: impl Into<String>) -> StoreError {
    StoreError::InvalidRepositoryInput {
        reason: reason.into(),
    }
}
