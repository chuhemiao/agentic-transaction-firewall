use atf_audit::{
    AgentRegisteredPayload, AgentStatusChangedPayload, AuditPayload, EventType,
    IdentityKeyRegisteredPayload, IdentityKeyRevokedPayload, IdentityRejectedPayload,
    IdentityVerifiedPayload, IntentReceivedPayload, NewAuditEvent, ReplayDetectedPayload,
    RequestScopeBinding,
};
use atf_core::{IntentLifecycleState, ProfileBinding, Timestamp};
use atf_identity::{EnvelopeVerificationContext, IdentityError};
use atf_intent::{validate_profile, TransactionIntent};
use chrono::{DateTime, Utc};
use sqlx::{FromRow, Postgres, Transaction};

use crate::audit::{append_in_transaction, AuditReferences, StoredAuditEvent};
use crate::idempotency::reserve_in_transaction;
use crate::identity::load_identity_snapshot_for_update;
use crate::lifecycle::CONTRACT_VERSION as LIFECYCLE_CONTRACT_VERSION;
use crate::models::{AdmissionGrant, AdmittedIntent, AuthenticatedAdmissionInput, StoredLifecycle};
use crate::repository::{
    map_admission_insert_error, normalize_intent, normalize_timestamp, set_write_timeouts,
};
use crate::{Store, StoreError};

const NONCE_REPLAY_REASON: &str = "NONCE_BINDING_CONFLICT";

#[derive(Debug, FromRow)]
struct NonceRow {
    organization_id: String,
    agent_id: String,
    nonce_hash: String,
    key_id: String,
    intent_id: String,
    intent_hash: String,
    idempotency_key: String,
    envelope_hash: String,
    envelope_expires_at: DateTime<Utc>,
    agent_lifecycle_version: i64,
    agent_record_hash: String,
    key_lifecycle_version: i64,
    key_record_hash: String,
    verified_event_id: String,
    consumed_at: DateTime<Utc>,
}

impl Store {
    /// Verify current durable identity under row locks, consume the signed
    /// Nonce and coordinate it with the idempotency reservation. No Policy or
    /// Risk work runs inside this transaction.
    pub async fn authenticate_and_admit(
        &self,
        input: AuthenticatedAdmissionInput,
    ) -> Result<AdmissionGrant, StoreError> {
        let intent = normalize_intent(input.intent)?;
        let received_at = normalize_timestamp(input.received_at);
        let organization_id = intent.principal.organization_id.clone();
        let intent_hash = intent.canonical_hash();
        let context = EnvelopeVerificationContext {
            audience: &input.audience,
            environment: &input.environment,
            verification_time: received_at,
        };

        let mut transaction = self.pool.begin().await?;
        set_write_timeouts(&mut transaction).await?;
        ensure_organization(&mut transaction, &organization_id).await?;

        if let Err(error) = input.envelope.validate(&intent, &context) {
            return reject_and_commit(transaction, &intent, error.code(), received_at).await;
        }

        let (snapshot, chain) = match load_identity_snapshot_for_update(
            &mut transaction,
            &organization_id,
            &input.envelope.agent_id,
            &input.envelope.key_id,
        )
        .await
        {
            Ok(value) => value,
            Err(StoreError::AgentNotFound { .. }) => {
                return reject_and_commit(
                    transaction,
                    &intent,
                    IdentityError::UnknownAgent(input.envelope.agent_id.clone()).code(),
                    received_at,
                )
                .await;
            }
            Err(StoreError::IdentityKeyNotFound { .. }) => {
                return reject_and_commit(
                    transaction,
                    &intent,
                    IdentityError::UnknownKey {
                        agent_id: input.envelope.agent_id.clone(),
                        key_id: input.envelope.key_id.clone(),
                    }
                    .code(),
                    received_at,
                )
                .await;
            }
            Err(error) => return Err(error),
        };

        if let Err(error) =
            snapshot.verify_envelope(&intent, &input.envelope, &input.signature, &context)
        {
            return reject_and_commit(transaction, &intent, error.code(), received_at).await;
        }

        let envelope_hash = atf_core::sha256_hex(&input.envelope.canonical_bytes());
        let nonce_hash = atf_core::sha256_hex(input.envelope.nonce.as_bytes());
        let identity = IdentityVerifiedPayload {
            organization_id: organization_id.clone(),
            agent_id: input.envelope.agent_id.clone(),
            key_id: input.envelope.key_id.clone(),
            envelope_hash: envelope_hash.clone(),
        };
        let verified_event_id = atf_core::new_ulid();

        let inserted = insert_nonce(
            &mut transaction,
            &intent,
            &input.envelope.key_id,
            &nonce_hash,
            &envelope_hash,
            input.envelope.expires_at,
            snapshot.agent().lifecycle_version,
            &snapshot.agent().record.canonical_hash(),
            snapshot.key().lifecycle_version,
            &snapshot.key().key_record_hash,
            &verified_event_id,
            received_at,
        )
        .await?;

        if !inserted {
            let row = fetch_nonce_for_update(
                &mut transaction,
                &organization_id,
                &input.envelope.agent_id,
                &nonce_hash,
            )
            .await?
            .ok_or_else(|| {
                nonce_corrupt(
                    &organization_id,
                    &input.envelope.agent_id,
                    "conflicting Nonce disappeared",
                )
            })?;
            verify_nonce_row(&row, &chain)?;
            if nonce_matches(
                &row,
                &intent,
                &input.envelope.key_id,
                &nonce_hash,
                &envelope_hash,
                input.envelope.expires_at,
            ) {
                return classify_exact_retry(
                    &mut transaction,
                    &intent,
                    &intent_hash,
                    input.lease_duration,
                )
                .await;
            }

            let replay = NewAuditEvent::from_payload(
                received_at,
                None,
                AuditPayload::ReplayDetected(ReplayDetectedPayload {
                    organization_id: organization_id.clone(),
                    agent_id: input.envelope.agent_id.clone(),
                    key_id: input.envelope.key_id.clone(),
                    nonce_hash: nonce_hash.clone(),
                    attempted_intent_id: intent.intent_id.clone(),
                    attempted_intent_hash: intent_hash,
                    bound_intent_id: row.intent_id,
                    bound_intent_hash: row.intent_hash,
                    reason_code: NONCE_REPLAY_REASON.into(),
                }),
            )?;
            append_in_transaction(
                &mut transaction,
                &organization_id,
                replay,
                AuditReferences::default(),
            )
            .await?;
            transaction.commit().await?;
            return Err(StoreError::NonceReplay {
                organization_id,
                agent_id: input.envelope.agent_id,
                nonce_hash,
            });
        }

        match reserve_in_transaction(
            &mut transaction,
            &intent,
            &intent_hash,
            input.lease_duration,
        )
        .await
        {
            Ok(evaluator_lease) => {
                let (admitted, _) = insert_authenticated_intent(
                    &mut transaction,
                    intent,
                    intent_hash,
                    received_at,
                    identity,
                    verified_event_id,
                )
                .await?;
                transaction.commit().await?;
                Ok(AdmissionGrant {
                    admitted,
                    evaluator_lease,
                })
            }
            Err(error @ StoreError::IdempotencyCompleted { .. })
            | Err(error @ StoreError::IdempotencyInProgress { .. }) => {
                load_initial_identity_evidence(
                    &mut transaction,
                    &organization_id,
                    &intent.intent_id,
                    &intent_hash,
                    &chain,
                )
                .await?;
                let retry_event = event_with_id(
                    verified_event_id,
                    received_at,
                    None,
                    AuditPayload::IdentityVerified(identity),
                )?;
                append_in_transaction(
                    &mut transaction,
                    &organization_id,
                    retry_event,
                    AuditReferences::default(),
                )
                .await?;
                transaction.commit().await?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    /// Persist a rejected identity attempt without admitting or reserving the
    /// untrusted Intent. The claimed organization must already exist; this
    /// operation never provisions a tenant from caller-controlled input.
    pub async fn record_identity_rejection(
        &self,
        intent: &TransactionIntent,
        reason_code: &'static str,
        occurred_at: Timestamp,
    ) -> Result<(), StoreError> {
        let occurred_at = normalize_timestamp(occurred_at);
        let mut transaction = self.pool.begin().await?;
        set_write_timeouts(&mut transaction).await?;
        ensure_organization(&mut transaction, &intent.principal.organization_id).await?;
        append_rejection(&mut transaction, intent, reason_code, occurred_at).await?;
        transaction.commit().await?;
        Ok(())
    }
}

async fn insert_authenticated_intent(
    transaction: &mut Transaction<'_, Postgres>,
    intent: TransactionIntent,
    intent_hash: String,
    received_at: Timestamp,
    identity: IdentityVerifiedPayload,
    verified_event_id: String,
) -> Result<(AdmittedIntent, StoredAuditEvent), StoreError> {
    let organization_id = intent.principal.organization_id.clone();
    let profile =
        validate_profile(&intent).map_err(|error| StoreError::InvalidRepositoryInput {
            reason: format!("admitted Intent Profile is invalid: {error}"),
        })?;
    let received_payload = AuditPayload::IntentReceived(IntentReceivedPayload {
        organization_id: organization_id.clone(),
        agent_id: intent.principal.agent_id.clone(),
        idempotency_key: intent.idempotency_key.clone(),
        intent_hash: intent_hash.clone(),
        amount: intent.transaction.amount,
        resource_id: intent.resource.resource_id.clone(),
        binding: Some(RequestScopeBinding {
            profile: ProfileBinding {
                id: profile.id().into(),
                version: profile.version().into(),
            },
            action_category: intent.action.category.clone(),
            action_operation: intent.action.operation.clone(),
        }),
    });
    let received_event = NewAuditEvent::from_payload(
        received_at,
        Some(intent.intent_id.clone()),
        received_payload,
    )?;
    let verified_event = event_with_id(
        verified_event_id,
        received_at,
        Some(intent.intent_id.clone()),
        AuditPayload::IdentityVerified(identity.clone()),
    )?;
    let lifecycle = StoredLifecycle {
        state: IntentLifecycleState::IdentityVerified,
        version: 2,
        contract_version: LIFECYCLE_CONTRACT_VERSION,
        last_event_id: Some(verified_event.event_id.clone()),
        updated_at: received_at,
    };

    sqlx::query(
        r#"
        INSERT INTO intents (
            organization_id, intent_id, idempotency_key, spec_version,
            canonical_intent, canonical_intent_bytes, intent_hash,
            created_at, expires_at, received_at, lifecycle_state,
            lifecycle_version, lifecycle_contract_version,
            lifecycle_event_id, lifecycle_updated_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15
        )
        "#,
    )
    .bind(&organization_id)
    .bind(&intent.intent_id)
    .bind(&intent.idempotency_key)
    .bind(&intent.spec_version)
    .bind(intent.canonical_value())
    .bind(intent.canonical_bytes())
    .bind(&intent_hash)
    .bind(intent.created_at.as_datetime())
    .bind(intent.expires_at.as_datetime())
    .bind(received_at.as_datetime())
    .bind(lifecycle.state.as_str())
    .bind(lifecycle.version)
    .bind(lifecycle.contract_version)
    .bind(&lifecycle.last_event_id)
    .bind(lifecycle.updated_at.as_datetime())
    .execute(&mut **transaction)
    .await
    .map_err(|error| map_admission_insert_error(error, &intent))?;

    let audit_event = append_in_transaction(
        transaction,
        &organization_id,
        received_event,
        AuditReferences::default(),
    )
    .await?;
    let identity_event = append_in_transaction(
        transaction,
        &organization_id,
        verified_event,
        AuditReferences::default(),
    )
    .await?;
    if lifecycle.last_event_id.as_deref() != Some(identity_event.event.event_id.as_str()) {
        return Err(nonce_corrupt(
            &organization_id,
            &intent.principal.agent_id,
            "Identity lifecycle pointer does not match the committed verification event",
        ));
    }

    Ok((
        AdmittedIntent {
            organization_id,
            intent,
            intent_hash,
            received_at,
            lifecycle,
            audit_event,
            identity,
        },
        identity_event,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn insert_nonce(
    transaction: &mut Transaction<'_, Postgres>,
    intent: &TransactionIntent,
    key_id: &str,
    nonce_hash: &str,
    envelope_hash: &str,
    envelope_expires_at: Timestamp,
    agent_lifecycle_version: i64,
    agent_record_hash: &str,
    key_lifecycle_version: i64,
    key_record_hash: &str,
    verified_event_id: &str,
    consumed_at: Timestamp,
) -> Result<bool, StoreError> {
    let result = sqlx::query(
        r#"
        INSERT INTO identity_nonces (
            organization_id, agent_id, nonce_hash, key_id, intent_id,
            intent_hash, idempotency_key, envelope_hash, envelope_expires_at,
            agent_lifecycle_version, agent_record_hash,
            key_lifecycle_version, key_record_hash,
            verified_event_id, consumed_at
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
            $11, $12, $13, $14, $15
        )
        ON CONFLICT (organization_id, agent_id, nonce_hash) DO NOTHING
        "#,
    )
    .bind(&intent.principal.organization_id)
    .bind(&intent.principal.agent_id)
    .bind(nonce_hash)
    .bind(key_id)
    .bind(&intent.intent_id)
    .bind(intent.canonical_hash())
    .bind(&intent.idempotency_key)
    .bind(envelope_hash)
    .bind(envelope_expires_at.as_datetime())
    .bind(agent_lifecycle_version)
    .bind(agent_record_hash)
    .bind(key_lifecycle_version)
    .bind(key_record_hash)
    .bind(verified_event_id)
    .bind(consumed_at.as_datetime())
    .execute(&mut **transaction)
    .await?;
    Ok(result.rows_affected() == 1)
}

async fn classify_exact_retry(
    transaction: &mut Transaction<'_, Postgres>,
    intent: &TransactionIntent,
    intent_hash: &str,
    lease_duration: std::time::Duration,
) -> Result<AdmissionGrant, StoreError> {
    match reserve_in_transaction(transaction, intent, intent_hash, lease_duration).await {
        Err(error @ StoreError::IdempotencyCompleted { .. })
        | Err(error @ StoreError::IdempotencyInProgress { .. }) => Err(error),
        Ok(_) | Err(StoreError::IdempotencyConflict { .. }) => Err(nonce_corrupt(
            &intent.principal.organization_id,
            &intent.principal.agent_id,
            "a committed exact Nonce binding disagrees with idempotency state",
        )),
        Err(error) => Err(error),
    }
}

pub(crate) async fn load_initial_identity_evidence(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    intent_id: &str,
    expected_intent_hash: &str,
    chain: &[StoredAuditEvent],
) -> Result<IdentityVerifiedPayload, StoreError> {
    let mut events = chain.iter().filter(|stored| {
        stored.event.event_type == EventType::IdentityVerified
            && stored.event.intent_id.as_deref() == Some(intent_id)
    });
    let event = events
        .next()
        .ok_or_else(|| StoreError::IncompleteAdmissionEvidence {
            organization_id: organization_id.to_owned(),
            intent_id: intent_id.to_owned(),
        })?;
    if events.next().is_some() {
        return Err(StoreError::IncompleteAdmissionEvidence {
            organization_id: organization_id.to_owned(),
            intent_id: intent_id.to_owned(),
        });
    }
    let payload = match event.event.typed_payload()? {
        AuditPayload::IdentityVerified(payload) => payload,
        _ => {
            return Err(StoreError::IncompleteAdmissionEvidence {
                organization_id: organization_id.to_owned(),
                intent_id: intent_id.to_owned(),
            })
        }
    };
    let row = fetch_nonce_by_event(transaction, organization_id, &event.event.event_id)
        .await?
        .ok_or_else(|| StoreError::IncompleteAdmissionEvidence {
            organization_id: organization_id.to_owned(),
            intent_id: intent_id.to_owned(),
        })?;
    verify_nonce_row(&row, chain)?;
    if row.intent_id != intent_id
        || row.intent_hash != expected_intent_hash
        || payload.organization_id != organization_id
        || payload.agent_id != row.agent_id
        || payload.key_id != row.key_id
        || payload.envelope_hash != row.envelope_hash
    {
        return Err(StoreError::IncompleteAdmissionEvidence {
            organization_id: organization_id.to_owned(),
            intent_id: intent_id.to_owned(),
        });
    }
    Ok(payload)
}

async fn reject_and_commit(
    mut transaction: Transaction<'_, Postgres>,
    intent: &TransactionIntent,
    reason_code: &'static str,
    occurred_at: Timestamp,
) -> Result<AdmissionGrant, StoreError> {
    append_rejection(&mut transaction, intent, reason_code, occurred_at).await?;
    transaction.commit().await?;
    Err(StoreError::IdentityRejected { reason_code })
}

async fn append_rejection(
    transaction: &mut Transaction<'_, Postgres>,
    intent: &TransactionIntent,
    reason_code: &'static str,
    occurred_at: Timestamp,
) -> Result<(), StoreError> {
    let event = NewAuditEvent::from_payload(
        occurred_at,
        None,
        AuditPayload::IdentityRejected(IdentityRejectedPayload {
            organization_id: intent.principal.organization_id.clone(),
            agent_id: intent.principal.agent_id.clone(),
            reason_code: reason_code.to_owned(),
        }),
    )?;
    append_in_transaction(
        transaction,
        &intent.principal.organization_id,
        event,
        AuditReferences::default(),
    )
    .await?;
    Ok(())
}

fn event_with_id(
    event_id: String,
    occurred_at: Timestamp,
    intent_id: Option<String>,
    payload: AuditPayload,
) -> Result<NewAuditEvent, StoreError> {
    let mut event = NewAuditEvent::from_payload(occurred_at, intent_id, payload)?;
    event.event_id = event_id;
    Ok(event)
}

async fn fetch_nonce_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    agent_id: &str,
    nonce_hash: &str,
) -> Result<Option<NonceRow>, StoreError> {
    sqlx::query_as(
        r#"
        SELECT organization_id, agent_id, nonce_hash::text AS nonce_hash,
               key_id, intent_id, intent_hash::text AS intent_hash,
               idempotency_key, envelope_hash::text AS envelope_hash,
               envelope_expires_at, agent_lifecycle_version,
               agent_record_hash::text AS agent_record_hash,
               key_lifecycle_version, key_record_hash::text AS key_record_hash,
               verified_event_id, consumed_at
        FROM identity_nonces
        WHERE organization_id = $1 AND agent_id = $2 AND nonce_hash = $3
        FOR UPDATE
        "#,
    )
    .bind(organization_id)
    .bind(agent_id)
    .bind(nonce_hash)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::Database)
}

async fn fetch_nonce_by_event(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    verified_event_id: &str,
) -> Result<Option<NonceRow>, StoreError> {
    sqlx::query_as(
        r#"
        SELECT organization_id, agent_id, nonce_hash::text AS nonce_hash,
               key_id, intent_id, intent_hash::text AS intent_hash,
               idempotency_key, envelope_hash::text AS envelope_hash,
               envelope_expires_at, agent_lifecycle_version,
               agent_record_hash::text AS agent_record_hash,
               key_lifecycle_version, key_record_hash::text AS key_record_hash,
               verified_event_id, consumed_at
        FROM identity_nonces
        WHERE organization_id = $1 AND verified_event_id = $2
        "#,
    )
    .bind(organization_id)
    .bind(verified_event_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(StoreError::Database)
}

fn verify_nonce_row(row: &NonceRow, chain: &[StoredAuditEvent]) -> Result<(), StoreError> {
    let event = chain
        .iter()
        .find(|stored| stored.event.event_id == row.verified_event_id)
        .ok_or_else(|| {
            nonce_corrupt(
                &row.organization_id,
                &row.agent_id,
                "verified_event_id is absent from the Audit chain",
            )
        })?;
    let payload = match event.event.typed_payload().map_err(|error| {
        nonce_corrupt(
            &row.organization_id,
            &row.agent_id,
            format!("verification Audit payload is invalid: {error}"),
        )
    })? {
        AuditPayload::IdentityVerified(payload) => payload,
        _ => {
            return Err(nonce_corrupt(
                &row.organization_id,
                &row.agent_id,
                "verified_event_id does not name IdentityVerified",
            ))
        }
    };
    let event_scope_matches = event.event.intent_id.is_none()
        || event.event.intent_id.as_deref() == Some(row.intent_id.as_str());
    let columns_match = event_scope_matches
        && event.event.occurred_at == Timestamp::from_datetime(row.consumed_at)
        && payload.organization_id == row.organization_id
        && payload.agent_id == row.agent_id
        && payload.key_id == row.key_id
        && payload.envelope_hash == row.envelope_hash
        && row.envelope_expires_at > row.consumed_at
        && row.agent_lifecycle_version > 0
        && row.key_lifecycle_version > 0;
    if !columns_match {
        return Err(nonce_corrupt(
            &row.organization_id,
            &row.agent_id,
            "Nonce columns disagree with IdentityVerified evidence",
        ));
    }
    if !agent_version_matches(row, chain) || !key_version_matches(row, chain) {
        return Err(nonce_corrupt(
            &row.organization_id,
            &row.agent_id,
            "Nonce identity lifecycle version lacks matching Audit evidence",
        ));
    }
    Ok(())
}

fn agent_version_matches(row: &NonceRow, chain: &[StoredAuditEvent]) -> bool {
    chain
        .iter()
        .any(|stored| match stored.event.typed_payload() {
            Ok(AuditPayload::AgentRegistered(AgentRegisteredPayload {
                organization_id,
                agent_id,
                record_hash,
                lifecycle_version,
                ..
            }))
            | Ok(AuditPayload::AgentStatusChanged(AgentStatusChangedPayload {
                organization_id,
                agent_id,
                record_hash,
                lifecycle_version,
                ..
            })) => {
                organization_id == row.organization_id
                    && agent_id == row.agent_id
                    && record_hash == row.agent_record_hash
                    && i64::try_from(lifecycle_version).ok() == Some(row.agent_lifecycle_version)
            }
            _ => false,
        })
}

fn key_version_matches(row: &NonceRow, chain: &[StoredAuditEvent]) -> bool {
    chain
        .iter()
        .any(|stored| match stored.event.typed_payload() {
            Ok(AuditPayload::IdentityKeyRegistered(IdentityKeyRegisteredPayload {
                organization_id,
                agent_id,
                key_id,
                key_record_hash,
                lifecycle_version,
                ..
            }))
            | Ok(AuditPayload::IdentityKeyRevoked(IdentityKeyRevokedPayload {
                organization_id,
                agent_id,
                key_id,
                key_record_hash,
                lifecycle_version,
                ..
            })) => {
                organization_id == row.organization_id
                    && agent_id == row.agent_id
                    && key_id == row.key_id
                    && key_record_hash == row.key_record_hash
                    && i64::try_from(lifecycle_version).ok() == Some(row.key_lifecycle_version)
            }
            _ => false,
        })
}

fn nonce_matches(
    row: &NonceRow,
    intent: &TransactionIntent,
    key_id: &str,
    nonce_hash: &str,
    envelope_hash: &str,
    envelope_expires_at: Timestamp,
) -> bool {
    row.organization_id == intent.principal.organization_id
        && row.agent_id == intent.principal.agent_id
        && row.key_id == key_id
        && row.nonce_hash == nonce_hash
        && row.intent_id == intent.intent_id
        && row.intent_hash == intent.canonical_hash()
        && row.idempotency_key == intent.idempotency_key
        && row.envelope_hash == envelope_hash
        && Timestamp::from_datetime(row.envelope_expires_at) == envelope_expires_at
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

fn nonce_corrupt(organization_id: &str, agent_id: &str, reason: impl Into<String>) -> StoreError {
    StoreError::NonceStateCorrupt {
        organization_id: organization_id.to_owned(),
        agent_id: agent_id.to_owned(),
        reason: reason.into(),
    }
}
