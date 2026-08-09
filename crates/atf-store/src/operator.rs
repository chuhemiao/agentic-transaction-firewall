use atf_audit::{
    AuditPayload, NewAuditEvent, OperatorRegisteredPayload, OperatorRoleChangedPayload,
    OperatorStatusChangedPayload,
};
use atf_core::Timestamp;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{FromRow, Postgres, Transaction};

use crate::audit::{append_in_transaction, load_verified_in_transaction, AuditReferences};
use crate::{Store, StoreError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperatorKind {
    Human,
    Service,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OperatorStatus {
    Active,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperatorRole {
    Approver,
    Auditor,
    OrgAdmin,
    PolicyAuthor,
}

impl OperatorRole {
    pub const fn can_read_decisions(self) -> bool {
        matches!(self, Self::Auditor | Self::OrgAdmin)
    }

    pub const fn can_read_audit(self) -> bool {
        matches!(self, Self::Auditor | Self::OrgAdmin)
    }

    pub const fn can_change_policy(self) -> bool {
        matches!(self, Self::PolicyAuthor | Self::OrgAdmin)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorRegistration {
    pub operator_id: String,
    pub issuer_id: String,
    pub subject_fingerprint: String,
    pub principal_kind: OperatorKind,
    pub audit_organization_id: String,
    pub created_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredOperator {
    pub operator_id: String,
    pub issuer_id: String,
    pub subject_fingerprint: String,
    pub principal_kind: OperatorKind,
    pub status: OperatorStatus,
    pub audit_organization_id: String,
    pub record_hash: String,
    pub lifecycle_version: i64,
    pub last_event_id: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorRoleBinding {
    pub operator_id: String,
    pub organization_id: String,
    pub role: OperatorRole,
    pub active: bool,
    pub binding_hash: String,
    pub lifecycle_version: i64,
    pub last_event_id: String,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorPrincipal {
    pub operator_id: String,
    pub principal_kind: OperatorKind,
    pub issuer_id: String,
    pub subject_fingerprint: String,
    pub organization_id: String,
    pub roles: Vec<OperatorRole>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalOperator {
    operator_id: String,
    issuer_id: String,
    subject_fingerprint: String,
    principal_kind: OperatorKind,
    status: OperatorStatus,
    audit_organization_id: String,
    created_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CanonicalRoleBinding {
    operator_id: String,
    organization_id: String,
    role: OperatorRole,
    status: RoleBindingStatus,
    created_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum RoleBindingStatus {
    Active,
    Revoked,
}

#[derive(Debug, FromRow)]
struct OperatorRow {
    operator_id: String,
    issuer_id: String,
    subject_fingerprint: String,
    principal_kind: String,
    status: String,
    audit_organization_id: String,
    canonical_record: Value,
    canonical_record_bytes: Vec<u8>,
    record_hash: String,
    lifecycle_version: i64,
    last_event_id: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, FromRow)]
struct RoleRow {
    operator_id: String,
    organization_id: String,
    role: String,
    status: String,
    canonical_binding: Value,
    canonical_binding_bytes: Vec<u8>,
    binding_hash: String,
    lifecycle_version: i64,
    last_event_id: String,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

pub fn operator_subject_fingerprint(issuer: &str, subject: &str) -> Result<String, StoreError> {
    if issuer.is_empty()
        || issuer.trim() != issuer
        || issuer.len() > 2_048
        || issuer
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(invalid(
            "issuer must be 1..2048 trimmed, control-free bytes",
        ));
    }
    if subject.is_empty()
        || subject.len() > 512
        || subject
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
        return Err(invalid(
            "external subject must be 1..512 control-free bytes",
        ));
    }
    let mut binding = Vec::with_capacity(issuer.len() + subject.len() + 1);
    binding.extend_from_slice(issuer.as_bytes());
    binding.push(0);
    binding.extend_from_slice(subject.as_bytes());
    Ok(atf_core::sha256_hex(&binding))
}

impl Store {
    pub async fn provision_operator(
        &self,
        registration: OperatorRegistration,
        actor_id: &str,
        occurred_at: Timestamp,
    ) -> Result<StoredOperator, StoreError> {
        validate_registration(&registration)?;
        validate_identifier("actor_id", actor_id)?;
        validate_timestamp("occurred_at", occurred_at)?;
        if occurred_at < registration.created_at {
            return Err(invalid(
                "occurred_at cannot precede the Operator creation time",
            ));
        }

        let canonical = CanonicalOperator {
            operator_id: registration.operator_id.clone(),
            issuer_id: registration.issuer_id.clone(),
            subject_fingerprint: registration.subject_fingerprint.clone(),
            principal_kind: registration.principal_kind,
            status: OperatorStatus::Active,
            audit_organization_id: registration.audit_organization_id.clone(),
            created_at: registration.created_at,
        };
        let (canonical_record, canonical_record_bytes, record_hash) =
            canonical_operator(&canonical)?;

        let mut transaction = self.pool.begin().await?;
        set_mutation_timeouts(&mut transaction).await?;
        ensure_organization(&mut transaction, &registration.audit_organization_id).await?;
        let event = NewAuditEvent::from_payload(
            occurred_at,
            None,
            AuditPayload::OperatorRegistered(OperatorRegisteredPayload {
                organization_id: registration.audit_organization_id.clone(),
                operator_id: registration.operator_id.clone(),
                issuer_id: registration.issuer_id.clone(),
                subject_fingerprint: registration.subject_fingerprint.clone(),
                principal_kind: kind_name(registration.principal_kind).into(),
                status: status_name(OperatorStatus::Active).into(),
                record_hash: record_hash.clone(),
                lifecycle_version: 1,
                actor_id: actor_id.into(),
            }),
        )?;
        let stored_event = append_in_transaction(
            &mut transaction,
            &registration.audit_organization_id,
            event,
            AuditReferences::default(),
        )
        .await?;

        let inserted = sqlx::query(
            r#"
            INSERT INTO operator_subjects (
                operator_id, issuer_id, subject_fingerprint, principal_kind,
                status, audit_organization_id, canonical_record,
                canonical_record_bytes, record_hash, lifecycle_version,
                last_event_id, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, 'ACTIVE', $5, $6, $7, $8, 1, $9, $10, $11)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(&registration.operator_id)
        .bind(&registration.issuer_id)
        .bind(&registration.subject_fingerprint)
        .bind(kind_name(registration.principal_kind))
        .bind(&registration.audit_organization_id)
        .bind(&canonical_record)
        .bind(&canonical_record_bytes)
        .bind(&record_hash)
        .bind(&stored_event.event.event_id)
        .bind(registration.created_at.as_datetime())
        .bind(occurred_at.as_datetime())
        .execute(&mut *transaction)
        .await?;
        if inserted.rows_affected() != 1 {
            return Err(StoreError::OperatorConflict {
                operator_id: registration.operator_id,
            });
        }
        transaction.commit().await?;
        Ok(StoredOperator {
            operator_id: canonical.operator_id,
            issuer_id: canonical.issuer_id,
            subject_fingerprint: canonical.subject_fingerprint,
            principal_kind: canonical.principal_kind,
            status: canonical.status,
            audit_organization_id: canonical.audit_organization_id,
            record_hash,
            lifecycle_version: 1,
            last_event_id: stored_event.event.event_id,
            created_at: canonical.created_at,
            updated_at: occurred_at,
        })
    }

    pub async fn load_operator(&self, operator_id: &str) -> Result<StoredOperator, StoreError> {
        validate_identifier("operator_id", operator_id)?;
        let mut transaction = self.pool.begin().await?;
        set_read_transaction(&mut transaction).await?;
        let row = fetch_operator(&mut transaction, operator_id).await?;
        let chain =
            load_verified_in_transaction(&mut transaction, &row.audit_organization_id).await?;
        let operator = verify_operator_row(row, &chain)?;
        transaction.commit().await?;
        Ok(operator)
    }

    pub async fn set_operator_status(
        &self,
        operator_id: &str,
        status: OperatorStatus,
        actor_id: &str,
        reason_code: &str,
        occurred_at: Timestamp,
    ) -> Result<StoredOperator, StoreError> {
        validate_identifier("operator_id", operator_id)?;
        validate_identifier("actor_id", actor_id)?;
        validate_identifier("reason_code", reason_code)?;
        validate_timestamp("occurred_at", occurred_at)?;

        let mut transaction = self.pool.begin().await?;
        set_mutation_timeouts(&mut transaction).await?;
        let row = fetch_operator_for_update(&mut transaction, operator_id).await?;
        let chain =
            load_verified_in_transaction(&mut transaction, &row.audit_organization_id).await?;
        let current = verify_operator_row(row, &chain)?;
        if current.status == status {
            return Err(invalid("Operator status transition must change status"));
        }
        if occurred_at < current.updated_at {
            return Err(invalid(
                "occurred_at cannot precede the current Operator lifecycle version",
            ));
        }
        let version = current
            .lifecycle_version
            .checked_add(1)
            .ok_or_else(|| invalid("Operator lifecycle version overflow"))?;
        let audit_version = u64::try_from(version)
            .map_err(|_| invalid("Operator lifecycle version is outside Audit representation"))?;
        let canonical = CanonicalOperator {
            operator_id: current.operator_id.clone(),
            issuer_id: current.issuer_id.clone(),
            subject_fingerprint: current.subject_fingerprint.clone(),
            principal_kind: current.principal_kind,
            status,
            audit_organization_id: current.audit_organization_id.clone(),
            created_at: current.created_at,
        };
        let (canonical_record, canonical_record_bytes, record_hash) =
            canonical_operator(&canonical)?;
        let event = NewAuditEvent::from_payload(
            occurred_at,
            None,
            AuditPayload::OperatorStatusChanged(OperatorStatusChangedPayload {
                organization_id: current.audit_organization_id.clone(),
                operator_id: current.operator_id.clone(),
                previous_status: status_name(current.status).into(),
                status: status_name(status).into(),
                record_hash: record_hash.clone(),
                lifecycle_version: audit_version,
                actor_id: actor_id.into(),
                reason_code: reason_code.into(),
            }),
        )?;
        let stored_event = append_in_transaction(
            &mut transaction,
            &current.audit_organization_id,
            event,
            AuditReferences::default(),
        )
        .await?;
        let updated = sqlx::query(
            r#"
            UPDATE operator_subjects
            SET status = $2, canonical_record = $3,
                canonical_record_bytes = $4, record_hash = $5,
                lifecycle_version = $6, last_event_id = $7, updated_at = $8
            WHERE operator_id = $1
            "#,
        )
        .bind(operator_id)
        .bind(status_name(status))
        .bind(&canonical_record)
        .bind(&canonical_record_bytes)
        .bind(&record_hash)
        .bind(version)
        .bind(&stored_event.event.event_id)
        .bind(occurred_at.as_datetime())
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::OperatorNotFound {
                operator_id: operator_id.into(),
            });
        }
        transaction.commit().await?;
        Ok(StoredOperator {
            operator_id: canonical.operator_id,
            issuer_id: canonical.issuer_id,
            subject_fingerprint: canonical.subject_fingerprint,
            principal_kind: canonical.principal_kind,
            status,
            audit_organization_id: canonical.audit_organization_id,
            record_hash,
            lifecycle_version: version,
            last_event_id: stored_event.event.event_id,
            created_at: canonical.created_at,
            updated_at: occurred_at,
        })
    }

    pub async fn grant_operator_role(
        &self,
        operator_id: &str,
        organization_id: &str,
        role: OperatorRole,
        actor_id: &str,
        reason_code: &str,
        occurred_at: Timestamp,
    ) -> Result<OperatorRoleBinding, StoreError> {
        self.change_operator_role(
            operator_id,
            organization_id,
            role,
            RoleBindingStatus::Active,
            actor_id,
            reason_code,
            occurred_at,
        )
        .await
    }

    pub async fn revoke_operator_role(
        &self,
        operator_id: &str,
        organization_id: &str,
        role: OperatorRole,
        actor_id: &str,
        reason_code: &str,
        occurred_at: Timestamp,
    ) -> Result<OperatorRoleBinding, StoreError> {
        self.change_operator_role(
            operator_id,
            organization_id,
            role,
            RoleBindingStatus::Revoked,
            actor_id,
            reason_code,
            occurred_at,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn change_operator_role(
        &self,
        operator_id: &str,
        organization_id: &str,
        role: OperatorRole,
        target: RoleBindingStatus,
        actor_id: &str,
        reason_code: &str,
        occurred_at: Timestamp,
    ) -> Result<OperatorRoleBinding, StoreError> {
        validate_identifier("operator_id", operator_id)?;
        validate_identifier("organization_id", organization_id)?;
        validate_identifier("actor_id", actor_id)?;
        validate_identifier("reason_code", reason_code)?;
        validate_timestamp("occurred_at", occurred_at)?;

        let mut transaction = self.pool.begin().await?;
        set_mutation_timeouts(&mut transaction).await?;
        ensure_organization(&mut transaction, organization_id).await?;
        let operator_row = fetch_operator_for_update(&mut transaction, operator_id).await?;
        let operator_chain =
            load_verified_in_transaction(&mut transaction, &operator_row.audit_organization_id)
                .await?;
        let _operator = verify_operator_row(operator_row, &operator_chain)?;

        let existing =
            fetch_role_for_update(&mut transaction, operator_id, organization_id, role).await?;
        let role_chain = if existing.is_some() {
            Some(load_verified_in_transaction(&mut transaction, organization_id).await?)
        } else {
            None
        };
        let (version, created_at) = match existing {
            Some(row) => {
                let current = verify_role_row(
                    row,
                    role_chain
                        .as_deref()
                        .expect("existing role loaded its verified organization chain"),
                )?;
                if current.active == matches!(target, RoleBindingStatus::Active) {
                    return Err(StoreError::OperatorRoleConflict {
                        operator_id: operator_id.into(),
                        organization_id: organization_id.into(),
                        role: role_name(role).into(),
                    });
                }
                (
                    current
                        .lifecycle_version
                        .checked_add(1)
                        .ok_or_else(|| invalid("Operator role lifecycle version overflow"))?,
                    current.created_at,
                )
            }
            None if matches!(target, RoleBindingStatus::Active) => (1, occurred_at),
            None => {
                return Err(StoreError::OperatorRoleNotFound {
                    operator_id: operator_id.into(),
                    organization_id: organization_id.into(),
                    role: role_name(role).into(),
                })
            }
        };

        finish_role_change(
            transaction,
            operator_id,
            organization_id,
            role,
            target,
            version,
            created_at,
            actor_id,
            reason_code,
            occurred_at,
        )
        .await
    }

    pub async fn resolve_operator_principal(
        &self,
        issuer_id: &str,
        subject_fingerprint: &str,
        organization_id: &str,
    ) -> Result<Option<OperatorPrincipal>, StoreError> {
        validate_identifier("issuer_id", issuer_id)?;
        validate_sha256("subject_fingerprint", subject_fingerprint)?;
        validate_identifier("organization_id", organization_id)?;
        let mut transaction = self.pool.begin().await?;
        set_read_transaction(&mut transaction).await?;
        let Some(row) =
            fetch_operator_by_subject(&mut transaction, issuer_id, subject_fingerprint).await?
        else {
            transaction.commit().await?;
            return Ok(None);
        };
        let operator_chain =
            load_verified_in_transaction(&mut transaction, &row.audit_organization_id).await?;
        let operator = verify_operator_row(row, &operator_chain)?;
        if operator.status != OperatorStatus::Active {
            transaction.commit().await?;
            return Ok(None);
        }

        let role_rows =
            fetch_roles(&mut transaction, &operator.operator_id, organization_id).await?;
        let role_chain =
            if role_rows.is_empty() || organization_id == operator.audit_organization_id {
                None
            } else {
                Some(load_verified_in_transaction(&mut transaction, organization_id).await?)
            };
        let chain = role_chain.as_deref().unwrap_or(&operator_chain);
        let mut roles = Vec::new();
        for row in role_rows {
            let binding = verify_role_row(row, chain)?;
            if binding.active {
                roles.push(binding.role);
            }
        }
        roles.sort_unstable();
        transaction.commit().await?;
        Ok(Some(OperatorPrincipal {
            operator_id: operator.operator_id,
            principal_kind: operator.principal_kind,
            issuer_id: operator.issuer_id,
            subject_fingerprint: operator.subject_fingerprint,
            organization_id: organization_id.into(),
            roles,
        }))
    }
}

pub(crate) async fn authorize_policy_change(
    transaction: &mut Transaction<'_, Postgres>,
    operator_id: &str,
    organization_id: &str,
) -> Result<(), StoreError> {
    validate_identifier("operator_id", operator_id)?;
    validate_identifier("organization_id", organization_id)?;
    let denied = || StoreError::PolicyAuthorizationDenied {
        organization_id: organization_id.into(),
        operator_id: operator_id.into(),
    };
    let Some(row) =
        fetch_operator_query(transaction, "operator_id = $1", operator_id, true).await?
    else {
        return Err(denied());
    };
    let operator_chain =
        load_verified_in_transaction(transaction, &row.audit_organization_id).await?;
    let operator = verify_operator_row(row, &operator_chain)?;
    if operator.status != OperatorStatus::Active {
        return Err(denied());
    }

    let role_rows = fetch_roles_for_update(transaction, operator_id, organization_id).await?;
    let role_chain = if organization_id == operator.audit_organization_id {
        None
    } else {
        Some(load_verified_in_transaction(transaction, organization_id).await?)
    };
    let chain = role_chain.as_deref().unwrap_or(&operator_chain);
    let authorized = role_rows.into_iter().try_fold(false, |authorized, row| {
        let binding = verify_role_row(row, chain)?;
        Ok::<_, StoreError>(authorized || (binding.active && binding.role.can_change_policy()))
    })?;
    if authorized {
        Ok(())
    } else {
        Err(denied())
    }
}

pub(crate) async fn authorize_decision_read(
    transaction: &mut Transaction<'_, Postgres>,
    operator_id: &str,
    organization_id: &str,
) -> Result<(), StoreError> {
    validate_identifier("operator_id", operator_id)?;
    validate_identifier("organization_id", organization_id)?;
    let denied = || StoreError::DecisionReadAuthorizationDenied {
        organization_id: organization_id.into(),
        operator_id: operator_id.into(),
    };
    let Some(row) =
        fetch_operator_query(transaction, "operator_id = $1", operator_id, true).await?
    else {
        return Err(denied());
    };
    let operator_chain =
        load_verified_in_transaction(transaction, &row.audit_organization_id).await?;
    let operator = verify_operator_row(row, &operator_chain)?;
    if operator.status != OperatorStatus::Active {
        return Err(denied());
    }
    let role_rows = fetch_roles_for_update(transaction, operator_id, organization_id).await?;
    let role_chain = if organization_id == operator.audit_organization_id {
        None
    } else {
        Some(load_verified_in_transaction(transaction, organization_id).await?)
    };
    let chain = role_chain.as_deref().unwrap_or(&operator_chain);
    let authorized = role_rows.into_iter().try_fold(false, |authorized, row| {
        let binding = verify_role_row(row, chain)?;
        Ok::<_, StoreError>(authorized || (binding.active && binding.role.can_read_decisions()))
    })?;
    if authorized {
        Ok(())
    } else {
        Err(denied())
    }
}

pub(crate) async fn authorize_audit_read_and_load_chain(
    transaction: &mut Transaction<'_, Postgres>,
    operator_id: &str,
    organization_id: &str,
) -> Result<Vec<crate::StoredAuditEvent>, StoreError> {
    validate_identifier("operator_id", operator_id)?;
    validate_identifier("organization_id", organization_id)?;
    let denied = || StoreError::AuditReadAuthorizationDenied {
        organization_id: organization_id.into(),
        operator_id: operator_id.into(),
    };
    let Some(row) =
        fetch_operator_query(transaction, "operator_id = $1", operator_id, false).await?
    else {
        return Err(denied());
    };
    let audit_organization_id = row.audit_organization_id.clone();
    let operator_chain = load_verified_in_transaction(transaction, &audit_organization_id).await?;
    let operator = verify_operator_row(row, &operator_chain)?;
    if operator.status != OperatorStatus::Active {
        return Err(denied());
    }

    let role_rows = fetch_roles(transaction, operator_id, organization_id).await?;
    if role_rows.is_empty() {
        return Err(denied());
    }
    let organization_chain = if organization_id == audit_organization_id {
        operator_chain
    } else {
        load_verified_in_transaction(transaction, organization_id).await?
    };
    let authorized = role_rows.into_iter().try_fold(false, |authorized, row| {
        let binding = verify_role_row(row, &organization_chain)?;
        Ok::<_, StoreError>(authorized || (binding.active && binding.role.can_read_audit()))
    })?;
    if authorized {
        Ok(organization_chain)
    } else {
        Err(denied())
    }
}

#[allow(clippy::too_many_arguments)]
async fn finish_role_change(
    mut transaction: Transaction<'_, Postgres>,
    operator_id: &str,
    organization_id: &str,
    role: OperatorRole,
    target: RoleBindingStatus,
    version: i64,
    created_at: Timestamp,
    actor_id: &str,
    reason_code: &str,
    occurred_at: Timestamp,
) -> Result<OperatorRoleBinding, StoreError> {
    let audit_version = u64::try_from(version)
        .map_err(|_| invalid("Operator role version is outside Audit representation"))?;
    let canonical = CanonicalRoleBinding {
        operator_id: operator_id.into(),
        organization_id: organization_id.into(),
        role,
        status: target,
        created_at,
    };
    let (canonical_binding, canonical_binding_bytes, binding_hash) = canonical_role(&canonical)?;
    let payload = OperatorRoleChangedPayload {
        organization_id: organization_id.into(),
        operator_id: operator_id.into(),
        role: role_name(role).into(),
        binding_status: role_status_name(target).into(),
        binding_hash: binding_hash.clone(),
        lifecycle_version: audit_version,
        actor_id: actor_id.into(),
        reason_code: reason_code.into(),
    };
    let payload = if matches!(target, RoleBindingStatus::Active) {
        AuditPayload::OperatorRoleGranted(payload)
    } else {
        AuditPayload::OperatorRoleRevoked(payload)
    };
    let event = NewAuditEvent::from_payload(occurred_at, None, payload)?;
    let stored_event = append_in_transaction(
        &mut transaction,
        organization_id,
        event,
        AuditReferences::default(),
    )
    .await?;

    if version == 1 {
        sqlx::query(
            r#"
            INSERT INTO operator_roles (
                operator_id, organization_id, role, status, canonical_binding,
                canonical_binding_bytes, binding_hash, lifecycle_version,
                last_event_id, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, 1, $8, $9, $10)
            "#,
        )
        .bind(operator_id)
        .bind(organization_id)
        .bind(role_name(role))
        .bind(role_status_name(target))
        .bind(&canonical_binding)
        .bind(&canonical_binding_bytes)
        .bind(&binding_hash)
        .bind(&stored_event.event.event_id)
        .bind(created_at.as_datetime())
        .bind(occurred_at.as_datetime())
        .execute(&mut *transaction)
        .await?;
    } else {
        let updated = sqlx::query(
            r#"
            UPDATE operator_roles
            SET status = $4, canonical_binding = $5,
                canonical_binding_bytes = $6, binding_hash = $7,
                lifecycle_version = $8, last_event_id = $9, updated_at = $10
            WHERE operator_id = $1 AND organization_id = $2 AND role = $3
            "#,
        )
        .bind(operator_id)
        .bind(organization_id)
        .bind(role_name(role))
        .bind(role_status_name(target))
        .bind(&canonical_binding)
        .bind(&canonical_binding_bytes)
        .bind(&binding_hash)
        .bind(version)
        .bind(&stored_event.event.event_id)
        .bind(occurred_at.as_datetime())
        .execute(&mut *transaction)
        .await?;
        if updated.rows_affected() != 1 {
            return Err(StoreError::OperatorRoleNotFound {
                operator_id: operator_id.into(),
                organization_id: organization_id.into(),
                role: role_name(role).into(),
            });
        }
    }
    transaction.commit().await?;
    Ok(OperatorRoleBinding {
        operator_id: operator_id.into(),
        organization_id: organization_id.into(),
        role,
        active: matches!(target, RoleBindingStatus::Active),
        binding_hash,
        lifecycle_version: version,
        last_event_id: stored_event.event.event_id,
        created_at,
        updated_at: occurred_at,
    })
}

async fn fetch_operator(
    transaction: &mut Transaction<'_, Postgres>,
    operator_id: &str,
) -> Result<OperatorRow, StoreError> {
    fetch_operator_query(transaction, "operator_id = $1", operator_id, false)
        .await?
        .ok_or_else(|| StoreError::OperatorNotFound {
            operator_id: operator_id.into(),
        })
}

async fn fetch_operator_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    operator_id: &str,
) -> Result<OperatorRow, StoreError> {
    fetch_operator_query(transaction, "operator_id = $1", operator_id, true)
        .await?
        .ok_or_else(|| StoreError::OperatorNotFound {
            operator_id: operator_id.into(),
        })
}

async fn fetch_operator_query(
    transaction: &mut Transaction<'_, Postgres>,
    _predicate: &str,
    operator_id: &str,
    for_update: bool,
) -> Result<Option<OperatorRow>, StoreError> {
    let query = if for_update {
        operator_select("WHERE operator_id = $1 FOR UPDATE")
    } else {
        operator_select("WHERE operator_id = $1")
    };
    Ok(sqlx::query_as(&query)
        .bind(operator_id)
        .fetch_optional(&mut **transaction)
        .await?)
}

async fn fetch_operator_by_subject(
    transaction: &mut Transaction<'_, Postgres>,
    issuer_id: &str,
    subject_fingerprint: &str,
) -> Result<Option<OperatorRow>, StoreError> {
    let query = operator_select("WHERE issuer_id = $1 AND subject_fingerprint = $2");
    Ok(sqlx::query_as(&query)
        .bind(issuer_id)
        .bind(subject_fingerprint)
        .fetch_optional(&mut **transaction)
        .await?)
}

fn operator_select(suffix: &str) -> String {
    format!(
        r#"
        SELECT operator_id, issuer_id,
               subject_fingerprint::text AS subject_fingerprint,
               principal_kind, status, audit_organization_id,
               canonical_record, canonical_record_bytes,
               record_hash::text AS record_hash, lifecycle_version,
               last_event_id, created_at, updated_at
        FROM operator_subjects
        {suffix}
        "#
    )
}

async fn fetch_role_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    operator_id: &str,
    organization_id: &str,
    role: OperatorRole,
) -> Result<Option<RoleRow>, StoreError> {
    Ok(sqlx::query_as(
        r#"
        SELECT operator_id, organization_id, role, status,
               canonical_binding, canonical_binding_bytes,
               binding_hash::text AS binding_hash, lifecycle_version,
               last_event_id, created_at, updated_at
        FROM operator_roles
        WHERE operator_id = $1 AND organization_id = $2 AND role = $3
        FOR UPDATE
        "#,
    )
    .bind(operator_id)
    .bind(organization_id)
    .bind(role_name(role))
    .fetch_optional(&mut **transaction)
    .await?)
}

async fn fetch_roles(
    transaction: &mut Transaction<'_, Postgres>,
    operator_id: &str,
    organization_id: &str,
) -> Result<Vec<RoleRow>, StoreError> {
    Ok(sqlx::query_as(
        r#"
        SELECT operator_id, organization_id, role, status,
               canonical_binding, canonical_binding_bytes,
               binding_hash::text AS binding_hash, lifecycle_version,
               last_event_id, created_at, updated_at
        FROM operator_roles
        WHERE operator_id = $1 AND organization_id = $2
        ORDER BY role
        "#,
    )
    .bind(operator_id)
    .bind(organization_id)
    .fetch_all(&mut **transaction)
    .await?)
}

async fn fetch_roles_for_update(
    transaction: &mut Transaction<'_, Postgres>,
    operator_id: &str,
    organization_id: &str,
) -> Result<Vec<RoleRow>, StoreError> {
    Ok(sqlx::query_as(
        r#"
        SELECT operator_id, organization_id, role, status,
               canonical_binding, canonical_binding_bytes,
               binding_hash::text AS binding_hash, lifecycle_version,
               last_event_id, created_at, updated_at
        FROM operator_roles
        WHERE operator_id = $1 AND organization_id = $2
        ORDER BY role
        FOR UPDATE
        "#,
    )
    .bind(operator_id)
    .bind(organization_id)
    .fetch_all(&mut **transaction)
    .await?)
}

fn verify_operator_row(
    row: OperatorRow,
    chain: &[crate::StoredAuditEvent],
) -> Result<StoredOperator, StoreError> {
    let canonical: CanonicalOperator = serde_json::from_value(row.canonical_record.clone())
        .map_err(|error| {
            corrupt(
                &row.operator_id,
                format!("canonical record cannot be decoded: {error}"),
            )
        })?;
    let (canonical_value, canonical_bytes, record_hash) = canonical_operator(&canonical)?;
    let kind = parse_kind(&row.principal_kind)
        .ok_or_else(|| corrupt(&row.operator_id, "unknown principal kind"))?;
    let status = parse_status(&row.status)
        .ok_or_else(|| corrupt(&row.operator_id, "unknown Operator status"))?;
    let columns_match = canonical_value == row.canonical_record
        && canonical_bytes == row.canonical_record_bytes
        && record_hash == row.record_hash
        && canonical.operator_id == row.operator_id
        && canonical.issuer_id == row.issuer_id
        && canonical.subject_fingerprint == row.subject_fingerprint
        && canonical.principal_kind == kind
        && canonical.status == status
        && canonical.audit_organization_id == row.audit_organization_id
        && canonical.created_at == Timestamp::from_datetime(row.created_at)
        && row.lifecycle_version > 0;
    if !columns_match {
        return Err(corrupt(
            &row.operator_id,
            "canonical Operator record, hash, bytes, or redundant columns disagree",
        ));
    }
    let event = chain
        .iter()
        .find(|stored| stored.event.event_id == row.last_event_id)
        .ok_or_else(|| corrupt(&row.operator_id, "last event is absent from Audit chain"))?;
    let version = u64::try_from(row.lifecycle_version)
        .map_err(|_| corrupt(&row.operator_id, "lifecycle version is invalid"))?;
    let payload = event.event.typed_payload().map_err(|error| {
        corrupt(
            &row.operator_id,
            format!("Audit payload is invalid: {error}"),
        )
    })?;
    let evidence_matches = event.event.occurred_at == Timestamp::from_datetime(row.updated_at)
        && match payload {
            AuditPayload::OperatorRegistered(payload) => {
                version == 1
                    && payload.organization_id == row.audit_organization_id
                    && payload.operator_id == row.operator_id
                    && payload.issuer_id == row.issuer_id
                    && payload.subject_fingerprint == row.subject_fingerprint
                    && payload.principal_kind == row.principal_kind
                    && payload.status == row.status
                    && payload.record_hash == row.record_hash
                    && payload.lifecycle_version == version
            }
            AuditPayload::OperatorStatusChanged(payload) => {
                payload.organization_id == row.audit_organization_id
                    && payload.operator_id == row.operator_id
                    && payload.status == row.status
                    && payload.record_hash == row.record_hash
                    && payload.lifecycle_version == version
            }
            _ => false,
        };
    if !evidence_matches {
        return Err(corrupt(
            &row.operator_id,
            "last Audit event does not bind current Operator state",
        ));
    }
    Ok(StoredOperator {
        operator_id: row.operator_id,
        issuer_id: row.issuer_id,
        subject_fingerprint: row.subject_fingerprint,
        principal_kind: kind,
        status,
        audit_organization_id: row.audit_organization_id,
        record_hash: row.record_hash,
        lifecycle_version: row.lifecycle_version,
        last_event_id: row.last_event_id,
        created_at: Timestamp::from_datetime(row.created_at),
        updated_at: Timestamp::from_datetime(row.updated_at),
    })
}

fn verify_role_row(
    row: RoleRow,
    chain: &[crate::StoredAuditEvent],
) -> Result<OperatorRoleBinding, StoreError> {
    let role =
        parse_role(&row.role).ok_or_else(|| corrupt(&row.operator_id, "unknown Operator role"))?;
    let status = parse_role_status(&row.status)
        .ok_or_else(|| corrupt(&row.operator_id, "unknown role binding status"))?;
    let canonical: CanonicalRoleBinding = serde_json::from_value(row.canonical_binding.clone())
        .map_err(|error| {
            corrupt(
                &row.operator_id,
                format!("role binding cannot be decoded: {error}"),
            )
        })?;
    let (canonical_value, canonical_bytes, binding_hash) = canonical_role(&canonical)?;
    let columns_match = canonical_value == row.canonical_binding
        && canonical_bytes == row.canonical_binding_bytes
        && binding_hash == row.binding_hash
        && canonical.operator_id == row.operator_id
        && canonical.organization_id == row.organization_id
        && canonical.role == role
        && canonical.status == status
        && canonical.created_at == Timestamp::from_datetime(row.created_at)
        && row.lifecycle_version > 0;
    if !columns_match {
        return Err(corrupt(
            &row.operator_id,
            "canonical role binding, hash, bytes, or redundant columns disagree",
        ));
    }
    let event = chain
        .iter()
        .find(|stored| stored.event.event_id == row.last_event_id)
        .ok_or_else(|| corrupt(&row.operator_id, "role event is absent from Audit chain"))?;
    let version = u64::try_from(row.lifecycle_version)
        .map_err(|_| corrupt(&row.operator_id, "role lifecycle version is invalid"))?;
    let payload = event.event.typed_payload().map_err(|error| {
        corrupt(
            &row.operator_id,
            format!("role Audit payload is invalid: {error}"),
        )
    })?;
    let fields = match payload {
        AuditPayload::OperatorRoleGranted(payload) if status == RoleBindingStatus::Active => {
            payload
        }
        AuditPayload::OperatorRoleRevoked(payload) if status == RoleBindingStatus::Revoked => {
            payload
        }
        _ => {
            return Err(corrupt(
                &row.operator_id,
                "role Audit event type disagrees with state",
            ))
        }
    };
    let evidence_matches = event.event.occurred_at == Timestamp::from_datetime(row.updated_at)
        && fields.organization_id == row.organization_id
        && fields.operator_id == row.operator_id
        && fields.role == row.role
        && fields.binding_status == row.status
        && fields.binding_hash == row.binding_hash
        && fields.lifecycle_version == version;
    if !evidence_matches {
        return Err(corrupt(
            &row.operator_id,
            "last Audit event does not bind current role state",
        ));
    }
    Ok(OperatorRoleBinding {
        operator_id: row.operator_id,
        organization_id: row.organization_id,
        role,
        active: status == RoleBindingStatus::Active,
        binding_hash: row.binding_hash,
        lifecycle_version: row.lifecycle_version,
        last_event_id: row.last_event_id,
        created_at: Timestamp::from_datetime(row.created_at),
        updated_at: Timestamp::from_datetime(row.updated_at),
    })
}

fn canonical_operator(value: &CanonicalOperator) -> Result<(Value, Vec<u8>, String), StoreError> {
    canonical(value)
}

fn canonical_role(value: &CanonicalRoleBinding) -> Result<(Value, Vec<u8>, String), StoreError> {
    canonical(value)
}

fn canonical<T: Serialize>(value: &T) -> Result<(Value, Vec<u8>, String), StoreError> {
    let value = atf_core::sort_json_keys(serde_json::to_value(value)?);
    let bytes = serde_json::to_vec(&value)?;
    let hash = atf_core::sha256_hex(&bytes);
    Ok((value, bytes, hash))
}

fn validate_registration(value: &OperatorRegistration) -> Result<(), StoreError> {
    validate_identifier("operator_id", &value.operator_id)?;
    validate_identifier("issuer_id", &value.issuer_id)?;
    validate_sha256("subject_fingerprint", &value.subject_fingerprint)?;
    validate_identifier("audit_organization_id", &value.audit_organization_id)?;
    validate_timestamp("created_at", value.created_at)
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
            organization_id: organization_id.into(),
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

fn validate_sha256(field: &'static str, value: &str) -> Result<(), StoreError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(invalid(format!(
            "{field} must be 64 lowercase SHA-256 hex bytes"
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

fn kind_name(value: OperatorKind) -> &'static str {
    match value {
        OperatorKind::Human => "HUMAN",
        OperatorKind::Service => "SERVICE",
    }
}

fn parse_kind(value: &str) -> Option<OperatorKind> {
    match value {
        "HUMAN" => Some(OperatorKind::Human),
        "SERVICE" => Some(OperatorKind::Service),
        _ => None,
    }
}

fn status_name(value: OperatorStatus) -> &'static str {
    match value {
        OperatorStatus::Active => "ACTIVE",
        OperatorStatus::Disabled => "DISABLED",
    }
}

fn parse_status(value: &str) -> Option<OperatorStatus> {
    match value {
        "ACTIVE" => Some(OperatorStatus::Active),
        "DISABLED" => Some(OperatorStatus::Disabled),
        _ => None,
    }
}

fn role_name(value: OperatorRole) -> &'static str {
    match value {
        OperatorRole::OrgAdmin => "org_admin",
        OperatorRole::PolicyAuthor => "policy_author",
        OperatorRole::Approver => "approver",
        OperatorRole::Auditor => "auditor",
    }
}

fn parse_role(value: &str) -> Option<OperatorRole> {
    match value {
        "org_admin" => Some(OperatorRole::OrgAdmin),
        "policy_author" => Some(OperatorRole::PolicyAuthor),
        "approver" => Some(OperatorRole::Approver),
        "auditor" => Some(OperatorRole::Auditor),
        _ => None,
    }
}

fn role_status_name(value: RoleBindingStatus) -> &'static str {
    match value {
        RoleBindingStatus::Active => "ACTIVE",
        RoleBindingStatus::Revoked => "REVOKED",
    }
}

fn parse_role_status(value: &str) -> Option<RoleBindingStatus> {
    match value {
        "ACTIVE" => Some(RoleBindingStatus::Active),
        "REVOKED" => Some(RoleBindingStatus::Revoked),
        _ => None,
    }
}

fn invalid(reason: impl Into<String>) -> StoreError {
    StoreError::InvalidRepositoryInput {
        reason: reason.into(),
    }
}

fn corrupt(operator_id: &str, reason: impl Into<String>) -> StoreError {
    StoreError::OperatorStateCorrupt {
        operator_id: operator_id.into(),
        reason: reason.into(),
    }
}
