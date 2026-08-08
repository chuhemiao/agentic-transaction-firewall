use crate::audit::{append_in_transaction, AuditReferences, StoredAuditEvent};
use crate::models::{FinalizationInput, StoredLifecycle};
use crate::StoreError;
use atf_audit::{
    AuditPayload, OptionalModuleOutcome, PolicyOutcome, RequiredModuleOutcome, RiskSeverity,
    SimulationOutcome,
};
use atf_core::{DecisionKind, IntentLifecycleState, Timestamp};
use atf_intent::TransactionIntent;
use sqlx::{Postgres, Transaction};

pub(crate) const CONTRACT_VERSION: i32 = 1;

pub(crate) fn validate_finalization_input(input: &FinalizationInput) -> Result<(), StoreError> {
    input
        .decision
        .verify_hash()
        .map_err(|error| StoreError::DecisionBindingMismatch {
            reason: error.to_string(),
        })?;
    if input.decision.intent_id != input.intent_id {
        return Err(StoreError::DecisionBindingMismatch {
            reason: format!(
                "Decision names `{}` but finalization requested `{}`",
                input.decision.intent_id, input.intent_id
            ),
        });
    }
    for (field, value) in [
        ("organization_id", input.organization_id.as_str()),
        ("intent_id", input.intent_id.as_str()),
        ("evaluation_id", input.evaluation.evaluation_id.as_str()),
        ("decision_id", input.decision.decision_id.as_str()),
    ] {
        if value.is_empty() || value.trim() != value || value.len() > 128 {
            return Err(StoreError::InvalidRepositoryInput {
                reason: format!("{field} must be 1..128 trimmed bytes"),
            });
        }
    }
    if input.expected_lifecycle_version <= 0 {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "expected lifecycle version must be positive".into(),
        });
    }
    if input.decided_at < input.evaluation.evaluated_at {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "decided_at cannot precede evaluated_at".into(),
        });
    }
    AuditPayload::PolicyEvaluated(input.evaluation.policy.clone()).validate()?;
    AuditPayload::RiskEvaluated(input.evaluation.risk.clone()).validate()?;
    AuditPayload::SimulationCompleted(input.evaluation.simulation.clone()).validate()?;

    let policy_permits = matches!(
        input.evaluation.policy.outcome,
        RequiredModuleOutcome::Succeeded {
            result: PolicyOutcome::Permit
        }
    );
    if policy_permits
        && matches!(
            input.evaluation.risk.outcome,
            OptionalModuleOutcome::NotRun { .. }
        )
    {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "Risk cannot be NOT_RUN after Policy permits".into(),
        });
    }
    if !policy_permits
        && !matches!(
            input.evaluation.risk.outcome,
            OptionalModuleOutcome::NotRun { .. }
        )
    {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "Risk must be NOT_RUN after Policy forbid/error".into(),
        });
    }

    let expected = expected_decision_kind(input);
    if input.decision.decision != expected {
        return Err(StoreError::InvalidRepositoryInput {
            reason: format!(
                "Decision {:?} contradicts typed module outcomes, which require {expected:?}",
                input.decision.decision
            ),
        });
    }
    Ok(())
}

fn expected_decision_kind(input: &FinalizationInput) -> DecisionKind {
    if matches!(
        input.evaluation.policy.outcome,
        RequiredModuleOutcome::Error { .. }
    ) || matches!(
        input.evaluation.risk.outcome,
        OptionalModuleOutcome::Error { .. }
    ) || matches!(
        input.evaluation.simulation.outcome,
        OptionalModuleOutcome::Error { .. }
    ) {
        return DecisionKind::Error;
    }
    if matches!(
        input.evaluation.policy.outcome,
        RequiredModuleOutcome::Succeeded {
            result: PolicyOutcome::Forbid
        }
    ) {
        return DecisionKind::Deny;
    }
    if matches!(
        input.evaluation.simulation.outcome,
        OptionalModuleOutcome::Succeeded {
            result: SimulationOutcome::Unsafe
        }
    ) {
        return DecisionKind::Deny;
    }
    if matches!(
        input.evaluation.simulation.outcome,
        OptionalModuleOutcome::Succeeded {
            result: SimulationOutcome::Review
        }
    ) {
        return DecisionKind::Review;
    }

    let worst_risk = match &input.evaluation.risk.outcome {
        OptionalModuleOutcome::Succeeded { result } => result
            .iter()
            .map(|finding| finding.severity)
            .max_by_key(|severity| match severity {
                RiskSeverity::Info => 0,
                RiskSeverity::Medium => 1,
                RiskSeverity::High => 2,
                RiskSeverity::Critical => 3,
            }),
        OptionalModuleOutcome::Error { .. } | OptionalModuleOutcome::NotRun { .. } => None,
    };
    match worst_risk {
        Some(RiskSeverity::Critical) => DecisionKind::Deny,
        Some(RiskSeverity::High) => DecisionKind::Review,
        Some(RiskSeverity::Info | RiskSeverity::Medium) | None => DecisionKind::Permit,
    }
}

pub(crate) async fn append_event(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    intent_id: &str,
    occurred_at: Timestamp,
    payload: AuditPayload,
    references: AuditReferences,
    lifecycle: &mut StoredLifecycle,
) -> Result<StoredAuditEvent, StoreError> {
    let next_state = payload.next_state(Some(lifecycle.state))?.ok_or_else(|| {
        StoreError::InvalidRepositoryInput {
            reason: format!(
                "{:?} does not advance the Intent lifecycle",
                payload.event_type()
            ),
        }
    })?;
    if next_state == lifecycle.state {
        return Err(StoreError::InvalidRepositoryInput {
            reason: format!(
                "{:?} did not change the Intent lifecycle",
                payload.event_type()
            ),
        });
    }
    let event =
        atf_audit::NewAuditEvent::from_payload(occurred_at, Some(intent_id.to_owned()), payload)?;
    let stored = append_in_transaction(transaction, organization_id, event, references).await?;
    lifecycle.state = next_state;
    lifecycle.version =
        lifecycle
            .version
            .checked_add(1)
            .ok_or_else(|| StoreError::DurableStateCorrupt {
                organization_id: organization_id.to_owned(),
                reason: format!("Intent `{intent_id}` lifecycle version overflowed"),
            })?;
    lifecycle.last_event_id = Some(stored.event.event_id.clone());
    lifecycle.updated_at = stored.event.occurred_at;
    Ok(stored)
}

pub(crate) fn state_from_str(value: &str) -> Option<IntentLifecycleState> {
    IntentLifecycleState::ALL
        .into_iter()
        .find(|state| state.as_str() == value)
}

pub(crate) fn verify_replay(
    organization_id: &str,
    intent: &TransactionIntent,
    materialized: &StoredLifecycle,
    chain: &[StoredAuditEvent],
) -> Result<(), StoreError> {
    if materialized.contract_version == 0 {
        return Ok(());
    }
    if materialized.contract_version != CONTRACT_VERSION {
        return Err(corrupt(
            organization_id,
            format!(
                "Intent `{}` uses unsupported lifecycle contract version {}",
                intent.intent_id, materialized.contract_version
            ),
        ));
    }

    let mut state = None;
    let mut version = 0_i64;
    let mut last_event_id = None;
    let mut updated_at = None;
    for stored in chain.iter().filter(|stored| {
        stored.event.intent_id.as_deref() == Some(intent.intent_id.as_str())
            && stored.event.event_type.has_lifecycle_effect()
    }) {
        let payload = stored.event.typed_payload().map_err(|error| {
            corrupt(
                organization_id,
                format!(
                    "Intent `{}` lifecycle event `{}` is not typed: {error}",
                    intent.intent_id, stored.event.event_id
                ),
            )
        })?;
        verify_payload_binding(organization_id, intent, &payload)?;
        state = payload.next_state(state).map_err(|error| {
            corrupt(
                organization_id,
                format!(
                    "Intent `{}` lifecycle replay failed at event `{}`: {error}",
                    intent.intent_id, stored.event.event_id
                ),
            )
        })?;
        version = version.checked_add(1).ok_or_else(|| {
            corrupt(
                organization_id,
                format!("Intent `{}` lifecycle version overflowed", intent.intent_id),
            )
        })?;
        last_event_id = Some(stored.event.event_id.clone());
        updated_at = Some(stored.event.occurred_at);
    }

    let matches = state == Some(materialized.state)
        && version == materialized.version
        && last_event_id == materialized.last_event_id
        && updated_at == Some(materialized.updated_at);
    if !matches {
        return Err(corrupt(
            organization_id,
            format!(
                "Intent `{}` materialized lifecycle does not match typed Audit replay",
                intent.intent_id
            ),
        ));
    }
    Ok(())
}

fn verify_payload_binding(
    organization_id: &str,
    intent: &TransactionIntent,
    payload: &AuditPayload,
) -> Result<(), StoreError> {
    let bound = match payload {
        AuditPayload::IntentReceived(value) => {
            value.organization_id == organization_id
                && value.agent_id == intent.principal.agent_id
                && value.idempotency_key == intent.idempotency_key
                && value.intent_hash == intent.canonical_hash()
                && value.amount == intent.transaction.amount
                && value.resource_id == intent.resource.resource_id
        }
        AuditPayload::IdentityVerified(value) => {
            value.organization_id == organization_id && value.agent_id == intent.principal.agent_id
        }
        AuditPayload::IdentityVerificationSkipped(value) => {
            value.organization_id == organization_id && value.agent_id == intent.principal.agent_id
        }
        AuditPayload::IdentityRejected(value) => {
            value.organization_id == organization_id && value.agent_id == intent.principal.agent_id
        }
        AuditPayload::DecisionRecorded(value) => {
            value.organization_id == organization_id
                && value.agent_id == intent.principal.agent_id
                && value.intent_hash == intent.canonical_hash()
                && value.action_category == intent.action.category
                && value.resource_id == intent.resource.resource_id
                && value.amount == intent.transaction.amount
                && value.destination == intent.transaction.destination
        }
        _ => true,
    };
    if !bound {
        return Err(corrupt(
            organization_id,
            format!(
                "Intent `{}` has lifecycle evidence bound to different facts",
                intent.intent_id
            ),
        ));
    }
    Ok(())
}

fn corrupt(organization_id: &str, reason: impl Into<String>) -> StoreError {
    StoreError::DurableStateCorrupt {
        organization_id: organization_id.to_owned(),
        reason: reason.into(),
    }
}
