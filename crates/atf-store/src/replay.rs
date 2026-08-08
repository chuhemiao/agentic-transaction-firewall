use atf_audit::{
    AuditPayload, EventType, OptionalModuleOutcome, OriginalReplayCompletedPayload,
    PolicyEvaluatedPayload, PolicyOutcome as AuditPolicyOutcome, RequiredModuleOutcome,
    RiskEvaluatedPayload, RiskFindingEvidence, RiskSeverity,
};
use atf_core::Timestamp;
use atf_decision::{decide, DecisionInput, PolicyDecisionInput, RiskDecisionInput};
use atf_policy::{PolicyDecision, PolicyOutcome};
use atf_risk::{RiskEvaluation, Severity};
use thiserror::Error;

use crate::audit::{append_in_transaction, AuditReferences};
use crate::operator::authorize_decision_read;
use crate::{Store, StoreError, StoredAuditEvent};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalReplayRequest {
    pub replay_id: String,
    pub organization_id: String,
    pub intent_id: String,
    pub actor_id: String,
    pub occurred_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginalReplayResult {
    pub replay_id: String,
    pub original_evaluation_id: String,
    pub original_decision_id: String,
    pub original_decision_hash: String,
    pub replayed_decision_hash: String,
    pub matched: bool,
    pub audit_event: StoredAuditEvent,
}

#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("Original Replay request is invalid")]
    InvalidRequest,
    #[error("the operator is not authorized to replay this Decision")]
    AuthorizationDenied,
    #[error("the exact admitted Intent is missing")]
    IntentMissing,
    #[error("the original finalized Decision is missing")]
    DecisionMissing,
    #[error("the immutable Evaluation Context is missing")]
    ContextMissing,
    #[error("the exact Policy Bundle artifact is missing")]
    PolicyArtifactMissing,
    #[error("the exact Risk Rule Set artifact is missing")]
    RiskArtifactMissing,
    #[error("an immutable Replay input or its Audit evidence was modified")]
    InputTampered,
    #[error("the recomputed module evidence differs from the original Evaluation")]
    EvaluationMismatch,
    #[error("the recomputed Decision differs from the original authoritative Decision")]
    DecisionMismatch,
    #[error("durable Replay processing failed: {0}")]
    Store(#[source] StoreError),
}

impl ReplayError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "REPLAY_INVALID_REQUEST",
            Self::AuthorizationDenied => "REPLAY_AUTHORIZATION_DENIED",
            Self::IntentMissing => "REPLAY_INTENT_MISSING",
            Self::DecisionMissing => "REPLAY_DECISION_MISSING",
            Self::ContextMissing => "REPLAY_CONTEXT_MISSING",
            Self::PolicyArtifactMissing => "REPLAY_POLICY_ARTIFACT_MISSING",
            Self::RiskArtifactMissing => "REPLAY_RISK_ARTIFACT_MISSING",
            Self::InputTampered => "REPLAY_INPUT_TAMPERED",
            Self::EvaluationMismatch => "REPLAY_EVALUATION_MISMATCH",
            Self::DecisionMismatch => "REPLAY_DECISION_MISMATCH",
            Self::Store(_) => "REPLAY_STORE_ERROR",
        }
    }
}

impl Store {
    /// Deterministically reproduce the original authoritative Decision from
    /// immutable inputs. Only non-authoritative evidence is appended.
    pub async fn replay_original(
        &self,
        request: OriginalReplayRequest,
    ) -> Result<OriginalReplayResult, ReplayError> {
        validate_request(&request)?;
        // Authorize before revealing whether any referenced artifact exists,
        // then authorize again in the evidence-append transaction to close the
        // time-of-check/time-of-use window.
        let mut authorization = self
            .pool
            .begin()
            .await
            .map_err(|error| store_error(StoreError::from(error)))?;
        crate::repository::set_write_timeouts(&mut authorization)
            .await
            .map_err(store_error)?;
        authorize_replay(
            &mut authorization,
            &request.actor_id,
            &request.organization_id,
        )
        .await?;
        authorization
            .commit()
            .await
            .map_err(|error| store_error(StoreError::from(error)))?;

        let admitted = self
            .load_admitted_intent(&request.organization_id, &request.intent_id)
            .await
            .map_err(map_input_error)?
            .ok_or(ReplayError::IntentMissing)?;
        let original = self
            .load_finalized_decision(&request.organization_id, &request.intent_id)
            .await
            .map_err(map_input_error)?
            .ok_or(ReplayError::DecisionMissing)?;
        let context = original
            .evaluation_context
            .as_ref()
            .ok_or(ReplayError::ContextMissing)?;
        if request.occurred_at < original.decided_at {
            return Err(ReplayError::InvalidRequest);
        }

        let (policy_id, policy_version, policy_hash) = context
            .policy()
            .available_parts()
            .ok_or(ReplayError::PolicyArtifactMissing)?;
        let policy = self
            .load_policy_bundle(
                &request.organization_id,
                context.environment(),
                policy_id,
                policy_version,
                policy_hash,
                context.evaluation_time(),
            )
            .await
            .map_err(map_policy_error)?;
        let (engine_version, rule_set_version, rule_set_hash) = context
            .risk()
            .available_parts()
            .ok_or(ReplayError::RiskArtifactMissing)?;
        let risk_rule_set = self
            .load_risk_rule_set(
                &request.organization_id,
                context.environment(),
                engine_version,
                rule_set_version,
                rule_set_hash,
            )
            .await
            .map_err(map_risk_error)?;

        let chain = self
            .load_verified_audit_chain(&request.organization_id)
            .await
            .map_err(map_input_error)?;
        let through_sequence = usize::try_from(context.history().through_sequence())
            .map_err(|_| ReplayError::InputTampered)?;
        if through_sequence == 0 || chain.len() < through_sequence {
            return Err(ReplayError::InputTampered);
        }
        let history = &chain[..through_sequence];
        if history.last().map(|event| event.event_hash.as_str())
            != Some(context.history().snapshot_hash())
        {
            return Err(ReplayError::InputTampered);
        }

        let original_policy = evidence_payload(
            &original.evaluation.evidence,
            "policy",
            EventType::PolicyEvaluated,
        )?;
        let AuditPayload::PolicyEvaluated(original_policy) = original_policy else {
            return Err(ReplayError::InputTampered);
        };
        let original_risk = evidence_payload(
            &original.evaluation.evidence,
            "risk",
            EventType::RiskEvaluated,
        )?;
        let AuditPayload::RiskEvaluated(original_risk) = original_risk else {
            return Err(ReplayError::InputTampered);
        };

        let evaluated_policy = policy.evaluate(&admitted.intent, context);
        let (policy_outcome, policy_error_code) =
            reproduce_policy(evaluated_policy, &original_policy)?;
        let replayed_risk = match policy_outcome.as_ref() {
            Some(outcome) if outcome.decision == PolicyDecision::Permit => {
                match atf_risk::evaluate_context(
                    &admitted.intent,
                    &risk_rule_set,
                    context,
                    history.iter().map(|event| &event.event),
                ) {
                    Ok(evaluation) => ReplayedRisk::Evaluated(evaluation),
                    Err(error) => ReplayedRisk::Error(error.code().into()),
                }
            }
            Some(outcome) if outcome.decision == PolicyDecision::Forbid => {
                ReplayedRisk::NotRun("POLICY_FORBID")
            }
            None if policy_error_code.is_some() => ReplayedRisk::NotRun("POLICY_ERROR"),
            _ => return Err(ReplayError::EvaluationMismatch),
        };
        reproduce_risk(&replayed_risk, &risk_rule_set, &original_risk)?;

        let policy_input = match (&policy_outcome, &policy_error_code) {
            (Some(outcome), None) => PolicyDecisionInput::Evaluated(outcome),
            (None, Some(error_code)) => PolicyDecisionInput::Error { error_code },
            _ => return Err(ReplayError::EvaluationMismatch),
        };
        let risk_input = match &replayed_risk {
            ReplayedRisk::Evaluated(evaluation) => RiskDecisionInput::Evaluated(evaluation),
            ReplayedRisk::Error(error_code) => RiskDecisionInput::Error { error_code },
            ReplayedRisk::NotRun(reason_code) => RiskDecisionInput::NotRun { reason_code },
        };
        let replayed = decide(DecisionInput {
            decision_id: original.decision.decision_id.clone(),
            intent: &admitted.intent,
            evaluation_context: context,
            policy: policy_input,
            risk: risk_input,
        })
        .map_err(|_| ReplayError::EvaluationMismatch)?;
        if replayed.decision_hash != original.decision_hash
            || replayed.canonical_bytes() != original.decision.canonical_bytes()
        {
            return Err(ReplayError::DecisionMismatch);
        }

        let mut transaction = self
            .pool
            .begin()
            .await
            .map_err(|error| store_error(StoreError::from(error)))?;
        crate::repository::set_write_timeouts(&mut transaction)
            .await
            .map_err(store_error)?;
        authorize_replay(
            &mut transaction,
            &request.actor_id,
            &request.organization_id,
        )
        .await?;
        let event = atf_audit::NewAuditEvent::from_payload(
            request.occurred_at,
            Some(request.intent_id.clone()),
            AuditPayload::OriginalReplayCompleted(OriginalReplayCompletedPayload {
                organization_id: request.organization_id.clone(),
                replay_id: request.replay_id.clone(),
                original_evaluation_id: original.evaluation.evaluation_id.clone(),
                original_decision_id: original.decision.decision_id.clone(),
                original_decision_hash: original.decision_hash.clone(),
                replayed_decision_hash: replayed.decision_hash.clone(),
                matched: true,
                authoritative: false,
                actor_id: request.actor_id,
            }),
        )
        .map_err(|error| store_error(StoreError::from(error)))?;
        let audit_event = append_in_transaction(
            &mut transaction,
            &request.organization_id,
            event,
            AuditReferences {
                evaluation_id: Some(original.evaluation.evaluation_id.clone()),
                decision_id: Some(original.decision.decision_id.clone()),
            },
        )
        .await
        .map_err(store_error)?;
        transaction
            .commit()
            .await
            .map_err(|error| store_error(StoreError::from(error)))?;

        Ok(OriginalReplayResult {
            replay_id: request.replay_id,
            original_evaluation_id: original.evaluation.evaluation_id,
            original_decision_id: original.decision.decision_id,
            original_decision_hash: original.decision_hash,
            replayed_decision_hash: replayed.decision_hash,
            matched: true,
            audit_event,
        })
    }
}

fn reproduce_policy(
    evaluated: Result<PolicyOutcome, atf_policy::PolicyError>,
    original: &PolicyEvaluatedPayload,
) -> Result<(Option<PolicyOutcome>, Option<String>), ReplayError> {
    match (&original.outcome, evaluated) {
        (RequiredModuleOutcome::Succeeded { .. }, Ok(outcome)) => {
            let replayed = policy_evidence(&outcome);
            if &replayed != original {
                return Err(ReplayError::EvaluationMismatch);
            }
            Ok((Some(outcome), None))
        }
        (RequiredModuleOutcome::Error { error_code }, Err(_))
            if error_code == "POLICY_EVALUATION_ERROR" =>
        {
            Ok((None, Some(error_code.clone())))
        }
        _ => Err(ReplayError::EvaluationMismatch),
    }
}

enum ReplayedRisk {
    Evaluated(RiskEvaluation),
    Error(String),
    NotRun(&'static str),
}

fn reproduce_risk(
    replayed: &ReplayedRisk,
    rule_set: &atf_risk::RiskRuleSet,
    original: &RiskEvaluatedPayload,
) -> Result<(), ReplayError> {
    let evidence = match replayed {
        ReplayedRisk::Evaluated(evaluation) => risk_evidence(evaluation),
        ReplayedRisk::Error(error_code) => RiskEvaluatedPayload {
            risk_rule_set_version: Some(rule_set.version().into()),
            risk_rule_set_hash: Some(rule_set.rule_set_hash().into()),
            outcome: OptionalModuleOutcome::Error {
                error_code: error_code.clone(),
            },
        },
        ReplayedRisk::NotRun(reason_code) => RiskEvaluatedPayload {
            risk_rule_set_version: Some(rule_set.version().into()),
            risk_rule_set_hash: Some(rule_set.rule_set_hash().into()),
            outcome: OptionalModuleOutcome::NotRun {
                reason_code: (*reason_code).into(),
            },
        },
    };
    if &evidence == original {
        Ok(())
    } else {
        Err(ReplayError::EvaluationMismatch)
    }
}

fn policy_evidence(outcome: &PolicyOutcome) -> PolicyEvaluatedPayload {
    PolicyEvaluatedPayload {
        outcome: RequiredModuleOutcome::Succeeded {
            result: match outcome.decision {
                PolicyDecision::Permit => AuditPolicyOutcome::Permit,
                PolicyDecision::Forbid => AuditPolicyOutcome::Forbid,
            },
        },
        policy_ids: outcome.policy_ids.clone(),
    }
}

fn risk_evidence(evaluation: &RiskEvaluation) -> RiskEvaluatedPayload {
    RiskEvaluatedPayload {
        risk_rule_set_version: Some(evaluation.rule_set_version.clone()),
        risk_rule_set_hash: Some(evaluation.rule_set_hash.clone()),
        outcome: OptionalModuleOutcome::Succeeded {
            result: evaluation
                .findings
                .iter()
                .map(|finding| RiskFindingEvidence {
                    code: finding.code.clone(),
                    severity: match finding.severity {
                        Severity::Info => RiskSeverity::Info,
                        Severity::Medium => RiskSeverity::Medium,
                        Severity::High => RiskSeverity::High,
                        Severity::Critical => RiskSeverity::Critical,
                    },
                })
                .collect(),
        },
    }
}

fn evidence_payload(
    evidence: &serde_json::Value,
    field: &str,
    event_type: EventType,
) -> Result<AuditPayload, ReplayError> {
    let value = evidence.get(field).ok_or(ReplayError::InputTampered)?;
    AuditPayload::from_data(event_type, value).map_err(|_| ReplayError::InputTampered)
}

fn validate_request(request: &OriginalReplayRequest) -> Result<(), ReplayError> {
    for value in [
        request.replay_id.as_str(),
        request.organization_id.as_str(),
        request.intent_id.as_str(),
        request.actor_id.as_str(),
    ] {
        if value.is_empty()
            || value.len() > 128
            || value.trim() != value
            || value
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control())
        {
            return Err(ReplayError::InvalidRequest);
        }
    }
    if request.occurred_at.as_datetime().timestamp_subsec_nanos() % 1_000_000 != 0 {
        return Err(ReplayError::InvalidRequest);
    }
    Ok(())
}

fn map_policy_error(error: StoreError) -> ReplayError {
    match error {
        StoreError::PolicyBundleNotFound { .. } => ReplayError::PolicyArtifactMissing,
        StoreError::PolicyStateCorrupt { .. } => ReplayError::InputTampered,
        other => map_input_error(other),
    }
}

fn map_risk_error(error: StoreError) -> ReplayError {
    match error {
        StoreError::RiskRuleSetNotFound { .. } => ReplayError::RiskArtifactMissing,
        StoreError::RiskStateCorrupt { .. } => ReplayError::InputTampered,
        other => map_input_error(other),
    }
}

fn map_input_error(error: StoreError) -> ReplayError {
    match error {
        StoreError::DurableStateCorrupt { .. }
        | StoreError::AuditChainCorrupt { .. }
        | StoreError::IncompleteAdmissionEvidence { .. }
        | StoreError::IncompleteDecisionEvidence { .. }
        | StoreError::EvaluationContextNotFound { .. }
        | StoreError::DecisionBindingMismatch { .. } => ReplayError::InputTampered,
        other => ReplayError::Store(other),
    }
}

fn store_error(error: StoreError) -> ReplayError {
    ReplayError::Store(error)
}

async fn authorize_replay(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    actor_id: &str,
    organization_id: &str,
) -> Result<(), ReplayError> {
    authorize_decision_read(transaction, actor_id, organization_id)
        .await
        .map_err(|error| match error {
            StoreError::DecisionReadAuthorizationDenied { .. } => ReplayError::AuthorizationDenied,
            other => map_input_error(other),
        })
}
