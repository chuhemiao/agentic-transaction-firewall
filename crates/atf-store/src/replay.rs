use atf_audit::{
    AuditPayload, CounterfactualReplayCompletedPayload, EventType, OptionalModuleOutcome,
    OriginalReplayCompletedPayload, PolicyEvaluatedPayload, PolicyOutcome as AuditPolicyOutcome,
    RequiredModuleOutcome, RiskEvaluatedPayload, RiskFindingEvidence, RiskSeverity,
    SimulationCompletedPayload,
};
use atf_core::{
    sort_json_keys, DecisionKind, EvaluationContext, Timestamp, VersionedArtifactReference,
};
use atf_decision::{decide, Decision, DecisionInput, PolicyDecisionInput, RiskDecisionInput};
use atf_policy::{PolicyDecision, PolicyOutcome};
use atf_risk::{RiskEvaluation, Severity};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::FromRow;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReplaySelection {
    pub bundle_id: String,
    pub policy_version: String,
    pub bundle_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskReplaySelection {
    pub engine_version: String,
    pub rule_set_version: String,
    pub rule_set_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterfactualReplayRequest {
    pub replay_id: String,
    pub organization_id: String,
    pub intent_id: String,
    pub counterfactual_evaluation_id: String,
    pub counterfactual_decision_id: String,
    pub selected_policy: PolicyReplaySelection,
    pub selected_risk: RiskReplaySelection,
    pub actor_id: String,
    pub occurred_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterfactualEvaluation {
    pub schema_version: u32,
    pub authoritative: bool,
    pub replay_id: String,
    pub evaluation_id: String,
    pub original_evaluation_id: String,
    pub original_decision_id: String,
    pub intent_id: String,
    pub intent_hash: String,
    pub evaluation_context_hash: String,
    pub context_snapshot_hash: String,
    pub evaluated_at: Timestamp,
    pub policy: VersionedArtifactReference,
    pub risk: VersionedArtifactReference,
    pub policy_result: PolicyEvaluatedPayload,
    pub risk_result: RiskEvaluatedPayload,
    pub simulation_result: SimulationCompletedPayload,
}

impl CounterfactualEvaluation {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&sort_json_keys(
            serde_json::to_value(self)
                .expect("Counterfactual Evaluation serialization cannot fail"),
        ))
        .expect("canonical Counterfactual Evaluation serialization cannot fail")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CounterfactualReplayResult {
    pub replay_id: String,
    pub organization_id: String,
    pub intent_id: String,
    pub original_evaluation_id: String,
    pub original_decision_id: String,
    pub original_decision_hash: String,
    pub original_outcome: DecisionKind,
    pub evaluation_context: EvaluationContext,
    pub evaluation: CounterfactualEvaluation,
    pub evaluation_hash: String,
    pub decision: Decision,
    pub decision_hash: String,
    pub selected_policy: PolicyReplaySelection,
    pub selected_risk: RiskReplaySelection,
    pub outcome_changed: bool,
    pub authoritative: bool,
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
    #[error("an explicitly selected Counterfactual Replay artifact is missing")]
    SelectedArtifactMissing,
    #[error("a Counterfactual Replay identity conflicts with immutable state")]
    CounterfactualConflict,
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
            Self::SelectedArtifactMissing => "REPLAY_SELECTED_ARTIFACT_MISSING",
            Self::CounterfactualConflict => "REPLAY_COUNTERFACTUAL_CONFLICT",
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

impl Store {
    /// Re-evaluate an immutable original snapshot under explicitly selected
    /// Policy/Risk artifacts. The result is a separate non-authoritative
    /// record; authoritative Evaluation/Decision rows are never written.
    pub async fn replay_counterfactual(
        &self,
        request: CounterfactualReplayRequest,
    ) -> Result<CounterfactualReplayResult, ReplayError> {
        validate_counterfactual_request(&request)?;
        authorize_before_discovery(self, &request.actor_id, &request.organization_id).await?;

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
        let original_context = original
            .evaluation_context
            .as_ref()
            .ok_or(ReplayError::ContextMissing)?;
        if request.occurred_at < original.decided_at
            || request.counterfactual_evaluation_id == original.evaluation.evaluation_id
            || request.counterfactual_decision_id == original.decision.decision_id
        {
            return Err(ReplayError::InvalidRequest);
        }

        let selected_policy = VersionedArtifactReference::available(
            request.selected_policy.bundle_id.clone(),
            request.selected_policy.policy_version.clone(),
            request.selected_policy.bundle_hash.clone(),
        )
        .map_err(|_| ReplayError::InvalidRequest)?;
        let selected_risk = VersionedArtifactReference::available(
            request.selected_risk.engine_version.clone(),
            request.selected_risk.rule_set_version.clone(),
            request.selected_risk.rule_set_hash.clone(),
        )
        .map_err(|_| ReplayError::InvalidRequest)?;
        if &selected_policy == original_context.policy()
            && &selected_risk == original_context.risk()
        {
            return Err(ReplayError::InvalidRequest);
        }

        let policy = self
            .load_policy_bundle(
                &request.organization_id,
                original_context.environment(),
                &request.selected_policy.bundle_id,
                &request.selected_policy.policy_version,
                &request.selected_policy.bundle_hash,
                original_context.evaluation_time(),
            )
            .await
            .map_err(map_selected_policy_error)?;
        let risk_rule_set = self
            .load_risk_rule_set(
                &request.organization_id,
                original_context.environment(),
                &request.selected_risk.engine_version,
                &request.selected_risk.rule_set_version,
                &request.selected_risk.rule_set_hash,
            )
            .await
            .map_err(map_selected_risk_error)?;
        let history =
            replay_history_prefix(self, &request.organization_id, original_context).await?;
        let context = original_context
            .derive_counterfactual(
                request.counterfactual_evaluation_id.clone(),
                selected_policy,
                selected_risk,
            )
            .map_err(|_| ReplayError::InputTampered)?;

        let (policy_outcome, policy_error_code, policy_result) =
            counterfactual_policy(policy.evaluate(&admitted.intent, &context));
        let replayed_risk = match policy_outcome.as_ref() {
            Some(outcome) if outcome.decision == PolicyDecision::Permit => {
                match atf_risk::evaluate_context(
                    &admitted.intent,
                    &risk_rule_set,
                    &context,
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
        let risk_result = replayed_risk_evidence(&replayed_risk, &risk_rule_set);
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
        let decision = decide(DecisionInput {
            decision_id: request.counterfactual_decision_id.clone(),
            intent: &admitted.intent,
            evaluation_context: &context,
            policy: policy_input,
            risk: risk_input,
        })
        .map_err(|_| ReplayError::EvaluationMismatch)?;
        let evaluation = CounterfactualEvaluation {
            schema_version: 1,
            authoritative: false,
            replay_id: request.replay_id.clone(),
            evaluation_id: request.counterfactual_evaluation_id.clone(),
            original_evaluation_id: original.evaluation.evaluation_id.clone(),
            original_decision_id: original.decision.decision_id.clone(),
            intent_id: admitted.intent.intent_id.clone(),
            intent_hash: admitted.intent_hash.clone(),
            evaluation_context_hash: context.evaluation_context_hash().into(),
            context_snapshot_hash: context.context_snapshot_hash().into(),
            evaluated_at: context.evaluation_time(),
            policy: context.policy().clone(),
            risk: context.risk().clone(),
            policy_result,
            risk_result,
            simulation_result: SimulationCompletedPayload {
                outcome: OptionalModuleOutcome::NotRun {
                    reason_code: context.simulation().reason_code().into(),
                },
            },
        };
        let context_json: Value = serde_json::from_slice(context.canonical_bytes())
            .map_err(|_| ReplayError::InputTampered)?;
        let evaluation_bytes = evaluation.canonical_bytes();
        let evaluation_json: Value = serde_json::from_slice(&evaluation_bytes)
            .map_err(|_| ReplayError::EvaluationMismatch)?;
        let evaluation_hash = atf_core::sha256_hex(&evaluation_bytes);
        let decision_bytes = decision.canonical_bytes();
        let decision_json: Value =
            serde_json::from_slice(&decision_bytes).map_err(|_| ReplayError::DecisionMismatch)?;
        let outcome_changed = decision.decision != original.decision.decision;

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
            AuditPayload::CounterfactualReplayCompleted(CounterfactualReplayCompletedPayload {
                organization_id: request.organization_id.clone(),
                replay_id: request.replay_id.clone(),
                original_evaluation_id: original.evaluation.evaluation_id.clone(),
                original_decision_id: original.decision.decision_id.clone(),
                original_decision_hash: original.decision_hash.clone(),
                counterfactual_evaluation_id: request.counterfactual_evaluation_id.clone(),
                evaluation_context_hash: context.evaluation_context_hash().into(),
                counterfactual_evaluation_hash: evaluation_hash.clone(),
                counterfactual_decision_id: request.counterfactual_decision_id.clone(),
                counterfactual_decision_hash: decision.decision_hash.clone(),
                policy_bundle_id: request.selected_policy.bundle_id.clone(),
                policy_version: request.selected_policy.policy_version.clone(),
                policy_bundle_hash: request.selected_policy.bundle_hash.clone(),
                risk_engine_version: request.selected_risk.engine_version.clone(),
                risk_rule_set_version: request.selected_risk.rule_set_version.clone(),
                risk_rule_set_hash: request.selected_risk.rule_set_hash.clone(),
                original_outcome: original.decision.decision,
                counterfactual_outcome: decision.decision,
                outcome_changed,
                authoritative: false,
                actor_id: request.actor_id.clone(),
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
        let inserted = sqlx::query(
            r#"
            INSERT INTO counterfactual_replays (
                organization_id, replay_id, intent_id,
                original_evaluation_id, original_decision_id, original_decision_hash,
                counterfactual_evaluation_id, counterfactual_decision_id, environment,
                policy_bundle_id, policy_version, policy_bundle_hash,
                risk_engine_version, risk_rule_set_version, risk_rule_set_hash,
                canonical_context, canonical_context_bytes, evaluation_context_hash,
                canonical_evaluation, canonical_evaluation_bytes, evaluation_hash,
                canonical_decision, canonical_decision_bytes, counterfactual_decision_hash,
                original_outcome, counterfactual_outcome, outcome_changed, authoritative,
                requested_by_operator_id, completed_event_id, evaluated_at, recorded_at
            )
            SELECT
                $1, $2, $3, $4, $5, $6, $7, $8, $9,
                $10, $11, $12, $13, $14, $15, $16, $17, $18,
                $19, $20, $21, $22, $23, $24, $25, $26, $27, FALSE,
                $28, $29, $30, $31
            WHERE NOT EXISTS (
                SELECT 1 FROM evaluations
                WHERE organization_id = $1 AND evaluation_id = $7
            ) AND NOT EXISTS (
                SELECT 1 FROM decisions
                WHERE organization_id = $1 AND decision_id = $8
            )
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(&request.organization_id)
        .bind(&request.replay_id)
        .bind(&request.intent_id)
        .bind(&original.evaluation.evaluation_id)
        .bind(&original.decision.decision_id)
        .bind(&original.decision_hash)
        .bind(&request.counterfactual_evaluation_id)
        .bind(&request.counterfactual_decision_id)
        .bind(original_context.environment())
        .bind(&request.selected_policy.bundle_id)
        .bind(&request.selected_policy.policy_version)
        .bind(&request.selected_policy.bundle_hash)
        .bind(&request.selected_risk.engine_version)
        .bind(&request.selected_risk.rule_set_version)
        .bind(&request.selected_risk.rule_set_hash)
        .bind(&context_json)
        .bind(context.canonical_bytes())
        .bind(context.evaluation_context_hash())
        .bind(&evaluation_json)
        .bind(&evaluation_bytes)
        .bind(&evaluation_hash)
        .bind(&decision_json)
        .bind(&decision_bytes)
        .bind(&decision.decision_hash)
        .bind(decision_kind_name(original.decision.decision))
        .bind(decision_kind_name(decision.decision))
        .bind(outcome_changed)
        .bind(&request.actor_id)
        .bind(&audit_event.event.event_id)
        .bind(context.evaluation_time().as_datetime())
        .bind(request.occurred_at.as_datetime())
        .execute(&mut *transaction)
        .await
        .map_err(|error| store_error(StoreError::from(error)))?;
        if inserted.rows_affected() != 1 {
            return Err(ReplayError::CounterfactualConflict);
        }
        transaction
            .commit()
            .await
            .map_err(|error| store_error(StoreError::from(error)))?;

        Ok(CounterfactualReplayResult {
            replay_id: request.replay_id,
            organization_id: request.organization_id,
            intent_id: request.intent_id,
            original_evaluation_id: original.evaluation.evaluation_id,
            original_decision_id: original.decision.decision_id,
            original_decision_hash: original.decision_hash,
            original_outcome: original.decision.decision,
            evaluation_context: context,
            evaluation,
            evaluation_hash,
            decision_hash: decision.decision_hash.clone(),
            decision,
            selected_policy: request.selected_policy,
            selected_risk: request.selected_risk,
            outcome_changed,
            authoritative: false,
            audit_event,
        })
    }

    /// Reload and fully verify one immutable Counterfactual Replay record.
    pub async fn load_counterfactual_replay(
        &self,
        organization_id: &str,
        replay_id: &str,
    ) -> Result<Option<CounterfactualReplayResult>, ReplayError> {
        validate_identifier(organization_id)?;
        validate_identifier(replay_id)?;
        let row: Option<CounterfactualReplayRow> = sqlx::query_as(
            r#"
            SELECT organization_id, replay_id, intent_id,
                   original_evaluation_id, original_decision_id,
                   original_decision_hash::text AS original_decision_hash,
                   counterfactual_evaluation_id, counterfactual_decision_id, environment,
                   policy_bundle_id, policy_version,
                   policy_bundle_hash::text AS policy_bundle_hash,
                   risk_engine_version, risk_rule_set_version,
                   risk_rule_set_hash::text AS risk_rule_set_hash,
                   canonical_context, canonical_context_bytes,
                   evaluation_context_hash::text AS evaluation_context_hash,
                   canonical_evaluation, canonical_evaluation_bytes,
                   evaluation_hash::text AS evaluation_hash,
                   canonical_decision, canonical_decision_bytes,
                   counterfactual_decision_hash::text AS counterfactual_decision_hash,
                   original_outcome, counterfactual_outcome, outcome_changed, authoritative,
                   requested_by_operator_id, completed_event_id, evaluated_at, recorded_at
            FROM counterfactual_replays
            WHERE organization_id = $1 AND replay_id = $2
            "#,
        )
        .bind(organization_id)
        .bind(replay_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|error| store_error(StoreError::from(error)))?;
        let Some(row) = row else {
            return Ok(None);
        };
        self.verify_counterfactual_row(row).await.map(Some)
    }

    async fn verify_counterfactual_row(
        &self,
        row: CounterfactualReplayRow,
    ) -> Result<CounterfactualReplayResult, ReplayError> {
        let fail = || ReplayError::InputTampered;
        let admitted = self
            .load_admitted_intent(&row.organization_id, &row.intent_id)
            .await
            .map_err(map_input_error)?
            .ok_or_else(fail)?;
        let original = self
            .load_finalized_decision(&row.organization_id, &row.intent_id)
            .await
            .map_err(map_input_error)?
            .ok_or_else(fail)?;
        if original.evaluation.evaluation_id != row.original_evaluation_id
            || original.decision.decision_id != row.original_decision_id
            || original.decision_hash != row.original_decision_hash
            || row.authoritative
        {
            return Err(fail());
        }
        let context = EvaluationContext::from_persisted(
            &row.canonical_context_bytes,
            &row.evaluation_context_hash,
        )
        .map_err(|_| fail())?;
        if serde_json::from_slice::<Value>(&row.canonical_context_bytes).map_err(|_| fail())?
            != row.canonical_context
            || serde_json::to_vec(&sort_json_keys(row.canonical_context.clone()))
                .map_err(|_| fail())?
                != row.canonical_context_bytes
            || context.evaluation_id() != row.counterfactual_evaluation_id
            || context.intent_id() != row.intent_id
            || context.intent_hash() != admitted.intent_hash
            || context.environment() != row.environment
            || context.evaluation_time() != Timestamp::from_datetime(row.evaluated_at)
            || context
                .verify_agent_context(&admitted.intent.context)
                .is_err()
        {
            return Err(fail());
        }
        let selected_policy = PolicyReplaySelection {
            bundle_id: row.policy_bundle_id.clone(),
            policy_version: row.policy_version.clone(),
            bundle_hash: row.policy_bundle_hash.clone(),
        };
        let selected_risk = RiskReplaySelection {
            engine_version: row.risk_engine_version.clone(),
            rule_set_version: row.risk_rule_set_version.clone(),
            rule_set_hash: row.risk_rule_set_hash.clone(),
        };
        if context.policy().available_parts()
            != Some((
                selected_policy.bundle_id.as_str(),
                selected_policy.policy_version.as_str(),
                selected_policy.bundle_hash.as_str(),
            ))
            || context.risk().available_parts()
                != Some((
                    selected_risk.engine_version.as_str(),
                    selected_risk.rule_set_version.as_str(),
                    selected_risk.rule_set_hash.as_str(),
                ))
        {
            return Err(fail());
        }
        self.load_policy_bundle(
            &row.organization_id,
            &row.environment,
            &row.policy_bundle_id,
            &row.policy_version,
            &row.policy_bundle_hash,
            context.evaluation_time(),
        )
        .await
        .map_err(map_selected_policy_error)?;
        self.load_risk_rule_set(
            &row.organization_id,
            &row.environment,
            &row.risk_engine_version,
            &row.risk_rule_set_version,
            &row.risk_rule_set_hash,
        )
        .await
        .map_err(map_selected_risk_error)?;

        let evaluation: CounterfactualEvaluation =
            serde_json::from_slice(&row.canonical_evaluation_bytes).map_err(|_| fail())?;
        if serde_json::from_slice::<Value>(&row.canonical_evaluation_bytes).map_err(|_| fail())?
            != row.canonical_evaluation
            || evaluation.canonical_bytes() != row.canonical_evaluation_bytes
            || atf_core::sha256_hex(&row.canonical_evaluation_bytes) != row.evaluation_hash
            || evaluation.schema_version != 1
            || evaluation.authoritative
            || evaluation.replay_id != row.replay_id
            || evaluation.evaluation_id != row.counterfactual_evaluation_id
            || evaluation.original_evaluation_id != row.original_evaluation_id
            || evaluation.original_decision_id != row.original_decision_id
            || evaluation.intent_id != row.intent_id
            || evaluation.intent_hash != admitted.intent_hash
            || evaluation.evaluation_context_hash != row.evaluation_context_hash
            || evaluation.context_snapshot_hash != context.context_snapshot_hash()
            || evaluation.evaluated_at != context.evaluation_time()
            || evaluation.policy != *context.policy()
            || evaluation.risk != *context.risk()
        {
            return Err(fail());
        }
        let decision: Decision =
            serde_json::from_slice(&row.canonical_decision_bytes).map_err(|_| fail())?;
        if serde_json::from_slice::<Value>(&row.canonical_decision_bytes).map_err(|_| fail())?
            != row.canonical_decision
            || decision.canonical_bytes() != row.canonical_decision_bytes
            || decision.decision_hash != row.counterfactual_decision_hash
            || decision.decision_id != row.counterfactual_decision_id
            || decision.verify_binding(&admitted.intent, &context).is_err()
            || decision_kind_name(original.decision.decision) != row.original_outcome
            || decision_kind_name(decision.decision) != row.counterfactual_outcome
            || row.outcome_changed != (original.decision.decision != decision.decision)
        {
            return Err(fail());
        }
        let chain = self
            .load_verified_audit_chain(&row.organization_id)
            .await
            .map_err(map_input_error)?;
        let audit_event = chain
            .into_iter()
            .find(|event| event.event.event_id == row.completed_event_id)
            .ok_or_else(fail)?;
        let payload = audit_event.event.typed_payload().map_err(|_| fail())?;
        let evidence_matches = audit_event.event.occurred_at
            == Timestamp::from_datetime(row.recorded_at)
            && audit_event.event.intent_id.as_deref() == Some(row.intent_id.as_str())
            && audit_event.evaluation_id.as_deref() == Some(row.original_evaluation_id.as_str())
            && audit_event.decision_id.as_deref() == Some(row.original_decision_id.as_str())
            && matches!(payload, AuditPayload::CounterfactualReplayCompleted(ref value)
                if value.organization_id == row.organization_id
                    && value.replay_id == row.replay_id
                    && value.original_evaluation_id == row.original_evaluation_id
                    && value.original_decision_id == row.original_decision_id
                    && value.original_decision_hash == row.original_decision_hash
                    && value.counterfactual_evaluation_id == row.counterfactual_evaluation_id
                    && value.evaluation_context_hash == row.evaluation_context_hash
                    && value.counterfactual_evaluation_hash == row.evaluation_hash
                    && value.counterfactual_decision_id == row.counterfactual_decision_id
                    && value.counterfactual_decision_hash == row.counterfactual_decision_hash
                    && value.policy_bundle_id == row.policy_bundle_id
                    && value.policy_version == row.policy_version
                    && value.policy_bundle_hash == row.policy_bundle_hash
                    && value.risk_engine_version == row.risk_engine_version
                    && value.risk_rule_set_version == row.risk_rule_set_version
                    && value.risk_rule_set_hash == row.risk_rule_set_hash
                    && value.original_outcome == original.decision.decision
                    && value.counterfactual_outcome == decision.decision
                    && value.outcome_changed == row.outcome_changed
                    && !value.authoritative
                    && value.actor_id == row.requested_by_operator_id);
        if !evidence_matches {
            return Err(fail());
        }

        Ok(CounterfactualReplayResult {
            replay_id: row.replay_id,
            organization_id: row.organization_id,
            intent_id: row.intent_id,
            original_evaluation_id: row.original_evaluation_id,
            original_decision_id: row.original_decision_id,
            original_decision_hash: row.original_decision_hash,
            original_outcome: original.decision.decision,
            evaluation_context: context,
            evaluation,
            evaluation_hash: row.evaluation_hash,
            decision_hash: row.counterfactual_decision_hash,
            decision,
            selected_policy,
            selected_risk,
            outcome_changed: row.outcome_changed,
            authoritative: false,
            audit_event,
        })
    }
}

#[derive(Debug, FromRow)]
struct CounterfactualReplayRow {
    organization_id: String,
    replay_id: String,
    intent_id: String,
    original_evaluation_id: String,
    original_decision_id: String,
    original_decision_hash: String,
    counterfactual_evaluation_id: String,
    counterfactual_decision_id: String,
    environment: String,
    policy_bundle_id: String,
    policy_version: String,
    policy_bundle_hash: String,
    risk_engine_version: String,
    risk_rule_set_version: String,
    risk_rule_set_hash: String,
    canonical_context: Value,
    canonical_context_bytes: Vec<u8>,
    evaluation_context_hash: String,
    canonical_evaluation: Value,
    canonical_evaluation_bytes: Vec<u8>,
    evaluation_hash: String,
    canonical_decision: Value,
    canonical_decision_bytes: Vec<u8>,
    counterfactual_decision_hash: String,
    original_outcome: String,
    counterfactual_outcome: String,
    outcome_changed: bool,
    authoritative: bool,
    requested_by_operator_id: String,
    completed_event_id: String,
    evaluated_at: DateTime<Utc>,
    recorded_at: DateTime<Utc>,
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

fn counterfactual_policy(
    evaluated: Result<PolicyOutcome, atf_policy::PolicyError>,
) -> (
    Option<PolicyOutcome>,
    Option<String>,
    PolicyEvaluatedPayload,
) {
    match evaluated {
        Ok(outcome) => {
            let evidence = policy_evidence(&outcome);
            (Some(outcome), None, evidence)
        }
        Err(_) => {
            let error_code = "POLICY_EVALUATION_ERROR".to_owned();
            (
                None,
                Some(error_code.clone()),
                PolicyEvaluatedPayload {
                    outcome: RequiredModuleOutcome::Error { error_code },
                    policy_ids: Vec::new(),
                },
            )
        }
    }
}

fn replayed_risk_evidence(
    replayed: &ReplayedRisk,
    rule_set: &atf_risk::RiskRuleSet,
) -> RiskEvaluatedPayload {
    match replayed {
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
    }
}

async fn authorize_before_discovery(
    store: &Store,
    actor_id: &str,
    organization_id: &str,
) -> Result<(), ReplayError> {
    let mut authorization = store
        .pool
        .begin()
        .await
        .map_err(|error| store_error(StoreError::from(error)))?;
    crate::repository::set_write_timeouts(&mut authorization)
        .await
        .map_err(store_error)?;
    authorize_replay(&mut authorization, actor_id, organization_id).await?;
    authorization
        .commit()
        .await
        .map_err(|error| store_error(StoreError::from(error)))
}

async fn replay_history_prefix(
    store: &Store,
    organization_id: &str,
    context: &EvaluationContext,
) -> Result<Vec<StoredAuditEvent>, ReplayError> {
    let chain = store
        .load_verified_audit_chain(organization_id)
        .await
        .map_err(map_input_error)?;
    let through_sequence = usize::try_from(context.history().through_sequence())
        .map_err(|_| ReplayError::InputTampered)?;
    if through_sequence == 0 || chain.len() < through_sequence {
        return Err(ReplayError::InputTampered);
    }
    let history = chain[..through_sequence].to_vec();
    if history.last().map(|event| event.event_hash.as_str())
        != Some(context.history().snapshot_hash())
    {
        return Err(ReplayError::InputTampered);
    }
    Ok(history)
}

const fn decision_kind_name(kind: DecisionKind) -> &'static str {
    match kind {
        DecisionKind::Permit => "PERMIT",
        DecisionKind::Review => "REVIEW",
        DecisionKind::Deny => "DENY",
        DecisionKind::Error => "ERROR",
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

fn validate_counterfactual_request(
    request: &CounterfactualReplayRequest,
) -> Result<(), ReplayError> {
    for value in [
        request.replay_id.as_str(),
        request.organization_id.as_str(),
        request.intent_id.as_str(),
        request.counterfactual_evaluation_id.as_str(),
        request.counterfactual_decision_id.as_str(),
        request.selected_policy.bundle_id.as_str(),
        request.selected_policy.policy_version.as_str(),
        request.selected_risk.engine_version.as_str(),
        request.selected_risk.rule_set_version.as_str(),
        request.actor_id.as_str(),
    ] {
        validate_identifier(value)?;
    }
    for hash in [
        request.selected_policy.bundle_hash.as_str(),
        request.selected_risk.rule_set_hash.as_str(),
    ] {
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ReplayError::InvalidRequest);
        }
    }
    if request.occurred_at.as_datetime().timestamp_subsec_nanos() % 1_000_000 != 0 {
        return Err(ReplayError::InvalidRequest);
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ReplayError> {
    if value.is_empty()
        || value.len() > 128
        || value.trim() != value
        || value
            .bytes()
            .any(|byte| byte == 0 || byte.is_ascii_control())
    {
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

fn map_selected_policy_error(error: StoreError) -> ReplayError {
    match error {
        StoreError::PolicyBundleNotFound { .. } => ReplayError::SelectedArtifactMissing,
        StoreError::PolicyStateCorrupt { .. } => ReplayError::InputTampered,
        other => map_input_error(other),
    }
}

fn map_selected_risk_error(error: StoreError) -> ReplayError {
    match error {
        StoreError::RiskRuleSetNotFound { .. } => ReplayError::SelectedArtifactMissing,
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
