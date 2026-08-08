use atf_core::DecisionKind;
use atf_intent::TransactionIntent;
use atf_policy::{PolicyDecision, PolicyOutcome};
use atf_risk::{RiskEvaluation, Severity};

use crate::error::DecisionError;
use crate::types::{Decision, Reason};

/// Exact Policy module outcome consumed by the Decision merge. Errors retain
/// only a stable safe code; detailed Policy diagnostics never enter Decision.
#[derive(Debug, Clone, Copy)]
pub enum PolicyDecisionInput<'a> {
    Evaluated(&'a PolicyOutcome),
    Error { error_code: &'a str },
}

/// Exact Risk module outcome consumed by the Decision merge. `NotRun` is only
/// valid after Policy forbid/error; a Policy Permit requires Evaluated/Error.
#[derive(Debug, Clone, Copy)]
pub enum RiskDecisionInput<'a> {
    Evaluated(&'a RiskEvaluation),
    Error { error_code: &'a str },
    NotRun { reason_code: &'a str },
}

/// All authority needed to create one canonical Decision. IDs and time come
/// from the caller's already-persisted Evaluation Context; the merge samples
/// no clock, randomness or environment state.
#[derive(Debug)]
pub struct DecisionInput<'a> {
    pub decision_id: String,
    pub intent: &'a TransactionIntent,
    pub evaluation_context: &'a atf_core::EvaluationContext,
    pub policy: PolicyDecisionInput<'a>,
    pub risk: RiskDecisionInput<'a>,
}

/// Merge Policy and Risk into a strongly bound version-1 Decision.
///
/// The function rejects module outputs whose Bundle/Rule Set identity differs
/// from the immutable Evaluation Context. Simulator remains explicitly
/// `NOT_RUN` through the Context binding until a typed Simulator exists.
pub fn decide(input: DecisionInput<'_>) -> Result<Decision, DecisionError> {
    validate_base_binding(input.intent, input.evaluation_context)?;

    let (decision, reasons) = match input.policy {
        PolicyDecisionInput::Error { error_code } => {
            require_not_run(input.risk)?;
            (
                DecisionKind::Error,
                vec![module_error_reason(error_code, "Policy")],
            )
        }
        PolicyDecisionInput::Evaluated(policy) => {
            validate_policy_binding(policy, input.evaluation_context)?;
            let policy_reasons = policy
                .policy_ids
                .iter()
                .map(|id| Reason {
                    code: id.clone(),
                    severity: "info".into(),
                    message: format!("Cedar policy `{id}` matched this request"),
                })
                .collect::<Vec<_>>();

            match policy.decision {
                PolicyDecision::Forbid => {
                    require_not_run(input.risk)?;
                    (DecisionKind::Deny, policy_reasons)
                }
                PolicyDecision::Permit => {
                    merge_permitted(input.risk, policy_reasons, input.evaluation_context)?
                }
            }
        }
    };

    Decision::seal(
        input.decision_id,
        input.intent,
        input.evaluation_context,
        decision,
        reasons,
    )
}

fn validate_base_binding(
    intent: &TransactionIntent,
    context: &atf_core::EvaluationContext,
) -> Result<(), DecisionError> {
    if context.intent_id() != intent.intent_id
        || context.intent_hash() != intent.canonical_hash()
        || context.verify_agent_context(&intent.context).is_err()
    {
        return Err(DecisionError::IntentBindingMismatch);
    }
    let profile =
        atf_intent::validate_profile(intent).map_err(|_| DecisionError::IntentBindingMismatch)?;
    if context.profile_id() != profile.id() || context.profile_version() != profile.version() {
        return Err(DecisionError::ContextBindingMismatch);
    }
    Ok(())
}

fn validate_policy_binding(
    policy: &PolicyOutcome,
    context: &atf_core::EvaluationContext,
) -> Result<(), DecisionError> {
    let expected = (
        policy.bundle_id.as_str(),
        policy.policy_version.as_str(),
        policy.bundle_hash.as_str(),
    );
    if context.policy().available_parts() != Some(expected) {
        return Err(DecisionError::PolicyBindingMismatch);
    }
    Ok(())
}

fn validate_risk_binding(
    risk: &RiskEvaluation,
    context: &atf_core::EvaluationContext,
) -> Result<(), DecisionError> {
    let Some((_, version, hash)) = context.risk().available_parts() else {
        return Err(DecisionError::RiskBindingMismatch);
    };
    if version != risk.rule_set_version || hash != risk.rule_set_hash {
        return Err(DecisionError::RiskBindingMismatch);
    }
    Ok(())
}

fn require_not_run(risk: RiskDecisionInput<'_>) -> Result<(), DecisionError> {
    match risk {
        RiskDecisionInput::NotRun { reason_code } if !reason_code.is_empty() => Ok(()),
        _ => Err(DecisionError::ModuleOrdering),
    }
}

fn merge_permitted(
    risk: RiskDecisionInput<'_>,
    mut reasons: Vec<Reason>,
    context: &atf_core::EvaluationContext,
) -> Result<(DecisionKind, Vec<Reason>), DecisionError> {
    match risk {
        RiskDecisionInput::Error { error_code } => Ok((
            DecisionKind::Error,
            vec![module_error_reason(error_code, "Risk")],
        )),
        RiskDecisionInput::NotRun { .. } => Err(DecisionError::ModuleOrdering),
        RiskDecisionInput::Evaluated(risk) => {
            validate_risk_binding(risk, context)?;
            reasons.extend(risk.findings.iter().map(|finding| Reason {
                code: finding.code.clone(),
                severity: finding.severity.to_string(),
                message: finding.message.clone(),
            }));
            let worst_risk = risk.findings.iter().map(|finding| finding.severity).max();
            let decision = match worst_risk {
                Some(Severity::Critical) => DecisionKind::Deny,
                Some(Severity::High) => DecisionKind::Review,
                _ => DecisionKind::Permit,
            };
            Ok((decision, reasons))
        }
    }
}

fn module_error_reason(code: &str, module: &str) -> Reason {
    Reason {
        code: code.into(),
        severity: "critical".into(),
        message: format!("{module} evaluation failed safely."),
    }
}
