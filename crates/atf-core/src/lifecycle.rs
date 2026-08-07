use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// The stable Intent lifecycle states defined by PRD §16.2.1.
///
/// Persistence is deliberately outside this type. DS-007 will store and
/// advance it, while reusing [`validate_lifecycle_transition`] as the single
/// domain transition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntentLifecycleState {
    Received,
    IdentityVerified,
    IdentityRejected,
    PolicyEvaluated,
    RiskEvaluated,
    SimulationCompleted,
    DecidedPermit,
    DecidedReview,
    DecidedDeny,
    DecidedError,
    ApprovalPending,
    Approved,
    Rejected,
    ExecutionAuthorized,
    ExecutionSubmitted,
    ExecutionConfirmed,
    ExecutionFailed,
    SettlementVerified,
    ReconciliationFailed,
    Expired,
    Cancelled,
}

impl IntentLifecycleState {
    pub const ALL: [Self; 21] = [
        Self::Received,
        Self::IdentityVerified,
        Self::IdentityRejected,
        Self::PolicyEvaluated,
        Self::RiskEvaluated,
        Self::SimulationCompleted,
        Self::DecidedPermit,
        Self::DecidedReview,
        Self::DecidedDeny,
        Self::DecidedError,
        Self::ApprovalPending,
        Self::Approved,
        Self::Rejected,
        Self::ExecutionAuthorized,
        Self::ExecutionSubmitted,
        Self::ExecutionConfirmed,
        Self::ExecutionFailed,
        Self::SettlementVerified,
        Self::ReconciliationFailed,
        Self::Expired,
        Self::Cancelled,
    ];

    pub fn allowed_next(self) -> &'static [Self] {
        use IntentLifecycleState as State;

        match self {
            State::Received => &[
                State::IdentityVerified,
                State::IdentityRejected,
                State::Expired,
                State::Cancelled,
            ],
            State::IdentityVerified => &[State::PolicyEvaluated, State::Expired, State::Cancelled],
            State::PolicyEvaluated => &[State::RiskEvaluated, State::Expired, State::Cancelled],
            State::RiskEvaluated => &[State::SimulationCompleted, State::Expired, State::Cancelled],
            State::SimulationCompleted => &[
                State::DecidedPermit,
                State::DecidedReview,
                State::DecidedDeny,
                State::DecidedError,
                State::Expired,
                State::Cancelled,
            ],
            State::DecidedPermit => &[
                State::ApprovalPending,
                State::ExecutionAuthorized,
                State::Expired,
                State::Cancelled,
            ],
            State::DecidedReview => &[State::ApprovalPending, State::Expired, State::Cancelled],
            State::ApprovalPending => &[
                State::Approved,
                State::Rejected,
                State::Expired,
                State::Cancelled,
            ],
            State::Approved => &[State::ExecutionAuthorized, State::Expired, State::Cancelled],
            State::ExecutionAuthorized => {
                &[State::ExecutionSubmitted, State::Expired, State::Cancelled]
            }
            State::ExecutionSubmitted => &[State::ExecutionConfirmed, State::ExecutionFailed],
            State::ExecutionConfirmed => &[State::SettlementVerified, State::ReconciliationFailed],
            State::IdentityRejected
            | State::DecidedDeny
            | State::DecidedError
            | State::Rejected
            | State::ExecutionFailed
            | State::SettlementVerified
            | State::ReconciliationFailed
            | State::Expired
            | State::Cancelled => &[],
        }
    }

    pub fn is_terminal(self) -> bool {
        self.allowed_next().is_empty()
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Received => "RECEIVED",
            Self::IdentityVerified => "IDENTITY_VERIFIED",
            Self::IdentityRejected => "IDENTITY_REJECTED",
            Self::PolicyEvaluated => "POLICY_EVALUATED",
            Self::RiskEvaluated => "RISK_EVALUATED",
            Self::SimulationCompleted => "SIMULATION_COMPLETED",
            Self::DecidedPermit => "DECIDED_PERMIT",
            Self::DecidedReview => "DECIDED_REVIEW",
            Self::DecidedDeny => "DECIDED_DENY",
            Self::DecidedError => "DECIDED_ERROR",
            Self::ApprovalPending => "APPROVAL_PENDING",
            Self::Approved => "APPROVED",
            Self::Rejected => "REJECTED",
            Self::ExecutionAuthorized => "EXECUTION_AUTHORIZED",
            Self::ExecutionSubmitted => "EXECUTION_SUBMITTED",
            Self::ExecutionConfirmed => "EXECUTION_CONFIRMED",
            Self::ExecutionFailed => "EXECUTION_FAILED",
            Self::SettlementVerified => "SETTLEMENT_VERIFIED",
            Self::ReconciliationFailed => "RECONCILIATION_FAILED",
            Self::Expired => "EXPIRED",
            Self::Cancelled => "CANCELLED",
        }
    }
}

impl fmt::Display for IntentLifecycleState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("invalid Intent lifecycle transition from {from} to {to}")]
pub struct LifecycleTransitionError {
    pub from: IntentLifecycleState,
    pub to: IntentLifecycleState,
}

/// Validate one state change. Unknown, backward, self, and post-terminal
/// transitions all fail closed through the same explicit error.
pub fn validate_lifecycle_transition(
    from: IntentLifecycleState,
    to: IntentLifecycleState,
) -> Result<(), LifecycleTransitionError> {
    if from.allowed_next().contains(&to) {
        Ok(())
    } else {
        Err(LifecycleTransitionError { from, to })
    }
}
