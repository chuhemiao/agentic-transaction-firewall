//! The Audit Ledger: hash-chained events (PRD §16). This is the domain
//! logic — event shape, chaining, integrity verification — wrapped by
//! `atf-store` for durable PostgreSQL append. `services/gateway` uses that
//! durable store as its only Decision/Audit authority.

mod error;
mod event;
mod ledger;
mod payload;

pub use error::ChainVerificationError;
pub use event::{AuditEvent, EventType, NewAuditEvent};
pub use ledger::AuditLedger;
pub use payload::{
    AgentPausedPayload, AgentRegisteredPayload, AgentStatusChangedPayload, ApprovalRejectedPayload,
    ApprovalRequestedPayload, ApprovalResolvedPayload, AuditPayload, AuditPayloadError,
    BudgetPayload, ContextEnrichedPayload, CounterfactualReplayCompletedPayload,
    DecisionBindingEvidence, DecisionRecordedPayload, ExecutionConfirmedPayload,
    ExecutionFailedPayload, ExecutionGrantPayload, ExecutionSubmittedPayload,
    IdentityKeyRegisteredPayload, IdentityKeyRevokedPayload, IdentityRejectedPayload,
    IdentityVerificationSkippedPayload, IdentityVerifiedPayload, IntentCancelledPayload,
    IntentExpiredPayload, IntentReceivedPayload, KillSwitchPayload, OperatorRegisteredPayload,
    OperatorRoleChangedPayload, OperatorStatusChangedPayload, OptionalModuleOutcome,
    OriginalReplayCompletedPayload, PolicyChangedPayload, PolicyEvaluatedPayload, PolicyOutcome,
    ReconciliationFailedPayload, ReplayDetectedPayload, RequiredModuleOutcome,
    RiskEvaluatedPayload, RiskFindingEvidence, RiskRuleSetStoredPayload, RiskSeverity,
    ServiceDeliveredPayload, SettlementVerifiedPayload, SimulationCompletedPayload,
    SimulationOutcome, AUDIT_PAYLOAD_SCHEMA_VERSION,
};
