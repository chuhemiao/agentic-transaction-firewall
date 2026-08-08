use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use atf_core::{
    validate_lifecycle_transition, Amount, DecisionKind, DecisionObligation, ExecutionConstraints,
    IntentLifecycleState, ProfileBinding, RequiredApproval, SimulationReference, Timestamp,
    VersionedArtifactReference,
};

use crate::EventType;

pub const AUDIT_PAYLOAD_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum RequiredModuleOutcome<T> {
    Succeeded { result: T },
    Error { error_code: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum OptionalModuleOutcome<T> {
    Succeeded { result: T },
    Error { error_code: String },
    NotRun { reason_code: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyOutcome {
    Permit,
    Forbid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RiskSeverity {
    Info,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SimulationOutcome {
    Safe,
    Review,
    Unsafe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentReceivedPayload {
    pub organization_id: String,
    pub agent_id: String,
    pub idempotency_key: String,
    pub intent_hash: String,
    pub amount: Amount,
    pub resource_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityVerifiedPayload {
    pub organization_id: String,
    pub agent_id: String,
    pub key_id: String,
    pub envelope_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityVerificationSkippedPayload {
    pub organization_id: String,
    pub agent_id: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityRejectedPayload {
    pub organization_id: String,
    pub agent_id: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayDetectedPayload {
    pub organization_id: String,
    pub agent_id: String,
    pub key_id: String,
    pub nonce_hash: String,
    pub attempted_intent_id: String,
    pub attempted_intent_hash: String,
    pub bound_intent_id: String,
    pub bound_intent_hash: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextEnrichedPayload {
    pub context_hash: String,
    pub source_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvaluatedPayload {
    pub outcome: RequiredModuleOutcome<PolicyOutcome>,
    pub policy_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskFindingEvidence {
    pub code: String,
    pub severity: RiskSeverity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskEvaluatedPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_rule_set_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_rule_set_hash: Option<String>,
    pub outcome: OptionalModuleOutcome<Vec<RiskFindingEvidence>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SimulationCompletedPayload {
    pub outcome: OptionalModuleOutcome<SimulationOutcome>,
}

/// Exact Decision-v1 input bindings mirrored into `DecisionRecorded`. The
/// optional parent field preserves decoding of immutable pre-DS-025 events;
/// every current Store finalization requires and verifies this value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionBindingEvidence {
    pub decision_version: String,
    pub profile: ProfileBinding,
    pub policy: VersionedArtifactReference,
    pub risk: VersionedArtifactReference,
    pub evaluation_context_hash: String,
    pub context_snapshot_hash: String,
    pub simulation: SimulationReference,
    pub evaluation_time: Timestamp,
    pub expires_at: Timestamp,
    pub required_approvals: Vec<RequiredApproval>,
    pub obligations: Vec<DecisionObligation>,
    pub execution_constraints: ExecutionConstraints,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecordedPayload {
    pub organization_id: String,
    pub agent_id: String,
    pub intent_hash: String,
    pub evaluation_id: String,
    pub evaluation_hash: String,
    pub decision_id: String,
    pub decision_hash: String,
    pub decision: DecisionKind,
    pub action_category: String,
    pub resource_id: String,
    pub amount: Amount,
    pub destination: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<Box<DecisionBindingEvidence>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRequestedPayload {
    pub approval_id: String,
    pub decision_id: String,
    pub required_roles: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalResolvedPayload {
    pub approval_id: String,
    pub approver_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRejectedPayload {
    pub approval_id: String,
    pub approver_id: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionGrantPayload {
    pub grant_id: String,
    pub decision_id: String,
    pub execution_hash: String,
    pub expires_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionSubmittedPayload {
    pub execution_id: String,
    pub grant_id: String,
    pub adapter_id: String,
    pub request_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionConfirmedPayload {
    pub execution_id: String,
    pub result_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionFailedPayload {
    pub execution_id: String,
    pub error_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettlementVerifiedPayload {
    pub execution_id: String,
    pub settlement_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceDeliveredPayload {
    pub execution_id: String,
    pub delivery_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconciliationFailedPayload {
    pub execution_id: String,
    pub error_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetPayload {
    pub budget_id: String,
    pub reservation_id: String,
    pub amount: Amount,
    pub asset: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyChangedPayload {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub organization_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub environment: Option<String>,
    pub policy_bundle_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    #[serde(default)]
    pub previous_policy_bundle_hash: Option<String>,
    pub policy_bundle_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub change_kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle_version: Option<u64>,
    pub actor_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentPausedPayload {
    pub organization_id: String,
    pub agent_id: String,
    pub actor_id: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentRegisteredPayload {
    pub organization_id: String,
    pub agent_id: String,
    pub status: String,
    pub record_hash: String,
    pub lifecycle_version: u64,
    pub actor_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentStatusChangedPayload {
    pub organization_id: String,
    pub agent_id: String,
    pub previous_status: String,
    pub status: String,
    pub record_hash: String,
    pub lifecycle_version: u64,
    pub actor_id: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityKeyRegisteredPayload {
    pub organization_id: String,
    pub agent_id: String,
    pub key_id: String,
    pub algorithm: String,
    pub public_key_fingerprint: String,
    pub key_record_hash: String,
    pub activates_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub lifecycle_version: u64,
    pub actor_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityKeyRevokedPayload {
    pub organization_id: String,
    pub agent_id: String,
    pub key_id: String,
    pub public_key_fingerprint: String,
    pub key_record_hash: String,
    pub revoked_at: Timestamp,
    pub lifecycle_version: u64,
    pub actor_id: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRegisteredPayload {
    pub organization_id: String,
    pub operator_id: String,
    pub issuer_id: String,
    pub subject_fingerprint: String,
    pub principal_kind: String,
    pub status: String,
    pub record_hash: String,
    pub lifecycle_version: u64,
    pub actor_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorStatusChangedPayload {
    pub organization_id: String,
    pub operator_id: String,
    pub previous_status: String,
    pub status: String,
    pub record_hash: String,
    pub lifecycle_version: u64,
    pub actor_id: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRoleChangedPayload {
    pub organization_id: String,
    pub operator_id: String,
    pub role: String,
    pub binding_status: String,
    pub binding_hash: String,
    pub lifecycle_version: u64,
    pub actor_id: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskRuleSetStoredPayload {
    pub organization_id: String,
    pub environment: String,
    pub engine_version: String,
    pub rule_set_version: String,
    pub rule_set_hash: String,
    pub artifact_hash: String,
    pub actor_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginalReplayCompletedPayload {
    pub organization_id: String,
    pub replay_id: String,
    pub original_evaluation_id: String,
    pub original_decision_id: String,
    pub original_decision_hash: String,
    pub replayed_decision_hash: String,
    pub matched: bool,
    pub authoritative: bool,
    pub actor_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KillSwitchPayload {
    pub scope: String,
    pub actor_id: String,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentExpiredPayload {
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentCancelledPayload {
    pub actor_id: String,
    pub reason_code: String,
}

/// Every canonical PRD §16 event payload. The envelope stores this as a JSON
/// object so canonical hashing remains stable across the durable boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditPayload {
    IntentReceived(IntentReceivedPayload),
    IdentityVerified(IdentityVerifiedPayload),
    IdentityVerificationSkipped(IdentityVerificationSkippedPayload),
    IdentityRejected(IdentityRejectedPayload),
    ReplayDetected(ReplayDetectedPayload),
    ContextEnriched(ContextEnrichedPayload),
    PolicyEvaluated(PolicyEvaluatedPayload),
    RiskEvaluated(RiskEvaluatedPayload),
    SimulationCompleted(SimulationCompletedPayload),
    DecisionRecorded(DecisionRecordedPayload),
    ApprovalRequested(ApprovalRequestedPayload),
    ApprovalApproved(ApprovalResolvedPayload),
    ApprovalRejected(ApprovalRejectedPayload),
    ExecutionGrantIssued(ExecutionGrantPayload),
    ExecutionSubmitted(ExecutionSubmittedPayload),
    ExecutionConfirmed(ExecutionConfirmedPayload),
    ExecutionFailed(ExecutionFailedPayload),
    SettlementVerified(SettlementVerifiedPayload),
    ServiceDelivered(ServiceDeliveredPayload),
    ReconciliationFailed(ReconciliationFailedPayload),
    BudgetReserved(BudgetPayload),
    BudgetCommitted(BudgetPayload),
    BudgetReleased(BudgetPayload),
    PolicyChanged(PolicyChangedPayload),
    AgentPaused(AgentPausedPayload),
    AgentRegistered(AgentRegisteredPayload),
    AgentStatusChanged(AgentStatusChangedPayload),
    IdentityKeyRegistered(IdentityKeyRegisteredPayload),
    IdentityKeyRevoked(IdentityKeyRevokedPayload),
    OperatorRegistered(OperatorRegisteredPayload),
    OperatorStatusChanged(OperatorStatusChangedPayload),
    OperatorRoleGranted(OperatorRoleChangedPayload),
    OperatorRoleRevoked(OperatorRoleChangedPayload),
    RiskRuleSetStored(RiskRuleSetStoredPayload),
    OriginalReplayCompleted(OriginalReplayCompletedPayload),
    KillSwitchEnabled(KillSwitchPayload),
    KillSwitchDisabled(KillSwitchPayload),
    IntentExpired(IntentExpiredPayload),
    IntentCancelled(IntentCancelledPayload),
}

impl AuditPayload {
    pub const fn event_type(&self) -> EventType {
        match self {
            Self::IntentReceived(_) => EventType::IntentReceived,
            Self::IdentityVerified(_) => EventType::IdentityVerified,
            Self::IdentityVerificationSkipped(_) => EventType::IdentityVerificationSkipped,
            Self::IdentityRejected(_) => EventType::IdentityRejected,
            Self::ReplayDetected(_) => EventType::ReplayDetected,
            Self::ContextEnriched(_) => EventType::ContextEnriched,
            Self::PolicyEvaluated(_) => EventType::PolicyEvaluated,
            Self::RiskEvaluated(_) => EventType::RiskEvaluated,
            Self::SimulationCompleted(_) => EventType::SimulationCompleted,
            Self::DecisionRecorded(_) => EventType::DecisionRecorded,
            Self::ApprovalRequested(_) => EventType::ApprovalRequested,
            Self::ApprovalApproved(_) => EventType::ApprovalApproved,
            Self::ApprovalRejected(_) => EventType::ApprovalRejected,
            Self::ExecutionGrantIssued(_) => EventType::ExecutionGrantIssued,
            Self::ExecutionSubmitted(_) => EventType::ExecutionSubmitted,
            Self::ExecutionConfirmed(_) => EventType::ExecutionConfirmed,
            Self::ExecutionFailed(_) => EventType::ExecutionFailed,
            Self::SettlementVerified(_) => EventType::SettlementVerified,
            Self::ServiceDelivered(_) => EventType::ServiceDelivered,
            Self::ReconciliationFailed(_) => EventType::ReconciliationFailed,
            Self::BudgetReserved(_) => EventType::BudgetReserved,
            Self::BudgetCommitted(_) => EventType::BudgetCommitted,
            Self::BudgetReleased(_) => EventType::BudgetReleased,
            Self::PolicyChanged(_) => EventType::PolicyChanged,
            Self::AgentPaused(_) => EventType::AgentPaused,
            Self::AgentRegistered(_) => EventType::AgentRegistered,
            Self::AgentStatusChanged(_) => EventType::AgentStatusChanged,
            Self::IdentityKeyRegistered(_) => EventType::IdentityKeyRegistered,
            Self::IdentityKeyRevoked(_) => EventType::IdentityKeyRevoked,
            Self::OperatorRegistered(_) => EventType::OperatorRegistered,
            Self::OperatorStatusChanged(_) => EventType::OperatorStatusChanged,
            Self::OperatorRoleGranted(_) => EventType::OperatorRoleGranted,
            Self::OperatorRoleRevoked(_) => EventType::OperatorRoleRevoked,
            Self::RiskRuleSetStored(_) => EventType::RiskRuleSetStored,
            Self::OriginalReplayCompleted(_) => EventType::OriginalReplayCompleted,
            Self::KillSwitchEnabled(_) => EventType::KillSwitchEnabled,
            Self::KillSwitchDisabled(_) => EventType::KillSwitchDisabled,
            Self::IntentExpired(_) => EventType::IntentExpired,
            Self::IntentCancelled(_) => EventType::IntentCancelled,
        }
    }

    pub fn to_data(&self) -> Value {
        let fields = match self {
            Self::IntentReceived(value) => encode(value),
            Self::IdentityVerified(value) => encode(value),
            Self::IdentityVerificationSkipped(value) => encode(value),
            Self::IdentityRejected(value) => encode(value),
            Self::ReplayDetected(value) => encode(value),
            Self::ContextEnriched(value) => encode(value),
            Self::PolicyEvaluated(value) => encode(value),
            Self::RiskEvaluated(value) => encode(value),
            Self::SimulationCompleted(value) => encode(value),
            Self::DecisionRecorded(value) => encode(value),
            Self::ApprovalRequested(value) => encode(value),
            Self::ApprovalApproved(value) => encode(value),
            Self::ApprovalRejected(value) => encode(value),
            Self::ExecutionGrantIssued(value) => encode(value),
            Self::ExecutionSubmitted(value) => encode(value),
            Self::ExecutionConfirmed(value) => encode(value),
            Self::ExecutionFailed(value) => encode(value),
            Self::SettlementVerified(value) => encode(value),
            Self::ServiceDelivered(value) => encode(value),
            Self::ReconciliationFailed(value) => encode(value),
            Self::BudgetReserved(value)
            | Self::BudgetCommitted(value)
            | Self::BudgetReleased(value) => encode(value),
            Self::PolicyChanged(value) => encode(value),
            Self::AgentPaused(value) => encode(value),
            Self::AgentRegistered(value) => encode(value),
            Self::AgentStatusChanged(value) => encode(value),
            Self::IdentityKeyRegistered(value) => encode(value),
            Self::IdentityKeyRevoked(value) => encode(value),
            Self::OperatorRegistered(value) => encode(value),
            Self::OperatorStatusChanged(value) => encode(value),
            Self::OperatorRoleGranted(value) | Self::OperatorRoleRevoked(value) => encode(value),
            Self::RiskRuleSetStored(value) => encode(value),
            Self::OriginalReplayCompleted(value) => encode(value),
            Self::KillSwitchEnabled(value) | Self::KillSwitchDisabled(value) => encode(value),
            Self::IntentExpired(value) => encode(value),
            Self::IntentCancelled(value) => encode(value),
        };
        with_schema_version(fields)
    }

    pub fn from_data(event_type: EventType, data: &Value) -> Result<Self, AuditPayloadError> {
        let fields = without_schema_version(event_type, data)?;
        let payload = match event_type {
            EventType::IntentReceived => Self::IntentReceived(decode(event_type, fields)?),
            EventType::IdentityVerified => Self::IdentityVerified(decode(event_type, fields)?),
            EventType::IdentityVerificationSkipped => {
                Self::IdentityVerificationSkipped(decode(event_type, fields)?)
            }
            EventType::IdentityRejected => Self::IdentityRejected(decode(event_type, fields)?),
            EventType::ReplayDetected => Self::ReplayDetected(decode(event_type, fields)?),
            EventType::ContextEnriched => Self::ContextEnriched(decode(event_type, fields)?),
            EventType::PolicyEvaluated => Self::PolicyEvaluated(decode(event_type, fields)?),
            EventType::RiskEvaluated => Self::RiskEvaluated(decode(event_type, fields)?),
            EventType::SimulationCompleted => {
                Self::SimulationCompleted(decode(event_type, fields)?)
            }
            EventType::DecisionRecorded => Self::DecisionRecorded(decode(event_type, fields)?),
            EventType::ApprovalRequested => Self::ApprovalRequested(decode(event_type, fields)?),
            EventType::ApprovalApproved => Self::ApprovalApproved(decode(event_type, fields)?),
            EventType::ApprovalRejected => Self::ApprovalRejected(decode(event_type, fields)?),
            EventType::ExecutionGrantIssued => {
                Self::ExecutionGrantIssued(decode(event_type, fields)?)
            }
            EventType::ExecutionSubmitted => Self::ExecutionSubmitted(decode(event_type, fields)?),
            EventType::ExecutionConfirmed => Self::ExecutionConfirmed(decode(event_type, fields)?),
            EventType::ExecutionFailed => Self::ExecutionFailed(decode(event_type, fields)?),
            EventType::SettlementVerified => Self::SettlementVerified(decode(event_type, fields)?),
            EventType::ServiceDelivered => Self::ServiceDelivered(decode(event_type, fields)?),
            EventType::ReconciliationFailed => {
                Self::ReconciliationFailed(decode(event_type, fields)?)
            }
            EventType::BudgetReserved => Self::BudgetReserved(decode(event_type, fields)?),
            EventType::BudgetCommitted => Self::BudgetCommitted(decode(event_type, fields)?),
            EventType::BudgetReleased => Self::BudgetReleased(decode(event_type, fields)?),
            EventType::PolicyChanged => Self::PolicyChanged(decode(event_type, fields)?),
            EventType::AgentPaused => Self::AgentPaused(decode(event_type, fields)?),
            EventType::AgentRegistered => Self::AgentRegistered(decode(event_type, fields)?),
            EventType::AgentStatusChanged => Self::AgentStatusChanged(decode(event_type, fields)?),
            EventType::IdentityKeyRegistered => {
                Self::IdentityKeyRegistered(decode(event_type, fields)?)
            }
            EventType::IdentityKeyRevoked => Self::IdentityKeyRevoked(decode(event_type, fields)?),
            EventType::OperatorRegistered => Self::OperatorRegistered(decode(event_type, fields)?),
            EventType::OperatorStatusChanged => {
                Self::OperatorStatusChanged(decode(event_type, fields)?)
            }
            EventType::OperatorRoleGranted => {
                Self::OperatorRoleGranted(decode(event_type, fields)?)
            }
            EventType::OperatorRoleRevoked => {
                Self::OperatorRoleRevoked(decode(event_type, fields)?)
            }
            EventType::RiskRuleSetStored => Self::RiskRuleSetStored(decode(event_type, fields)?),
            EventType::OriginalReplayCompleted => {
                Self::OriginalReplayCompleted(decode(event_type, fields)?)
            }
            EventType::KillSwitchEnabled => Self::KillSwitchEnabled(decode(event_type, fields)?),
            EventType::KillSwitchDisabled => Self::KillSwitchDisabled(decode(event_type, fields)?),
            EventType::IntentExpired => Self::IntentExpired(decode(event_type, fields)?),
            EventType::IntentCancelled => Self::IntentCancelled(decode(event_type, fields)?),
            EventType::ApprovalGranted
            | EventType::ExecutionRequested
            | EventType::KillSwitchTriggered => {
                return Err(AuditPayloadError::UnsupportedLegacyEvent { event_type });
            }
        };
        payload.validate()?;
        Ok(payload)
    }

    pub fn validate(&self) -> Result<(), AuditPayloadError> {
        let event_type = self.event_type();
        match self {
            Self::IntentReceived(value) => {
                strings(
                    event_type,
                    &[
                        ("organization_id", &value.organization_id),
                        ("agent_id", &value.agent_id),
                        ("idempotency_key", &value.idempotency_key),
                        ("resource_id", &value.resource_id),
                    ],
                )?;
                sha256(event_type, "intent_hash", &value.intent_hash)?;
                nonnegative_amount(event_type, "amount", value.amount)?;
            }
            Self::IdentityVerified(value) => {
                strings(
                    event_type,
                    &[
                        ("organization_id", &value.organization_id),
                        ("agent_id", &value.agent_id),
                        ("key_id", &value.key_id),
                    ],
                )?;
                sha256(event_type, "envelope_hash", &value.envelope_hash)?;
            }
            Self::IdentityVerificationSkipped(value) => strings(
                event_type,
                &[
                    ("organization_id", &value.organization_id),
                    ("agent_id", &value.agent_id),
                    ("reason_code", &value.reason_code),
                ],
            )?,
            Self::IdentityRejected(value) => strings(
                event_type,
                &[
                    ("organization_id", &value.organization_id),
                    ("agent_id", &value.agent_id),
                    ("reason_code", &value.reason_code),
                ],
            )?,
            Self::ReplayDetected(value) => {
                strings(
                    event_type,
                    &[
                        ("organization_id", &value.organization_id),
                        ("agent_id", &value.agent_id),
                        ("key_id", &value.key_id),
                        ("attempted_intent_id", &value.attempted_intent_id),
                        ("bound_intent_id", &value.bound_intent_id),
                        ("reason_code", &value.reason_code),
                    ],
                )?;
                sha256(event_type, "nonce_hash", &value.nonce_hash)?;
                sha256(
                    event_type,
                    "attempted_intent_hash",
                    &value.attempted_intent_hash,
                )?;
                sha256(event_type, "bound_intent_hash", &value.bound_intent_hash)?;
            }
            Self::ContextEnriched(value) => {
                sha256(event_type, "context_hash", &value.context_hash)?;
                string_list(event_type, "source_ids", &value.source_ids, true)?;
            }
            Self::PolicyEvaluated(value) => {
                validate_required_outcome(event_type, &value.outcome)?;
                string_list(event_type, "policy_ids", &value.policy_ids, false)?;
            }
            Self::RiskEvaluated(value) => {
                validate_optional_outcome(event_type, &value.outcome)?;
                match (&value.risk_rule_set_version, &value.risk_rule_set_hash) {
                    (Some(version), Some(hash)) => {
                        nonempty(event_type, "risk_rule_set_version", version)?;
                        sha256(event_type, "risk_rule_set_hash", hash)?;
                    }
                    (None, None) => {}
                    _ => {
                        return Err(invalid(
                            event_type,
                            "Risk Rule Set version and hash must appear together",
                        ));
                    }
                }
                if let OptionalModuleOutcome::Succeeded { result } = &value.outcome {
                    for finding in result {
                        nonempty(event_type, "finding.code", &finding.code)?;
                    }
                }
            }
            Self::SimulationCompleted(value) => {
                validate_optional_outcome(event_type, &value.outcome)?;
            }
            Self::DecisionRecorded(value) => {
                strings(
                    event_type,
                    &[
                        ("organization_id", &value.organization_id),
                        ("agent_id", &value.agent_id),
                        ("evaluation_id", &value.evaluation_id),
                        ("decision_id", &value.decision_id),
                        ("action_category", &value.action_category),
                        ("resource_id", &value.resource_id),
                    ],
                )?;
                sha256(event_type, "intent_hash", &value.intent_hash)?;
                sha256(event_type, "evaluation_hash", &value.evaluation_hash)?;
                sha256(event_type, "decision_hash", &value.decision_hash)?;
                nonnegative_amount(event_type, "amount", value.amount)?;
                if let Some(destination) = &value.destination {
                    nonempty(event_type, "destination", destination)?;
                }
                if let Some(binding) = &value.binding {
                    validate_decision_binding(event_type, binding)?;
                }
            }
            Self::ApprovalRequested(value) => {
                strings(
                    event_type,
                    &[
                        ("approval_id", &value.approval_id),
                        ("decision_id", &value.decision_id),
                    ],
                )?;
                string_list(event_type, "required_roles", &value.required_roles, true)?;
            }
            Self::ApprovalApproved(value) => strings(
                event_type,
                &[
                    ("approval_id", &value.approval_id),
                    ("approver_id", &value.approver_id),
                ],
            )?,
            Self::ApprovalRejected(value) => strings(
                event_type,
                &[
                    ("approval_id", &value.approval_id),
                    ("approver_id", &value.approver_id),
                    ("reason_code", &value.reason_code),
                ],
            )?,
            Self::ExecutionGrantIssued(value) => {
                strings(
                    event_type,
                    &[
                        ("grant_id", &value.grant_id),
                        ("decision_id", &value.decision_id),
                    ],
                )?;
                sha256(event_type, "execution_hash", &value.execution_hash)?;
            }
            Self::ExecutionSubmitted(value) => {
                strings(
                    event_type,
                    &[
                        ("execution_id", &value.execution_id),
                        ("grant_id", &value.grant_id),
                        ("adapter_id", &value.adapter_id),
                    ],
                )?;
                sha256(event_type, "request_hash", &value.request_hash)?;
            }
            Self::ExecutionConfirmed(value) => {
                nonempty(event_type, "execution_id", &value.execution_id)?;
                sha256(event_type, "result_hash", &value.result_hash)?;
            }
            Self::ExecutionFailed(value) => strings(
                event_type,
                &[
                    ("execution_id", &value.execution_id),
                    ("error_code", &value.error_code),
                ],
            )?,
            Self::SettlementVerified(value) => {
                nonempty(event_type, "execution_id", &value.execution_id)?;
                sha256(event_type, "settlement_hash", &value.settlement_hash)?;
            }
            Self::ServiceDelivered(value) => {
                nonempty(event_type, "execution_id", &value.execution_id)?;
                sha256(event_type, "delivery_hash", &value.delivery_hash)?;
            }
            Self::ReconciliationFailed(value) => strings(
                event_type,
                &[
                    ("execution_id", &value.execution_id),
                    ("error_code", &value.error_code),
                ],
            )?,
            Self::BudgetReserved(value)
            | Self::BudgetCommitted(value)
            | Self::BudgetReleased(value) => {
                strings(
                    event_type,
                    &[
                        ("budget_id", &value.budget_id),
                        ("reservation_id", &value.reservation_id),
                        ("asset", &value.asset),
                    ],
                )?;
                nonnegative_amount(event_type, "amount", value.amount)?;
            }
            Self::PolicyChanged(value) => {
                strings(
                    event_type,
                    &[
                        ("policy_bundle_id", &value.policy_bundle_id),
                        ("actor_id", &value.actor_id),
                    ],
                )?;
                sha256(event_type, "policy_bundle_hash", &value.policy_bundle_hash)?;
                if let Some(previous) = &value.previous_policy_bundle_hash {
                    sha256(event_type, "previous_policy_bundle_hash", previous)?;
                }
                let durable_fields = [
                    value.organization_id.is_some(),
                    value.environment.is_some(),
                    value.policy_version.is_some(),
                    value.change_kind.is_some(),
                ];
                if durable_fields.iter().any(|present| *present)
                    || value.previous_policy_bundle_hash.is_some()
                    || value.lifecycle_version.is_some()
                {
                    if durable_fields.iter().any(|present| !*present) {
                        return Err(invalid(
                            event_type,
                            "durable PolicyChanged scope/version/kind fields must be complete",
                        ));
                    }
                    strings(
                        event_type,
                        &[
                            (
                                "organization_id",
                                value.organization_id.as_deref().expect("checked above"),
                            ),
                            (
                                "environment",
                                value.environment.as_deref().expect("checked above"),
                            ),
                            (
                                "policy_version",
                                value.policy_version.as_deref().expect("checked above"),
                            ),
                        ],
                    )?;
                    let change_kind = value.change_kind.as_deref().expect("checked above");
                    if !matches!(change_kind, "INSTALLED" | "ACTIVATED" | "ROLLED_BACK") {
                        return Err(invalid(event_type, "change_kind is not supported"));
                    }
                    match change_kind {
                        "INSTALLED" if value.lifecycle_version.is_some() => {
                            return Err(invalid(
                                event_type,
                                "installed Bundle must not have a pointer lifecycle version",
                            ));
                        }
                        "ACTIVATED" => {
                            positive_optional_version(event_type, value.lifecycle_version)?;
                        }
                        "ROLLED_BACK" => {
                            positive_optional_version(event_type, value.lifecycle_version)?;
                            if value.previous_policy_bundle_hash.is_none() {
                                return Err(invalid(
                                    event_type,
                                    "rollback must identify the previous active Bundle hash",
                                ));
                            }
                        }
                        _ => {}
                    }
                }
            }
            Self::AgentPaused(value) => strings(
                event_type,
                &[
                    ("organization_id", &value.organization_id),
                    ("agent_id", &value.agent_id),
                    ("actor_id", &value.actor_id),
                    ("reason_code", &value.reason_code),
                ],
            )?,
            Self::AgentRegistered(value) => {
                strings(
                    event_type,
                    &[
                        ("organization_id", &value.organization_id),
                        ("agent_id", &value.agent_id),
                        ("status", &value.status),
                        ("actor_id", &value.actor_id),
                    ],
                )?;
                agent_status(event_type, "status", &value.status)?;
                sha256(event_type, "record_hash", &value.record_hash)?;
                positive_version(event_type, value.lifecycle_version)?;
            }
            Self::AgentStatusChanged(value) => {
                strings(
                    event_type,
                    &[
                        ("organization_id", &value.organization_id),
                        ("agent_id", &value.agent_id),
                        ("previous_status", &value.previous_status),
                        ("status", &value.status),
                        ("actor_id", &value.actor_id),
                        ("reason_code", &value.reason_code),
                    ],
                )?;
                agent_status(event_type, "previous_status", &value.previous_status)?;
                agent_status(event_type, "status", &value.status)?;
                sha256(event_type, "record_hash", &value.record_hash)?;
                positive_version(event_type, value.lifecycle_version)?;
            }
            Self::IdentityKeyRegistered(value) => {
                strings(
                    event_type,
                    &[
                        ("organization_id", &value.organization_id),
                        ("agent_id", &value.agent_id),
                        ("key_id", &value.key_id),
                        ("algorithm", &value.algorithm),
                        ("actor_id", &value.actor_id),
                    ],
                )?;
                if value.algorithm != "ED25519" {
                    return Err(invalid(event_type, "algorithm must be ED25519"));
                }
                sha256(
                    event_type,
                    "public_key_fingerprint",
                    &value.public_key_fingerprint,
                )?;
                sha256(event_type, "key_record_hash", &value.key_record_hash)?;
                if value
                    .expires_at
                    .is_some_and(|expires_at| expires_at <= value.activates_at)
                {
                    return Err(invalid(event_type, "expires_at must follow activates_at"));
                }
                positive_version(event_type, value.lifecycle_version)?;
            }
            Self::IdentityKeyRevoked(value) => {
                strings(
                    event_type,
                    &[
                        ("organization_id", &value.organization_id),
                        ("agent_id", &value.agent_id),
                        ("key_id", &value.key_id),
                        ("actor_id", &value.actor_id),
                        ("reason_code", &value.reason_code),
                    ],
                )?;
                sha256(
                    event_type,
                    "public_key_fingerprint",
                    &value.public_key_fingerprint,
                )?;
                sha256(event_type, "key_record_hash", &value.key_record_hash)?;
                positive_version(event_type, value.lifecycle_version)?;
            }
            Self::OperatorRegistered(value) => {
                strings(
                    event_type,
                    &[
                        ("organization_id", &value.organization_id),
                        ("operator_id", &value.operator_id),
                        ("issuer_id", &value.issuer_id),
                        ("principal_kind", &value.principal_kind),
                        ("status", &value.status),
                        ("actor_id", &value.actor_id),
                    ],
                )?;
                sha256(
                    event_type,
                    "subject_fingerprint",
                    &value.subject_fingerprint,
                )?;
                sha256(event_type, "record_hash", &value.record_hash)?;
                operator_kind(event_type, &value.principal_kind)?;
                operator_status(event_type, "status", &value.status)?;
                positive_version(event_type, value.lifecycle_version)?;
            }
            Self::OperatorStatusChanged(value) => {
                strings(
                    event_type,
                    &[
                        ("organization_id", &value.organization_id),
                        ("operator_id", &value.operator_id),
                        ("previous_status", &value.previous_status),
                        ("status", &value.status),
                        ("actor_id", &value.actor_id),
                        ("reason_code", &value.reason_code),
                    ],
                )?;
                operator_status(event_type, "previous_status", &value.previous_status)?;
                operator_status(event_type, "status", &value.status)?;
                sha256(event_type, "record_hash", &value.record_hash)?;
                positive_version(event_type, value.lifecycle_version)?;
            }
            Self::OperatorRoleGranted(value) | Self::OperatorRoleRevoked(value) => {
                strings(
                    event_type,
                    &[
                        ("organization_id", &value.organization_id),
                        ("operator_id", &value.operator_id),
                        ("role", &value.role),
                        ("binding_status", &value.binding_status),
                        ("actor_id", &value.actor_id),
                        ("reason_code", &value.reason_code),
                    ],
                )?;
                operator_role(event_type, &value.role)?;
                role_binding_status(event_type, &value.binding_status)?;
                let expected_status = if matches!(self, Self::OperatorRoleGranted(_)) {
                    "ACTIVE"
                } else {
                    "REVOKED"
                };
                if value.binding_status != expected_status {
                    return Err(invalid(
                        event_type,
                        format!("binding_status must be {expected_status}"),
                    ));
                }
                sha256(event_type, "binding_hash", &value.binding_hash)?;
                positive_version(event_type, value.lifecycle_version)?;
            }
            Self::RiskRuleSetStored(value) => {
                strings(
                    event_type,
                    &[
                        ("organization_id", &value.organization_id),
                        ("environment", &value.environment),
                        ("engine_version", &value.engine_version),
                        ("rule_set_version", &value.rule_set_version),
                        ("actor_id", &value.actor_id),
                    ],
                )?;
                sha256(event_type, "rule_set_hash", &value.rule_set_hash)?;
                sha256(event_type, "artifact_hash", &value.artifact_hash)?;
            }
            Self::OriginalReplayCompleted(value) => {
                strings(
                    event_type,
                    &[
                        ("organization_id", &value.organization_id),
                        ("replay_id", &value.replay_id),
                        ("original_evaluation_id", &value.original_evaluation_id),
                        ("original_decision_id", &value.original_decision_id),
                        ("actor_id", &value.actor_id),
                    ],
                )?;
                sha256(
                    event_type,
                    "original_decision_hash",
                    &value.original_decision_hash,
                )?;
                sha256(
                    event_type,
                    "replayed_decision_hash",
                    &value.replayed_decision_hash,
                )?;
                if !value.matched
                    || value.authoritative
                    || value.original_decision_hash != value.replayed_decision_hash
                {
                    return Err(invalid(
                        event_type,
                        "Original Replay evidence must have equal hashes and be matched and non-authoritative",
                    ));
                }
            }
            Self::KillSwitchEnabled(value) | Self::KillSwitchDisabled(value) => strings(
                event_type,
                &[
                    ("scope", &value.scope),
                    ("actor_id", &value.actor_id),
                    ("reason_code", &value.reason_code),
                ],
            )?,
            Self::IntentExpired(value) => {
                nonempty(event_type, "reason_code", &value.reason_code)?;
            }
            Self::IntentCancelled(value) => strings(
                event_type,
                &[
                    ("actor_id", &value.actor_id),
                    ("reason_code", &value.reason_code),
                ],
            )?,
        }
        Ok(())
    }

    pub const fn requires_intent_id(&self) -> bool {
        !matches!(
            self,
            Self::PolicyChanged(_)
                | Self::AgentPaused(_)
                | Self::AgentRegistered(_)
                | Self::AgentStatusChanged(_)
                | Self::IdentityKeyRegistered(_)
                | Self::IdentityKeyRevoked(_)
                | Self::OperatorRegistered(_)
                | Self::OperatorStatusChanged(_)
                | Self::OperatorRoleGranted(_)
                | Self::OperatorRoleRevoked(_)
                | Self::RiskRuleSetStored(_)
                | Self::ReplayDetected(_)
                | Self::KillSwitchEnabled(_)
                | Self::KillSwitchDisabled(_)
        )
    }

    pub fn validate_intent_scope(&self, intent_id: Option<&str>) -> Result<(), AuditPayloadError> {
        let event_type = self.event_type();
        if matches!(self, Self::IdentityVerified(_) | Self::IdentityRejected(_)) {
            return intent_id
                .map(|value| nonempty(event_type, "intent_id", value))
                .unwrap_or(Ok(()));
        }
        match (self.requires_intent_id(), intent_id) {
            (true, Some(value)) => nonempty(event_type, "intent_id", value),
            (true, None) => Err(invalid(event_type, "intent_id is required")),
            (false, None) => Ok(()),
            (false, Some(_)) => Err(invalid(
                event_type,
                "intent_id is forbidden for organization/operator events",
            )),
        }
    }

    /// Apply this event's declared lifecycle effect without persistence.
    /// DS-007 will call the same function inside its state transaction.
    pub fn next_state(
        &self,
        current: Option<IntentLifecycleState>,
    ) -> Result<Option<IntentLifecycleState>, AuditPayloadError> {
        use IntentLifecycleState as State;

        let event_type = self.event_type();
        let target = match self {
            Self::IntentReceived(_) => {
                return if current.is_none() {
                    Ok(Some(State::Received))
                } else {
                    Err(invalid(
                        event_type,
                        "IntentReceived cannot initialize an existing lifecycle",
                    ))
                };
            }
            Self::IdentityVerified(_) => State::IdentityVerified,
            Self::IdentityVerificationSkipped(_) => State::IdentityUnverified,
            Self::IdentityRejected(_) => State::IdentityRejected,
            Self::PolicyEvaluated(_) => State::PolicyEvaluated,
            Self::RiskEvaluated(_) => State::RiskEvaluated,
            Self::SimulationCompleted(_) => State::SimulationCompleted,
            Self::DecisionRecorded(value) => match value.decision {
                DecisionKind::Permit => State::DecidedPermit,
                DecisionKind::Review => State::DecidedReview,
                DecisionKind::Deny => State::DecidedDeny,
                DecisionKind::Error => State::DecidedError,
            },
            Self::ApprovalRequested(_) => State::ApprovalPending,
            Self::ApprovalApproved(_) => State::Approved,
            Self::ApprovalRejected(_) => State::Rejected,
            Self::ExecutionGrantIssued(_) => State::ExecutionAuthorized,
            Self::ExecutionSubmitted(_) => State::ExecutionSubmitted,
            Self::ExecutionConfirmed(_) => State::ExecutionConfirmed,
            Self::ExecutionFailed(_) => State::ExecutionFailed,
            Self::SettlementVerified(_) => State::SettlementVerified,
            Self::ReconciliationFailed(_) => State::ReconciliationFailed,
            Self::IntentExpired(_) => State::Expired,
            Self::IntentCancelled(_) => State::Cancelled,
            Self::ContextEnriched(_)
            | Self::ServiceDelivered(_)
            | Self::BudgetReserved(_)
            | Self::BudgetCommitted(_)
            | Self::BudgetReleased(_)
            | Self::PolicyChanged(_)
            | Self::AgentPaused(_)
            | Self::AgentRegistered(_)
            | Self::AgentStatusChanged(_)
            | Self::IdentityKeyRegistered(_)
            | Self::IdentityKeyRevoked(_)
            | Self::OperatorRegistered(_)
            | Self::OperatorStatusChanged(_)
            | Self::OperatorRoleGranted(_)
            | Self::OperatorRoleRevoked(_)
            | Self::RiskRuleSetStored(_)
            | Self::OriginalReplayCompleted(_)
            | Self::ReplayDetected(_)
            | Self::KillSwitchEnabled(_)
            | Self::KillSwitchDisabled(_) => return Ok(current),
        };

        let from = current.ok_or_else(|| invalid(event_type, "lifecycle is not initialized"))?;
        validate_lifecycle_transition(from, target)
            .map_err(|error| invalid(event_type, error.to_string()))?;
        Ok(Some(target))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AuditPayloadError {
    #[error("legacy Audit event {event_type:?} has no typed payload contract")]
    UnsupportedLegacyEvent { event_type: EventType },

    #[error("invalid {event_type:?} Audit payload: {reason}")]
    Invalid {
        event_type: EventType,
        reason: String,
    },
}

fn encode<T: Serialize>(value: &T) -> Value {
    serde_json::to_value(value).expect("typed Audit payload always serializes")
}

fn with_schema_version(value: Value) -> Value {
    let mut object = value
        .as_object()
        .cloned()
        .expect("typed Audit payloads serialize as objects");
    object.insert(
        "schema_version".into(),
        Value::from(AUDIT_PAYLOAD_SCHEMA_VERSION),
    );
    Value::Object(object)
}

fn without_schema_version(
    event_type: EventType,
    value: &Value,
) -> Result<Value, AuditPayloadError> {
    let mut object: Map<String, Value> = value
        .as_object()
        .cloned()
        .ok_or_else(|| invalid(event_type, "data must be an object"))?;
    let version = object
        .remove("schema_version")
        .and_then(|value| value.as_u64())
        .ok_or_else(|| invalid(event_type, "schema_version must be an integer"))?;
    if version != u64::from(AUDIT_PAYLOAD_SCHEMA_VERSION) {
        return Err(invalid(
            event_type,
            format!("unsupported schema_version {version}"),
        ));
    }
    Ok(Value::Object(object))
}

fn decode<T: DeserializeOwned>(
    event_type: EventType,
    value: Value,
) -> Result<T, AuditPayloadError> {
    serde_json::from_value(value).map_err(|error| invalid(event_type, error.to_string()))
}

fn validate_required_outcome<T>(
    event_type: EventType,
    outcome: &RequiredModuleOutcome<T>,
) -> Result<(), AuditPayloadError> {
    if let RequiredModuleOutcome::Error { error_code } = outcome {
        nonempty(event_type, "outcome.error_code", error_code)?;
    }
    Ok(())
}

fn validate_optional_outcome<T>(
    event_type: EventType,
    outcome: &OptionalModuleOutcome<T>,
) -> Result<(), AuditPayloadError> {
    match outcome {
        OptionalModuleOutcome::Succeeded { .. } => Ok(()),
        OptionalModuleOutcome::Error { error_code } => {
            nonempty(event_type, "outcome.error_code", error_code)
        }
        OptionalModuleOutcome::NotRun { reason_code } => {
            nonempty(event_type, "outcome.reason_code", reason_code)
        }
    }
}

fn validate_decision_binding(
    event_type: EventType,
    binding: &DecisionBindingEvidence,
) -> Result<(), AuditPayloadError> {
    strings(
        event_type,
        &[
            ("binding.decision_version", &binding.decision_version),
            ("binding.profile.id", &binding.profile.id),
            ("binding.profile.version", &binding.profile.version),
        ],
    )?;
    validate_artifact_reference(event_type, "binding.policy", &binding.policy)?;
    validate_artifact_reference(event_type, "binding.risk", &binding.risk)?;
    sha256(
        event_type,
        "binding.evaluation_context_hash",
        &binding.evaluation_context_hash,
    )?;
    sha256(
        event_type,
        "binding.context_snapshot_hash",
        &binding.context_snapshot_hash,
    )?;
    nonempty(
        event_type,
        "binding.simulation.reason_code",
        binding.simulation.reason_code(),
    )?;
    for value in [binding.evaluation_time, binding.expires_at] {
        if value.as_datetime().timestamp_subsec_nanos() % 1_000_000 != 0 {
            return Err(invalid(
                event_type,
                "Decision binding timestamps must use millisecond precision",
            ));
        }
    }
    for approval in &binding.required_approvals {
        nonempty(
            event_type,
            "binding.required_approvals.role",
            &approval.role,
        )?;
        if approval.count == 0 {
            return Err(invalid(
                event_type,
                "binding.required_approvals.count must be positive",
            ));
        }
    }
    for obligation in &binding.obligations {
        nonempty(
            event_type,
            "binding.obligations.type",
            &obligation.obligation_type,
        )?;
    }
    let constraints = &binding.execution_constraints;
    strings(
        event_type,
        &[
            (
                "binding.execution_constraints.action_category",
                &constraints.action_category,
            ),
            (
                "binding.execution_constraints.action_operation",
                &constraints.action_operation,
            ),
            (
                "binding.execution_constraints.resource_id",
                &constraints.resource_id,
            ),
            (
                "binding.execution_constraints.resource_protocol",
                &constraints.resource_protocol,
            ),
            (
                "binding.execution_constraints.network",
                &constraints.network,
            ),
            ("binding.execution_constraints.asset", &constraints.asset),
        ],
    )?;
    nonnegative_amount(
        event_type,
        "binding.execution_constraints.max_amount",
        constraints.max_amount,
    )?;
    if let Some(destination) = &constraints.destination {
        nonempty(
            event_type,
            "binding.execution_constraints.destination",
            destination,
        )?;
    }
    if let Some(adapter_id) = &constraints.adapter_id {
        nonempty(
            event_type,
            "binding.execution_constraints.adapter_id",
            adapter_id,
        )?;
    }
    Ok(())
}

fn validate_artifact_reference(
    event_type: EventType,
    field: &'static str,
    reference: &VersionedArtifactReference,
) -> Result<(), AuditPayloadError> {
    if let Some((artifact_id, version, hash)) = reference.available_parts() {
        nonempty(event_type, field, artifact_id)?;
        nonempty(event_type, field, version)?;
        sha256(event_type, field, hash)
    } else if let Some(reason_code) = reference.unavailable_reason() {
        nonempty(event_type, field, reason_code)
    } else {
        Err(invalid(event_type, format!("{field} is invalid")))
    }
}

fn strings(
    event_type: EventType,
    values: &[(&'static str, &str)],
) -> Result<(), AuditPayloadError> {
    for (field, value) in values {
        nonempty(event_type, field, value)?;
    }
    Ok(())
}

fn string_list(
    event_type: EventType,
    field: &'static str,
    values: &[String],
    require_item: bool,
) -> Result<(), AuditPayloadError> {
    if require_item && values.is_empty() {
        return Err(invalid(event_type, format!("{field} must not be empty")));
    }
    for value in values {
        nonempty(event_type, field, value)?;
    }
    Ok(())
}

fn nonempty(
    event_type: EventType,
    field: &'static str,
    value: &str,
) -> Result<(), AuditPayloadError> {
    if value.is_empty() || value.trim() != value || value.len() > 512 {
        Err(invalid(
            event_type,
            format!("{field} must be 1..512 trimmed bytes"),
        ))
    } else {
        Ok(())
    }
}

fn sha256(
    event_type: EventType,
    field: &'static str,
    value: &str,
) -> Result<(), AuditPayloadError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(invalid(
            event_type,
            format!("{field} must be 64 lowercase SHA-256 hex characters"),
        ))
    }
}

fn agent_status(
    event_type: EventType,
    field: &'static str,
    value: &str,
) -> Result<(), AuditPayloadError> {
    if matches!(
        value,
        "ACTIVE" | "SHADOW_ONLY" | "PAUSED" | "REVOKED" | "EXPIRED"
    ) {
        Ok(())
    } else {
        Err(invalid(
            event_type,
            format!("{field} is not an Agent status"),
        ))
    }
}

fn operator_kind(event_type: EventType, value: &str) -> Result<(), AuditPayloadError> {
    if matches!(value, "HUMAN" | "SERVICE") {
        Ok(())
    } else {
        Err(invalid(
            event_type,
            "principal_kind is not an Operator kind",
        ))
    }
}

fn operator_status(
    event_type: EventType,
    field: &'static str,
    value: &str,
) -> Result<(), AuditPayloadError> {
    if matches!(value, "ACTIVE" | "DISABLED") {
        Ok(())
    } else {
        Err(invalid(
            event_type,
            format!("{field} is not an Operator status"),
        ))
    }
}

fn operator_role(event_type: EventType, value: &str) -> Result<(), AuditPayloadError> {
    if matches!(
        value,
        "org_admin" | "policy_author" | "approver" | "auditor"
    ) {
        Ok(())
    } else {
        Err(invalid(event_type, "role is not an ATF Operator role"))
    }
}

fn role_binding_status(event_type: EventType, value: &str) -> Result<(), AuditPayloadError> {
    if matches!(value, "ACTIVE" | "REVOKED") {
        Ok(())
    } else {
        Err(invalid(event_type, "binding_status is invalid"))
    }
}

fn positive_version(event_type: EventType, version: u64) -> Result<(), AuditPayloadError> {
    if version > 0 {
        Ok(())
    } else {
        Err(invalid(event_type, "lifecycle_version must be positive"))
    }
}

fn positive_optional_version(
    event_type: EventType,
    version: Option<u64>,
) -> Result<(), AuditPayloadError> {
    version
        .ok_or_else(|| invalid(event_type, "pointer lifecycle_version is required"))
        .and_then(|version| positive_version(event_type, version))
}

fn nonnegative_amount(
    event_type: EventType,
    field: &'static str,
    value: Amount,
) -> Result<(), AuditPayloadError> {
    if value.is_negative() {
        Err(invalid(event_type, format!("{field} must not be negative")))
    } else {
        Ok(())
    }
}

fn invalid(event_type: EventType, reason: impl Into<String>) -> AuditPayloadError {
    AuditPayloadError::Invalid {
        event_type,
        reason: reason.into(),
    }
}
