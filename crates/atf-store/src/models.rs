use crate::audit::StoredAuditEvent;
use atf_audit::{PolicyEvaluatedPayload, RiskEvaluatedPayload, SimulationCompletedPayload};
use atf_core::{IntentLifecycleState, Timestamp};
use atf_decision::Decision;
use atf_intent::TransactionIntent;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::time::Duration;

/// Input for the first short durable-state transaction. Validation and
/// authentication happen before this boundary; successful return means the
/// immutable Intent and its `IntentReceived` evidence committed together.
#[derive(Debug, Clone)]
pub struct AdmissionInput {
    pub intent: TransactionIntent,
    pub received_at: Timestamp,
    pub lease_duration: Duration,
}

#[derive(Clone, PartialEq, Eq)]
pub struct EvaluatorLease {
    pub(crate) organization_id: String,
    pub(crate) idempotency_key: String,
    pub(crate) intent_id: String,
    pub(crate) intent_hash: String,
    pub(crate) owner: String,
    pub(crate) generation: i64,
    pub(crate) expires_at: Timestamp,
}

impl fmt::Debug for EvaluatorLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EvaluatorLease")
            .field("organization_id", &self.organization_id)
            .field("idempotency_key", &self.idempotency_key)
            .field("intent_id", &self.intent_id)
            .field("intent_hash", &self.intent_hash)
            .field("owner", &"[REDACTED]")
            .field("generation", &self.generation)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl EvaluatorLease {
    pub fn generation(&self) -> i64 {
        self.generation
    }

    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IdempotencyState {
    InProgress,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyResult {
    pub evaluation_id: String,
    pub decision_id: String,
    pub decision_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdempotencyReservation {
    pub organization_id: String,
    pub idempotency_key: String,
    pub intent_id: String,
    pub intent_hash: String,
    pub state: IdempotencyState,
    pub lease_generation: i64,
    pub lease_expires_at: Timestamp,
    pub result: Option<IdempotencyResult>,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
    pub completed_at: Option<Timestamp>,
}

/// The module outputs persisted by finalization. This is intentionally a
/// small storage envelope, not the future provenance-bearing Evaluation
/// Context contract scheduled for DS-023.
#[derive(Debug, Clone)]
pub struct EvaluationInput {
    pub evaluation_id: String,
    pub evaluated_at: Timestamp,
    pub policy: PolicyEvaluatedPayload,
    pub risk: RiskEvaluatedPayload,
    pub simulation: SimulationCompletedPayload,
}

/// Input for the second short durable-state transaction. Policy and Risk run
/// before this value is submitted, with no database transaction held open.
#[derive(Debug, Clone)]
pub struct FinalizationInput {
    pub organization_id: String,
    pub intent_id: String,
    pub expected_intent_hash: String,
    pub expected_lifecycle_version: i64,
    pub evaluator_lease: EvaluatorLease,
    pub evaluation: EvaluationInput,
    pub decision: Decision,
    pub decided_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdmittedIntent {
    pub organization_id: String,
    pub intent: TransactionIntent,
    pub intent_hash: String,
    pub received_at: Timestamp,
    pub lifecycle: StoredLifecycle,
    pub audit_event: StoredAuditEvent,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdmissionGrant {
    pub admitted: AdmittedIntent,
    pub evaluator_lease: EvaluatorLease,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredLifecycle {
    pub state: IntentLifecycleState,
    pub version: i64,
    pub contract_version: i32,
    pub last_event_id: Option<String>,
    pub updated_at: Timestamp,
}

/// Canonical evaluation envelope currently written by DS-004. The schema
/// version prevents later Evaluation Context work from silently reinterpreting
/// these early Durable Shadow records.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredEvaluation {
    pub schema_version: u32,
    pub evaluation_id: String,
    pub intent_id: String,
    pub intent_hash: String,
    pub evaluated_at: Timestamp,
    pub evidence: Value,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FinalizedDecision {
    pub organization_id: String,
    pub intent_hash: String,
    pub evaluation: StoredEvaluation,
    pub evaluation_hash: String,
    pub decision: Decision,
    pub decision_hash: String,
    pub decided_at: Timestamp,
    pub lifecycle: StoredLifecycle,
    pub audit_event: StoredAuditEvent,
}
