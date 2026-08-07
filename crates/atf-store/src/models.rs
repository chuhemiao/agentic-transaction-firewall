use crate::audit::StoredAuditEvent;
use atf_core::Timestamp;
use atf_decision::Decision;
use atf_intent::TransactionIntent;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Input for the first short durable-state transaction. Validation and
/// authentication happen before this boundary; successful return means the
/// immutable Intent and its `IntentReceived` evidence committed together.
#[derive(Debug, Clone)]
pub struct AdmissionInput {
    pub intent: TransactionIntent,
    pub received_at: Timestamp,
}

/// The module outputs persisted by finalization. This is intentionally a
/// small storage envelope, not the future provenance-bearing Evaluation
/// Context contract scheduled for DS-023.
#[derive(Debug, Clone)]
pub struct EvaluationInput {
    pub evaluation_id: String,
    pub evaluated_at: Timestamp,
    pub evidence: Value,
}

/// Input for the second short durable-state transaction. Policy and Risk run
/// before this value is submitted, with no database transaction held open.
#[derive(Debug, Clone)]
pub struct FinalizationInput {
    pub organization_id: String,
    pub intent_id: String,
    pub expected_intent_hash: String,
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
    pub audit_event: StoredAuditEvent,
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
    pub audit_event: StoredAuditEvent,
}
