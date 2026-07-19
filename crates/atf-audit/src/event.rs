use atf_core::Timestamp;
use serde::{Deserialize, Serialize};

/// The fixed set of audit event types (PRD §16.2). Unit variants serialize
/// as their exact PascalCase Rust name by default, which is also what
/// `schemas/audit-event.schema.json`'s `event_type` enum expects — no
/// `#[serde(rename_all = ...)]` needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    IntentReceived,
    IdentityVerified,
    PolicyEvaluated,
    RiskEvaluated,
    SimulationCompleted,
    ApprovalRequested,
    ApprovalGranted,
    ApprovalRejected,
    ExecutionRequested,
    ExecutionSubmitted,
    ExecutionConfirmed,
    SettlementVerified,
    ServiceDelivered,
    ReconciliationFailed,
    KillSwitchTriggered,
    PolicyChanged,
    AgentPaused,
}

/// One entry in the Audit Ledger hash chain (PRD §16.2/§16.3), matching
/// `schemas/audit-event.schema.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub event_type: EventType,
    pub occurred_at: Timestamp,
    /// `None` for events not tied to one Intent — `PolicyChanged`,
    /// `AgentPaused`, `KillSwitchTriggered`.
    pub intent_id: Option<String>,
    /// Canonical hash of the event immediately before this one in the
    /// ledger. `None` only for the very first event ever appended.
    pub prev_event_hash: Option<String>,
    pub data: serde_json::Value,
}

impl AuditEvent {
    /// Deterministic hash over this event's canonical JSON form (PRD
    /// §16.3.2) — this is the value the *next* event's `prev_event_hash`
    /// records, and what makes tampering with an earlier event detectable:
    /// changing it changes this hash, which then no longer matches what
    /// the following event captured.
    pub fn canonical_hash(&self) -> String {
        let value = atf_core::sort_json_keys(
            serde_json::to_value(self).expect("AuditEvent always serializes to JSON"),
        );
        let bytes = serde_json::to_vec(&value).expect("canonical value always serializes");
        atf_core::sha256_hex(&bytes)
    }
}
