use atf_core::{new_ulid, Timestamp};
use serde::{Deserialize, Serialize};

use crate::{AuditPayload, AuditPayloadError};

/// The fixed set of audit event types (PRD §16.2 plus lifecycle events
/// adopted by the security audit). Unit variants serialize as their exact
/// PascalCase Rust name by default, which is also what
/// `schemas/audit-event.schema.json`'s `event_type` enum expects — no
/// `#[serde(rename_all = ...)]` needed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventType {
    IntentReceived,
    IdentityVerified,
    IdentityVerificationSkipped,
    IdentityRejected,
    ContextEnriched,
    PolicyEvaluated,
    RiskEvaluated,
    DecisionRecorded,
    SimulationCompleted,
    ApprovalRequested,
    ApprovalApproved,
    ApprovalGranted,
    ApprovalRejected,
    ExecutionGrantIssued,
    ExecutionRequested,
    ExecutionSubmitted,
    ExecutionConfirmed,
    ExecutionFailed,
    SettlementVerified,
    ServiceDelivered,
    ReconciliationFailed,
    BudgetReserved,
    BudgetCommitted,
    BudgetReleased,
    KillSwitchTriggered,
    KillSwitchEnabled,
    KillSwitchDisabled,
    PolicyChanged,
    AgentPaused,
    IntentExpired,
    IntentCancelled,
}

impl EventType {
    pub const fn has_typed_payload(self) -> bool {
        !matches!(
            self,
            Self::ApprovalGranted | Self::ExecutionRequested | Self::KillSwitchTriggered
        )
    }

    /// Whether this event initializes or advances an Intent lifecycle. These
    /// events may only be appended by a state transaction.
    pub const fn has_lifecycle_effect(self) -> bool {
        !matches!(
            self,
            Self::ContextEnriched
                | Self::ServiceDelivered
                | Self::BudgetReserved
                | Self::BudgetCommitted
                | Self::BudgetReleased
                | Self::KillSwitchTriggered
                | Self::KillSwitchEnabled
                | Self::KillSwitchDisabled
                | Self::PolicyChanged
                | Self::AgentPaused
                | Self::ApprovalGranted
                | Self::ExecutionRequested
        )
    }
}

/// Caller-owned facts for a new Audit event. Chain position and predecessor
/// are deliberately absent: the durable store derives both while holding the
/// organization's chain-head lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewAuditEvent {
    pub event_id: String,
    pub event_type: EventType,
    pub occurred_at: Timestamp,
    pub intent_id: Option<String>,
    pub data: serde_json::Value,
}

impl NewAuditEvent {
    pub fn from_payload(
        occurred_at: Timestamp,
        intent_id: Option<String>,
        payload: AuditPayload,
    ) -> Result<Self, AuditPayloadError> {
        payload.validate()?;
        payload.validate_intent_scope(intent_id.as_deref())?;
        Ok(Self::new(
            payload.event_type(),
            occurred_at,
            intent_id,
            payload.to_data(),
        ))
    }

    /// Construct a legacy/untyped event. New lifecycle producers should use
    /// [`Self::from_payload`] so event type, schema version, scope, and fields
    /// cannot drift apart.
    pub fn new(
        event_type: EventType,
        occurred_at: Timestamp,
        intent_id: Option<String>,
        data: serde_json::Value,
    ) -> Self {
        Self {
            event_id: new_ulid(),
            event_type,
            occurred_at,
            intent_id,
            data,
        }
        .normalized()
    }

    /// Match the millisecond precision used by `Timestamp`'s canonical wire
    /// representation so the typed value, JSON bytes, and PostgreSQL column
    /// cannot disagree about sub-millisecond data.
    pub fn normalized(mut self) -> Self {
        self.occurred_at = self
            .occurred_at
            .to_string()
            .parse()
            .expect("Timestamp's canonical Display is always valid RFC 3339");
        self
    }

    /// Build the canonical event after persistence has selected the committed
    /// predecessor under its database lock.
    pub fn chain(self, prev_event_hash: Option<String>) -> AuditEvent {
        AuditEvent {
            event_id: self.event_id,
            event_type: self.event_type,
            occurred_at: self.occurred_at,
            intent_id: self.intent_id,
            prev_event_hash,
            data: self.data,
        }
    }
}

/// One entry in the Audit Ledger hash chain (PRD §16.2/§16.3), matching
/// `schemas/audit-event.schema.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub event_type: EventType,
    pub occurred_at: Timestamp,
    /// `None` for events not tied to one Intent — `PolicyChanged`,
    /// `AgentPaused`, `KillSwitchTriggered`.
    pub intent_id: Option<String>,
    /// Canonical hash of the event immediately before this one in the
    /// chain. `None` only for that chain's first event.
    pub prev_event_hash: Option<String>,
    pub data: serde_json::Value,
}

impl AuditEvent {
    pub fn typed_payload(&self) -> Result<AuditPayload, AuditPayloadError> {
        let payload = AuditPayload::from_data(self.event_type, &self.data)?;
        payload.validate_intent_scope(self.intent_id.as_deref())?;
        Ok(payload)
    }

    pub fn canonical_value(&self) -> serde_json::Value {
        atf_core::sort_json_keys(
            serde_json::to_value(self).expect("AuditEvent always serializes to JSON"),
        )
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.canonical_value()).expect("canonical value always serializes")
    }

    /// Deterministic hash over this event's canonical JSON form (PRD
    /// §16.3.2) — this is the value the *next* event's `prev_event_hash`
    /// records, and what makes tampering with an earlier event detectable:
    /// changing it changes this hash, which then no longer matches what
    /// the following event captured.
    pub fn canonical_hash(&self) -> String {
        atf_core::sha256_hex(&self.canonical_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_event_uses_explicit_occurrence_time_and_store_owned_predecessor() {
        let occurred_at = "2026-08-08T12:34:56Z".parse().unwrap();
        let event = NewAuditEvent::new(
            EventType::RiskEvaluated,
            occurred_at,
            Some("intent-1".into()),
            serde_json::json!({"risk": "LOW"}),
        )
        .chain(Some("a".repeat(64)));

        assert_eq!(event.occurred_at, occurred_at);
        assert_eq!(event.prev_event_hash, Some("a".repeat(64)));
    }

    #[test]
    fn canonical_hash_is_derived_from_explicit_canonical_bytes() {
        let event = AuditEvent {
            event_id: "event-1".into(),
            event_type: EventType::PolicyEvaluated,
            occurred_at: "2026-08-08T12:34:56Z".parse().unwrap(),
            intent_id: None,
            prev_event_hash: None,
            data: serde_json::json!({"z": 1, "a": {"y": 2, "b": 3}}),
        };

        assert_eq!(
            event.canonical_hash(),
            atf_core::sha256_hex(&event.canonical_bytes())
        );
        assert_eq!(
            String::from_utf8(event.canonical_bytes()).unwrap(),
            r#"{"data":{"a":{"b":3,"y":2},"z":1},"event_id":"event-1","event_type":"PolicyEvaluated","intent_id":null,"occurred_at":"2026-08-08T12:34:56.000Z","prev_event_hash":null}"#
        );
    }

    #[test]
    fn new_event_normalizes_occurrence_time_to_canonical_milliseconds() {
        let event = NewAuditEvent::new(
            EventType::IntentReceived,
            "2026-08-08T12:34:56.123456Z".parse().unwrap(),
            None,
            serde_json::json!({}),
        )
        .chain(None);
        let decoded: AuditEvent = serde_json::from_slice(&event.canonical_bytes()).unwrap();

        assert_eq!(event.occurred_at, decoded.occurred_at);
        assert_eq!(event.occurred_at.to_string(), "2026-08-08T12:34:56.123Z");
    }
}
