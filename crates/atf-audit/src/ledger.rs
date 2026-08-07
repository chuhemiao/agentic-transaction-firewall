use atf_core::Timestamp;

use crate::error::ChainVerificationError;
use crate::event::{AuditEvent, EventType, NewAuditEvent};

/// In-memory, append-only, hash-chained Audit Ledger (PRD §16.3).
///
/// This is domain logic, not a storage layer: PRD §16.3's MVP design calls
/// for a PostgreSQL append-only table, which this crate does not implement.
/// `atf-store` wraps the same canonical event/hash logic with a row-locked,
/// per-organization durable chain; the Gateway cutover is still pending.
#[derive(Debug, Default)]
pub struct AuditLedger {
    events: Vec<AuditEvent>,
}

impl AuditLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a new event to the chain and return it.
    ///
    /// `prev_event_hash` is set to the canonical hash of the event
    /// immediately before this one (`None` only for the very first event
    /// ever appended to this ledger) — this is what makes the log
    /// tamper-evident (PRD §16.3.2, §16.3.4): the ledger never updates or
    /// removes an existing event, so the only way to alter history is to
    /// change an event after the fact, which `verify_chain` then detects.
    pub fn append(
        &mut self,
        event_type: EventType,
        intent_id: Option<String>,
        data: serde_json::Value,
    ) -> &AuditEvent {
        let prev_event_hash = self.events.last().map(AuditEvent::canonical_hash);
        let event = NewAuditEvent::new(event_type, Timestamp::now(), intent_id, data)
            .chain(prev_event_hash);
        self.events.push(event);
        self.events.last().expect("an event was just pushed")
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &AuditEvent> {
        self.events.iter()
    }

    pub fn get(&self, event_id: &str) -> Option<&AuditEvent> {
        self.events.iter().find(|event| event.event_id == event_id)
    }

    /// Verify that every event's `prev_event_hash` matches the canonical
    /// hash of the event immediately before it (and that the first event
    /// has none). This is the check a periodic integrity job, or an
    /// incident investigation, would run (PRD §8.3, §16.3).
    pub fn verify_chain(&self) -> Result<(), ChainVerificationError> {
        let mut expected_prev_hash: Option<String> = None;
        for (index, event) in self.events.iter().enumerate() {
            if event.prev_event_hash != expected_prev_hash {
                return Err(ChainVerificationError { index });
            }
            expected_prev_hash = Some(event.canonical_hash());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_event_has_no_prev_hash() {
        let mut ledger = AuditLedger::new();
        let event = ledger.append(
            EventType::IntentReceived,
            Some("intent-1".into()),
            serde_json::json!({}),
        );
        assert_eq!(event.prev_event_hash, None);
    }

    #[test]
    fn second_events_prev_hash_is_the_first_events_canonical_hash() {
        let mut ledger = AuditLedger::new();
        ledger.append(
            EventType::IntentReceived,
            Some("intent-1".into()),
            serde_json::json!({}),
        );
        let first_hash = ledger.iter().next().unwrap().canonical_hash();

        let second = ledger.append(
            EventType::PolicyEvaluated,
            Some("intent-1".into()),
            serde_json::json!({"decision": "PERMIT"}),
        );
        assert_eq!(second.prev_event_hash, Some(first_hash));
    }

    #[test]
    fn verify_chain_passes_for_an_untampered_ledger() {
        let mut ledger = AuditLedger::new();
        ledger.append(
            EventType::IntentReceived,
            Some("intent-1".into()),
            serde_json::json!({}),
        );
        ledger.append(
            EventType::PolicyEvaluated,
            Some("intent-1".into()),
            serde_json::json!({}),
        );
        ledger.append(
            EventType::RiskEvaluated,
            Some("intent-1".into()),
            serde_json::json!({}),
        );
        assert!(ledger.verify_chain().is_ok());
    }

    #[test]
    fn verify_chain_fails_if_an_earlier_event_is_mutated_after_the_fact() {
        let mut ledger = AuditLedger::new();
        ledger.append(
            EventType::IntentReceived,
            Some("intent-1".into()),
            serde_json::json!({}),
        );
        ledger.append(
            EventType::PolicyEvaluated,
            Some("intent-1".into()),
            serde_json::json!({}),
        );

        // Simulate tampering: mutate the first event's data in place. A real
        // (persistent) ledger wouldn't expose a way to do this at all; this
        // reaches into the private field specifically to prove verify_chain
        // catches it if it somehow happened.
        ledger.events[0].data = serde_json::json!({"tampered": true});

        assert_eq!(
            ledger.verify_chain(),
            Err(ChainVerificationError { index: 1 })
        );
    }

    #[test]
    fn get_finds_an_event_by_id_and_none_for_unknown_ids() {
        let mut ledger = AuditLedger::new();
        let id = ledger
            .append(
                EventType::IntentReceived,
                Some("intent-1".into()),
                serde_json::json!({}),
            )
            .event_id
            .clone();

        assert!(ledger.get(&id).is_some());
        assert!(ledger.get("unknown-id").is_none());
    }

    #[test]
    fn len_and_is_empty_track_appended_events() {
        let mut ledger = AuditLedger::new();
        assert!(ledger.is_empty());
        assert_eq!(ledger.len(), 0);

        ledger.append(EventType::IntentReceived, None, serde_json::json!({}));
        assert!(!ledger.is_empty());
        assert_eq!(ledger.len(), 1);
    }
}
