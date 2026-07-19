//! Confirms that real `atf_audit::AuditEvent` output (not a hand-written
//! fixture) validates against `schemas/audit-event.schema.json` — the first
//! real producer that schema has had.

use atf_audit::{AuditLedger, EventType};

const SCHEMA_STR: &str = include_str!("../../../schemas/audit-event.schema.json");

fn assert_valid_against_schema(event: &atf_audit::AuditEvent) {
    let schema_value: serde_json::Value = serde_json::from_str(SCHEMA_STR).unwrap();
    let validator = jsonschema::validator_for(&schema_value).expect("schema itself is valid");
    let instance = serde_json::to_value(event).unwrap();

    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "AuditEvent {instance:#} failed schema validation: {errors:?}"
    );
}

#[test]
fn the_first_event_in_a_ledger_matches_the_schema() {
    let mut ledger = AuditLedger::new();
    let event = ledger.append(
        EventType::IntentReceived,
        Some("01J000000000000000000000".to_string()),
        serde_json::json!({"idempotency_key": "idem-1"}),
    );
    // First event: prev_event_hash is null, which the schema must accept.
    assert_eq!(event.prev_event_hash, None);
    assert_valid_against_schema(event);
}

#[test]
fn a_chained_event_with_no_intent_id_matches_the_schema() {
    let mut ledger = AuditLedger::new();
    ledger.append(EventType::IntentReceived, None, serde_json::json!({}));
    let event = ledger.append(
        EventType::KillSwitchTriggered,
        None,
        serde_json::json!({"reason": "manual"}),
    );
    assert!(event.prev_event_hash.is_some());
    assert!(event.intent_id.is_none());
    assert_valid_against_schema(event);
}
