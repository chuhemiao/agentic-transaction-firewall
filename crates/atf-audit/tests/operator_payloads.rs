use atf_audit::{
    AuditPayload, NewAuditEvent, OperatorRegisteredPayload, OperatorRoleChangedPayload,
    OperatorStatusChangedPayload,
};
use atf_core::Timestamp;

fn hash(byte: char) -> String {
    byte.to_string().repeat(64)
}

#[test]
fn operator_and_role_lifecycle_payloads_are_typed_and_redacted() {
    let occurred_at: Timestamp = "2026-08-08T12:00:00Z".parse().unwrap();
    let payloads = [
        AuditPayload::OperatorRegistered(OperatorRegisteredPayload {
            organization_id: "alpha-lab".into(),
            operator_id: "operator-1".into(),
            issuer_id: "corp-idp".into(),
            subject_fingerprint: hash('a'),
            principal_kind: "HUMAN".into(),
            status: "ACTIVE".into(),
            record_hash: hash('b'),
            lifecycle_version: 1,
            actor_id: "db-admin-1".into(),
        }),
        AuditPayload::OperatorStatusChanged(OperatorStatusChangedPayload {
            organization_id: "alpha-lab".into(),
            operator_id: "operator-1".into(),
            previous_status: "ACTIVE".into(),
            status: "DISABLED".into(),
            record_hash: hash('c'),
            lifecycle_version: 2,
            actor_id: "db-admin-1".into(),
            reason_code: "INCIDENT_RESPONSE".into(),
        }),
        AuditPayload::OperatorRoleGranted(OperatorRoleChangedPayload {
            organization_id: "alpha-lab".into(),
            operator_id: "operator-1".into(),
            role: "auditor".into(),
            binding_status: "ACTIVE".into(),
            binding_hash: hash('d'),
            lifecycle_version: 1,
            actor_id: "db-admin-1".into(),
            reason_code: "INITIAL_ACCESS".into(),
        }),
        AuditPayload::OperatorRoleRevoked(OperatorRoleChangedPayload {
            organization_id: "alpha-lab".into(),
            operator_id: "operator-1".into(),
            role: "auditor".into(),
            binding_status: "REVOKED".into(),
            binding_hash: hash('e'),
            lifecycle_version: 2,
            actor_id: "db-admin-1".into(),
            reason_code: "ACCESS_REMOVED".into(),
        }),
    ];

    for payload in payloads {
        let expected = payload.clone();
        let event = NewAuditEvent::from_payload(occurred_at, None, payload)
            .unwrap()
            .chain(None);
        assert_eq!(event.typed_payload().unwrap(), expected);
        assert!(event.event_type.requires_atomic_state_transaction());
        let encoded = serde_json::to_string(&event).unwrap();
        assert!(!encoded.contains("external-subject"));
        assert!(!encoded.contains("bearer"));
        assert!(!encoded.contains("email"));
    }
}
