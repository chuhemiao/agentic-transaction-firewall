use std::str::FromStr;

use atf_audit::{
    ApprovalRequestedPayload, AuditPayload, ContextEnrichedPayload, DecisionRecordedPayload,
    EventType, IdentityRejectedPayload, IdentityVerifiedPayload, IntentReceivedPayload,
    KillSwitchPayload, NewAuditEvent, OptionalModuleOutcome, PolicyEvaluatedPayload, PolicyOutcome,
    RequiredModuleOutcome, RiskEvaluatedPayload, RiskFindingEvidence, RiskSeverity,
    SimulationCompletedPayload,
};
use atf_core::{Amount, DecisionKind, IntentLifecycleState as State, Timestamp};

fn hash(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn received_payload() -> AuditPayload {
    AuditPayload::IntentReceived(IntentReceivedPayload {
        organization_id: "alpha-lab".into(),
        agent_id: "agent-1".into(),
        idempotency_key: "idem-1".into(),
        intent_hash: hash('a'),
        amount: Amount::from_str("12.50").unwrap(),
        resource_id: "dataset-1".into(),
    })
}

fn decision_payload(decision: DecisionKind) -> AuditPayload {
    AuditPayload::DecisionRecorded(DecisionRecordedPayload {
        organization_id: "alpha-lab".into(),
        agent_id: "agent-1".into(),
        intent_hash: hash('a'),
        evaluation_id: "evaluation-1".into(),
        evaluation_hash: hash('b'),
        decision_id: "decision-1".into(),
        decision_hash: hash('c'),
        decision,
        action_category: "payment".into(),
        resource_id: "dataset-1".into(),
        amount: Amount::from_str("12.50").unwrap(),
        destination: Some("merchant-1".into()),
    })
}

#[test]
fn typed_constructor_binds_event_type_schema_version_and_intent_scope() {
    let event = NewAuditEvent::from_payload(
        Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
        Some("intent-1".into()),
        received_payload(),
    )
    .unwrap()
    .chain(None);

    assert_eq!(event.event_type, EventType::IntentReceived);
    assert_eq!(event.data["schema_version"], 1);
    assert_eq!(event.typed_payload().unwrap(), received_payload());

    assert!(NewAuditEvent::from_payload(
        Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
        None,
        received_payload(),
    )
    .is_err());

    let operator_event = AuditPayload::KillSwitchEnabled(KillSwitchPayload {
        scope: "GLOBAL".into(),
        actor_id: "operator-1".into(),
        reason_code: "INCIDENT".into(),
    });
    assert!(NewAuditEvent::from_payload(
        Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
        Some("intent-1".into()),
        operator_event,
    )
    .is_err());
}

#[test]
fn payload_parser_rejects_type_confusion_unknown_fields_and_versions() {
    let policy = AuditPayload::PolicyEvaluated(PolicyEvaluatedPayload {
        outcome: RequiredModuleOutcome::Succeeded {
            result: PolicyOutcome::Permit,
        },
        policy_ids: vec!["allow-budget".into()],
    });
    let mut event = NewAuditEvent::from_payload(
        Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
        Some("intent-1".into()),
        policy,
    )
    .unwrap()
    .chain(None);

    event.event_type = EventType::RiskEvaluated;
    assert!(event.typed_payload().is_err());

    event.event_type = EventType::PolicyEvaluated;
    event.data["unexpected"] = serde_json::json!(true);
    assert!(event.typed_payload().is_err());

    event.data.as_object_mut().unwrap().remove("unexpected");
    event.data["outcome"]["unexpected"] = serde_json::json!(true);
    assert!(event.typed_payload().is_err());

    event.data["outcome"]
        .as_object_mut()
        .unwrap()
        .remove("unexpected");
    event.data["schema_version"] = serde_json::json!(2);
    assert!(event.typed_payload().is_err());
}

#[test]
fn typed_events_apply_only_their_documented_lifecycle_effect() {
    let identity_verified = AuditPayload::IdentityVerified(IdentityVerifiedPayload {
        organization_id: "alpha-lab".into(),
        agent_id: "agent-1".into(),
        key_id: "key-1".into(),
        envelope_hash: hash('d'),
    });
    let identity_rejected = AuditPayload::IdentityRejected(IdentityRejectedPayload {
        organization_id: "alpha-lab".into(),
        agent_id: "agent-1".into(),
        reason_code: "BAD_SIGNATURE".into(),
    });
    let policy = AuditPayload::PolicyEvaluated(PolicyEvaluatedPayload {
        outcome: RequiredModuleOutcome::Succeeded {
            result: PolicyOutcome::Permit,
        },
        policy_ids: vec!["allow-budget".into()],
    });
    let risk = AuditPayload::RiskEvaluated(RiskEvaluatedPayload {
        outcome: OptionalModuleOutcome::Succeeded {
            result: vec![RiskFindingEvidence {
                code: "DUPLICATE_PURCHASE".into(),
                severity: RiskSeverity::High,
            }],
        },
    });
    let simulation = AuditPayload::SimulationCompleted(SimulationCompletedPayload {
        outcome: OptionalModuleOutcome::NotRun {
            reason_code: "SIMULATOR_NOT_IMPLEMENTED".into(),
        },
    });

    assert_eq!(
        received_payload().next_state(None).unwrap(),
        Some(State::Received)
    );
    assert_eq!(
        identity_verified.next_state(Some(State::Received)).unwrap(),
        Some(State::IdentityVerified)
    );
    assert_eq!(
        identity_rejected.next_state(Some(State::Received)).unwrap(),
        Some(State::IdentityRejected)
    );
    assert_eq!(
        policy.next_state(Some(State::IdentityVerified)).unwrap(),
        Some(State::PolicyEvaluated)
    );
    assert_eq!(
        risk.next_state(Some(State::PolicyEvaluated)).unwrap(),
        Some(State::RiskEvaluated)
    );
    assert_eq!(
        simulation.next_state(Some(State::RiskEvaluated)).unwrap(),
        Some(State::SimulationCompleted)
    );

    for (decision, expected) in [
        (DecisionKind::Permit, State::DecidedPermit),
        (DecisionKind::Review, State::DecidedReview),
        (DecisionKind::Deny, State::DecidedDeny),
        (DecisionKind::Error, State::DecidedError),
    ] {
        assert_eq!(
            decision_payload(decision)
                .next_state(Some(State::SimulationCompleted))
                .unwrap(),
            Some(expected)
        );
    }
}

#[test]
fn non_state_evidence_preserves_state_and_invalid_advancement_fails_closed() {
    let context = AuditPayload::ContextEnriched(ContextEnrichedPayload {
        context_hash: hash('e'),
        source_ids: vec!["oracle-snapshot-1".into()],
    });
    assert_eq!(
        context.next_state(Some(State::IdentityVerified)).unwrap(),
        Some(State::IdentityVerified)
    );

    let approval = AuditPayload::ApprovalRequested(ApprovalRequestedPayload {
        approval_id: "approval-1".into(),
        decision_id: "decision-1".into(),
        required_roles: vec!["treasury-approver".into()],
    });
    assert!(approval.next_state(Some(State::DecidedDeny)).is_err());
    assert!(decision_payload(DecisionKind::Permit)
        .next_state(Some(State::DecidedError))
        .is_err());
    assert!(received_payload()
        .next_state(Some(State::Received))
        .is_err());
}

#[test]
fn malformed_identifiers_and_hashes_are_rejected_before_event_creation() {
    let mut payload = received_payload();
    let AuditPayload::IntentReceived(fields) = &mut payload else {
        unreachable!()
    };
    fields.organization_id.clear();
    fields.intent_hash = "not-a-hash".into();

    let result = NewAuditEvent::from_payload(
        Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
        Some("intent-1".into()),
        payload,
    );
    assert!(result.is_err());

    let mut payload = received_payload();
    let AuditPayload::IntentReceived(fields) = &mut payload else {
        unreachable!()
    };
    fields.amount = Amount::from_str("-0.01").unwrap();
    assert!(NewAuditEvent::from_payload(
        Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
        Some("intent-1".into()),
        payload,
    )
    .is_err());
}

#[test]
fn legacy_event_names_remain_decodable_without_becoming_typed_transitions() {
    for name in [
        r#""ApprovalGranted""#,
        r#""ExecutionRequested""#,
        r#""KillSwitchTriggered""#,
    ] {
        let event_type: EventType = serde_json::from_str(name).unwrap();
        assert!(!event_type.has_typed_payload());
    }
}
