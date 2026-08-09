use std::str::FromStr;

use atf_audit::{
    AgentRegisteredPayload, AgentStatusChangedPayload, ApprovalRequestedPayload, AuditPayload,
    ContextEnrichedPayload, CounterfactualReplayCompletedPayload, DecisionRecordedPayload,
    EventType, IdentityKeyRegisteredPayload, IdentityKeyRevokedPayload, IdentityRejectedPayload,
    IdentityVerificationSkippedPayload, IdentityVerifiedPayload, IntentReceivedPayload,
    KillSwitchPayload, NewAuditEvent, OptionalModuleOutcome, OriginalReplayCompletedPayload,
    PolicyEvaluatedPayload, PolicyOutcome, ReplayDetectedPayload, RequiredModuleOutcome,
    RiskEvaluatedPayload, RiskFindingEvidence, RiskSeverity, SimulationCompletedPayload,
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
        binding: None,
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
fn risk_rule_set_version_and_hash_are_an_atomic_compatibility_extension() {
    let occurred_at = Timestamp::from_str("2026-08-08T12:00:00Z").unwrap();
    let legacy = NewAuditEvent::from_payload(
        occurred_at,
        Some("intent-1".into()),
        AuditPayload::RiskEvaluated(RiskEvaluatedPayload {
            risk_rule_set_version: None,
            risk_rule_set_hash: None,
            history: None,
            outcome: OptionalModuleOutcome::Succeeded { result: Vec::new() },
        }),
    )
    .unwrap()
    .chain(None);
    assert!(legacy.typed_payload().is_ok());

    let mut partial = legacy;
    partial.data["risk_rule_set_version"] = serde_json::json!("risk-rules-1.0.0");
    assert!(partial.typed_payload().is_err());
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
    let identity_skipped =
        AuditPayload::IdentityVerificationSkipped(IdentityVerificationSkippedPayload {
            organization_id: "alpha-lab".into(),
            agent_id: "agent-1".into(),
            reason_code: "IDENTITY_GATEWAY_NOT_WIRED".into(),
        });
    let policy = AuditPayload::PolicyEvaluated(PolicyEvaluatedPayload {
        outcome: RequiredModuleOutcome::Succeeded {
            result: PolicyOutcome::Permit,
        },
        policy_ids: vec!["allow-budget".into()],
    });
    let risk = AuditPayload::RiskEvaluated(RiskEvaluatedPayload {
        risk_rule_set_version: None,
        risk_rule_set_hash: None,
        history: None,
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
        identity_skipped.next_state(Some(State::Received)).unwrap(),
        Some(State::IdentityUnverified)
    );
    assert_eq!(
        policy.next_state(Some(State::IdentityUnverified)).unwrap(),
        Some(State::PolicyEvaluated)
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

    let replay = AuditPayload::ReplayDetected(ReplayDetectedPayload {
        organization_id: "alpha-lab".into(),
        agent_id: "agent-1".into(),
        key_id: "key-1".into(),
        nonce_hash: hash('1'),
        attempted_intent_id: "intent-2".into(),
        attempted_intent_hash: hash('2'),
        bound_intent_id: "intent-1".into(),
        bound_intent_hash: hash('3'),
        reason_code: "NONCE_BINDING_CONFLICT".into(),
    });
    assert_eq!(
        replay.next_state(Some(State::IdentityVerified)).unwrap(),
        Some(State::IdentityVerified)
    );
    assert!(!EventType::ReplayDetected.has_lifecycle_effect());
    for event_type in [
        EventType::RiskRuleSetStored,
        EventType::OriginalReplayCompleted,
        EventType::CounterfactualReplayCompleted,
    ] {
        assert!(!event_type.has_lifecycle_effect());
        assert!(event_type.requires_atomic_state_transaction());
    }

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

    let mismatched_replay = AuditPayload::OriginalReplayCompleted(OriginalReplayCompletedPayload {
        organization_id: "alpha-lab".into(),
        replay_id: "replay-1".into(),
        original_evaluation_id: "evaluation-1".into(),
        original_decision_id: "decision-1".into(),
        original_decision_hash: hash('a'),
        replayed_decision_hash: hash('b'),
        matched: true,
        authoritative: false,
        actor_id: "operator-1".into(),
    });
    assert!(NewAuditEvent::from_payload(
        Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
        Some("intent-1".into()),
        mismatched_replay,
    )
    .is_err());

    let inconsistent_counterfactual =
        AuditPayload::CounterfactualReplayCompleted(CounterfactualReplayCompletedPayload {
            organization_id: "alpha-lab".into(),
            replay_id: "replay-2".into(),
            original_evaluation_id: "evaluation-1".into(),
            original_decision_id: "decision-1".into(),
            original_decision_hash: hash('a'),
            counterfactual_evaluation_id: "evaluation-2".into(),
            evaluation_context_hash: hash('e'),
            counterfactual_evaluation_hash: hash('f'),
            counterfactual_decision_id: "decision-2".into(),
            counterfactual_decision_hash: hash('b'),
            policy_bundle_id: "payments".into(),
            policy_version: "2.0.0".into(),
            policy_bundle_hash: hash('c'),
            risk_engine_version: "atf-risk-engine-v1".into(),
            risk_rule_set_version: "2.0.0".into(),
            risk_rule_set_hash: hash('d'),
            original_outcome: DecisionKind::Review,
            counterfactual_outcome: DecisionKind::Deny,
            outcome_changed: false,
            authoritative: false,
            actor_id: "operator-1".into(),
        });
    assert!(NewAuditEvent::from_payload(
        Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
        Some("intent-1".into()),
        inconsistent_counterfactual,
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

#[test]
fn identity_operator_events_are_typed_non_intent_evidence_without_key_material() {
    let occurred_at = Timestamp::from_str("2026-08-08T12:00:00Z").unwrap();
    let events = [
        AuditPayload::AgentRegistered(AgentRegisteredPayload {
            organization_id: "alpha-lab".into(),
            agent_id: "agent-1".into(),
            status: "ACTIVE".into(),
            record_hash: hash('6'),
            lifecycle_version: 1,
            actor_id: "operator-1".into(),
        }),
        AuditPayload::AgentStatusChanged(AgentStatusChangedPayload {
            organization_id: "alpha-lab".into(),
            agent_id: "agent-1".into(),
            previous_status: "ACTIVE".into(),
            status: "PAUSED".into(),
            record_hash: hash('7'),
            lifecycle_version: 2,
            actor_id: "operator-1".into(),
            reason_code: "OPERATOR_PAUSE".into(),
        }),
        AuditPayload::IdentityKeyRegistered(IdentityKeyRegisteredPayload {
            organization_id: "alpha-lab".into(),
            agent_id: "agent-1".into(),
            key_id: "key-1".into(),
            algorithm: "ED25519".into(),
            public_key_fingerprint: hash('8'),
            key_record_hash: hash('9'),
            activates_at: occurred_at,
            expires_at: Some(Timestamp::from_str("2026-09-08T12:00:00Z").unwrap()),
            lifecycle_version: 1,
            actor_id: "operator-1".into(),
        }),
        AuditPayload::IdentityKeyRevoked(IdentityKeyRevokedPayload {
            organization_id: "alpha-lab".into(),
            agent_id: "agent-1".into(),
            key_id: "key-1".into(),
            public_key_fingerprint: hash('8'),
            key_record_hash: hash('a'),
            revoked_at: occurred_at,
            lifecycle_version: 2,
            actor_id: "operator-1".into(),
            reason_code: "KEY_COMPROMISED".into(),
        }),
    ];

    for payload in events {
        let expected = payload.clone();
        let event = NewAuditEvent::from_payload(occurred_at, None, payload)
            .unwrap()
            .chain(None);
        assert!(event.event_type.has_typed_payload());
        assert!(!event.event_type.has_lifecycle_effect());
        assert_eq!(event.data["schema_version"], 1);
        assert_eq!(event.typed_payload().unwrap(), expected);
        assert_eq!(
            expected.next_state(Some(State::Received)).unwrap(),
            Some(State::Received)
        );
        assert!(event.data.get("public_key").is_none());
        assert!(event.data.get("private_key").is_none());
    }
}
