//! Executable proof that every typed Audit payload matches the public JSON
//! Schema and that type-confused or unversioned evidence is rejected.

use std::str::FromStr;

use atf_audit::*;
use atf_core::{Amount, DecisionKind, Timestamp};
use jsonschema::Validator;

const SCHEMA_STR: &str = include_str!("../../../schemas/audit-event.schema.json");

fn validator() -> Validator {
    let schema_value: serde_json::Value = serde_json::from_str(SCHEMA_STR).unwrap();
    jsonschema::validator_for(&schema_value).expect("schema itself is valid")
}

fn assert_valid(instance: &serde_json::Value) {
    let errors: Vec<String> = validator()
        .iter_errors(instance)
        .map(|error| error.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "AuditEvent {instance:#} failed schema validation: {errors:?}"
    );
}

fn assert_invalid(instance: &serde_json::Value) {
    assert!(
        !validator().is_valid(instance),
        "AuditEvent unexpectedly matched the schema: {instance:#}"
    );
}

fn text(value: &str) -> String {
    value.into()
}

fn hash(byte: char) -> String {
    std::iter::repeat_n(byte, 64).collect()
}

fn amount() -> Amount {
    Amount::from_str("12.50").unwrap()
}

fn all_typed_payloads() -> Vec<(Option<String>, AuditPayload)> {
    let intent = || Some(text("intent-1"));
    vec![
        (
            intent(),
            AuditPayload::IntentReceived(IntentReceivedPayload {
                organization_id: text("alpha-lab"),
                agent_id: text("agent-1"),
                idempotency_key: text("idem-1"),
                intent_hash: hash('a'),
                amount: amount(),
                resource_id: text("dataset-1"),
            }),
        ),
        (
            intent(),
            AuditPayload::IdentityVerified(IdentityVerifiedPayload {
                organization_id: text("alpha-lab"),
                agent_id: text("agent-1"),
                key_id: text("key-1"),
                envelope_hash: hash('b'),
            }),
        ),
        (
            intent(),
            AuditPayload::IdentityRejected(IdentityRejectedPayload {
                organization_id: text("alpha-lab"),
                agent_id: text("agent-1"),
                reason_code: text("BAD_SIGNATURE"),
            }),
        ),
        (
            intent(),
            AuditPayload::ContextEnriched(ContextEnrichedPayload {
                context_hash: hash('c'),
                source_ids: vec![text("oracle-snapshot-1")],
            }),
        ),
        (
            intent(),
            AuditPayload::PolicyEvaluated(PolicyEvaluatedPayload {
                outcome: RequiredModuleOutcome::Succeeded {
                    result: PolicyOutcome::Permit,
                },
                policy_ids: vec![text("allow-budget")],
            }),
        ),
        (
            intent(),
            AuditPayload::RiskEvaluated(RiskEvaluatedPayload {
                outcome: OptionalModuleOutcome::Succeeded {
                    result: vec![RiskFindingEvidence {
                        code: text("DUPLICATE_PURCHASE"),
                        severity: RiskSeverity::High,
                    }],
                },
            }),
        ),
        (
            intent(),
            AuditPayload::SimulationCompleted(SimulationCompletedPayload {
                outcome: OptionalModuleOutcome::NotRun {
                    reason_code: text("SIMULATOR_NOT_IMPLEMENTED"),
                },
            }),
        ),
        (
            intent(),
            AuditPayload::DecisionRecorded(DecisionRecordedPayload {
                organization_id: text("alpha-lab"),
                agent_id: text("agent-1"),
                intent_hash: hash('a'),
                evaluation_id: text("evaluation-1"),
                evaluation_hash: hash('d'),
                decision_id: text("decision-1"),
                decision_hash: hash('e'),
                decision: DecisionKind::Permit,
                action_category: text("payment"),
                resource_id: text("dataset-1"),
                amount: amount(),
                destination: Some(text("merchant-1")),
            }),
        ),
        (
            intent(),
            AuditPayload::ApprovalRequested(ApprovalRequestedPayload {
                approval_id: text("approval-1"),
                decision_id: text("decision-1"),
                required_roles: vec![text("treasury-approver")],
            }),
        ),
        (
            intent(),
            AuditPayload::ApprovalApproved(ApprovalResolvedPayload {
                approval_id: text("approval-1"),
                approver_id: text("user-1"),
            }),
        ),
        (
            intent(),
            AuditPayload::ApprovalRejected(ApprovalRejectedPayload {
                approval_id: text("approval-1"),
                approver_id: text("user-1"),
                reason_code: text("POLICY_EXCEPTION_REJECTED"),
            }),
        ),
        (
            intent(),
            AuditPayload::ExecutionGrantIssued(ExecutionGrantPayload {
                grant_id: text("grant-1"),
                decision_id: text("decision-1"),
                execution_hash: hash('f'),
                expires_at: Timestamp::from_str("2026-08-08T12:05:00Z").unwrap(),
            }),
        ),
        (
            intent(),
            AuditPayload::ExecutionSubmitted(ExecutionSubmittedPayload {
                execution_id: text("execution-1"),
                grant_id: text("grant-1"),
                adapter_id: text("x402"),
                request_hash: hash('1'),
            }),
        ),
        (
            intent(),
            AuditPayload::ExecutionConfirmed(ExecutionConfirmedPayload {
                execution_id: text("execution-1"),
                result_hash: hash('2'),
            }),
        ),
        (
            intent(),
            AuditPayload::ExecutionFailed(ExecutionFailedPayload {
                execution_id: text("execution-1"),
                error_code: text("ADAPTER_TIMEOUT"),
            }),
        ),
        (
            intent(),
            AuditPayload::SettlementVerified(SettlementVerifiedPayload {
                execution_id: text("execution-1"),
                settlement_hash: hash('3'),
            }),
        ),
        (
            intent(),
            AuditPayload::ServiceDelivered(ServiceDeliveredPayload {
                execution_id: text("execution-1"),
                delivery_hash: hash('4'),
            }),
        ),
        (
            intent(),
            AuditPayload::ReconciliationFailed(ReconciliationFailedPayload {
                execution_id: text("execution-1"),
                error_code: text("SETTLEMENT_MISMATCH"),
            }),
        ),
        (
            intent(),
            AuditPayload::BudgetReserved(BudgetPayload {
                budget_id: text("budget-1"),
                reservation_id: text("reservation-1"),
                amount: amount(),
                asset: text("USDC"),
            }),
        ),
        (
            intent(),
            AuditPayload::BudgetCommitted(BudgetPayload {
                budget_id: text("budget-1"),
                reservation_id: text("reservation-1"),
                amount: amount(),
                asset: text("USDC"),
            }),
        ),
        (
            intent(),
            AuditPayload::BudgetReleased(BudgetPayload {
                budget_id: text("budget-1"),
                reservation_id: text("reservation-1"),
                amount: amount(),
                asset: text("USDC"),
            }),
        ),
        (
            None,
            AuditPayload::PolicyChanged(PolicyChangedPayload {
                policy_bundle_id: text("bundle-1"),
                policy_bundle_hash: hash('5'),
                actor_id: text("operator-1"),
            }),
        ),
        (
            None,
            AuditPayload::AgentPaused(AgentPausedPayload {
                organization_id: text("alpha-lab"),
                agent_id: text("agent-1"),
                actor_id: text("operator-1"),
                reason_code: text("INCIDENT"),
            }),
        ),
        (
            None,
            AuditPayload::KillSwitchEnabled(KillSwitchPayload {
                scope: text("GLOBAL"),
                actor_id: text("operator-1"),
                reason_code: text("INCIDENT"),
            }),
        ),
        (
            None,
            AuditPayload::KillSwitchDisabled(KillSwitchPayload {
                scope: text("GLOBAL"),
                actor_id: text("operator-1"),
                reason_code: text("INCIDENT_RESOLVED"),
            }),
        ),
        (
            intent(),
            AuditPayload::IntentExpired(IntentExpiredPayload {
                reason_code: text("INTENT_TTL_EXPIRED"),
            }),
        ),
        (
            intent(),
            AuditPayload::IntentCancelled(IntentCancelledPayload {
                actor_id: text("user-1"),
                reason_code: text("USER_CANCELLED"),
            }),
        ),
    ]
}

#[test]
fn every_typed_payload_matches_the_public_schema() {
    for (intent_id, payload) in all_typed_payloads() {
        let expected = payload.clone();
        let event = NewAuditEvent::from_payload(
            Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
            intent_id,
            payload,
        )
        .unwrap()
        .chain(None);
        assert_eq!(event.typed_payload().unwrap(), expected);
        assert_valid(&serde_json::to_value(event).unwrap());
    }
}

#[test]
fn schema_rejects_type_confusion_unknown_fields_and_payload_version_drift() {
    let (_, payload) = all_typed_payloads()
        .into_iter()
        .find(|(_, payload)| matches!(payload, AuditPayload::PolicyEvaluated(_)))
        .unwrap();
    let event = NewAuditEvent::from_payload(
        Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
        Some(text("intent-1")),
        payload,
    )
    .unwrap()
    .chain(None);
    let mut instance = serde_json::to_value(event).unwrap();

    instance["event_type"] = serde_json::json!("RiskEvaluated");
    assert_invalid(&instance);

    instance["event_type"] = serde_json::json!("PolicyEvaluated");
    instance["data"]["unexpected"] = serde_json::json!(true);
    assert_invalid(&instance);

    instance["data"]
        .as_object_mut()
        .unwrap()
        .remove("unexpected");
    instance["data"]["outcome"]["unexpected"] = serde_json::json!(true);
    assert_invalid(&instance);

    instance["data"]["outcome"]
        .as_object_mut()
        .unwrap()
        .remove("unexpected");
    instance["data"]["schema_version"] = serde_json::json!(2);
    assert_invalid(&instance);

    instance["data"]["schema_version"] = serde_json::json!(1);
    instance["unexpected"] = serde_json::json!(true);
    assert_invalid(&instance);
}

#[test]
fn schema_rejects_bad_scope_identifiers_hashes_and_amounts() {
    let (intent_id, payload) = all_typed_payloads().remove(0);
    let event = NewAuditEvent::from_payload(
        Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
        intent_id,
        payload,
    )
    .unwrap()
    .chain(None);
    let mut instance = serde_json::to_value(event).unwrap();

    instance["intent_id"] = serde_json::Value::Null;
    assert_invalid(&instance);

    instance["intent_id"] = serde_json::json!("intent-1");
    instance["data"]["organization_id"] = serde_json::json!(" alpha-lab");
    assert_invalid(&instance);

    instance["data"]["organization_id"] = serde_json::json!("alpha-lab");
    instance["data"]["intent_hash"] = serde_json::json!("not-a-hash");
    assert_invalid(&instance);

    instance["data"]["intent_hash"] = serde_json::json!(hash('a'));
    instance["data"]["amount"] = serde_json::json!("-0.01");
    assert_invalid(&instance);
}

#[test]
fn legacy_wire_names_remain_schema_valid_but_unknown_names_do_not() {
    for event_type in [
        EventType::ApprovalGranted,
        EventType::ExecutionRequested,
        EventType::KillSwitchTriggered,
    ] {
        let event = NewAuditEvent::new(
            event_type,
            Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
            None,
            serde_json::json!({"legacy": true}),
        )
        .chain(None);
        assert_valid(&serde_json::to_value(event).unwrap());
    }

    let mut unknown = serde_json::to_value(
        NewAuditEvent::new(
            EventType::PolicyChanged,
            Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
            None,
            serde_json::json!({}),
        )
        .chain(None),
    )
    .unwrap();
    unknown["event_type"] = serde_json::json!("UnknownEvent");
    assert_invalid(&unknown);
}
