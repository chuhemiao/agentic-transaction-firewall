//! Executable proof that every typed Audit payload matches the public JSON
//! Schema and that type-confused or unversioned evidence is rejected.

use std::str::FromStr;

use atf_audit::*;
use atf_core::{
    AccountingBoundary, Amount, DecisionKind, DuplicatePurchaseHistory, DuplicatePurchaseMatch,
    DuplicatePurchaseQuery, ExecutionConstraints, ProfileBinding, RepositorySnapshot,
    RiskHistorySnapshot, SimulationReference, Timestamp, VersionedArtifactReference,
};
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

fn risk_history() -> RiskHistorySnapshot {
    let evaluated_at = Timestamp::from_str("2026-08-08T12:00:00Z").unwrap();
    RiskHistorySnapshot::new(
        RepositorySnapshot::new("audit-chain:alpha-lab:10", 10, hash('e')).unwrap(),
        Some(
            DuplicatePurchaseHistory::new(
                DuplicatePurchaseQuery::new(
                    "alpha-lab",
                    "agent-1",
                    "dataset-1",
                    "intent-1",
                    evaluated_at,
                    86_400,
                    AccountingBoundary::Permitted,
                )
                .unwrap(),
                Some(
                    DuplicatePurchaseMatch::new(
                        "intent-0",
                        "decision-0",
                        "event-0",
                        9,
                        Timestamp::from_str("2026-08-08T11:00:00Z").unwrap(),
                    )
                    .unwrap(),
                ),
            )
            .unwrap(),
        ),
    )
    .unwrap()
}

fn decision_binding() -> DecisionBindingEvidence {
    DecisionBindingEvidence {
        decision_version: "1".into(),
        profile: ProfileBinding {
            id: "atf.agent-commerce.payment".into(),
            version: "1.0".into(),
        },
        policy: VersionedArtifactReference::available("policy-a", "1.0.0", hash('a')).unwrap(),
        risk: VersionedArtifactReference::available("risk-v1", "1.0.0", hash('b')).unwrap(),
        evaluation_context_hash: hash('c'),
        context_snapshot_hash: hash('d'),
        simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED").unwrap(),
        evaluation_time: Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
        expires_at: Timestamp::from_str("2026-08-08T12:05:00Z").unwrap(),
        required_approvals: Vec::new(),
        obligations: Vec::new(),
        execution_constraints: ExecutionConstraints {
            action_category: "payment".into(),
            action_operation: "purchase_api_resource".into(),
            resource_id: "dataset-1".into(),
            resource_protocol: "x402".into(),
            network: "eip155:8453".into(),
            asset: "eip155:8453/erc20:0x1234".into(),
            max_amount: amount(),
            destination: Some("eip155:8453:0x1111".into()),
            adapter_id: None,
        },
    }
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
            None,
            AuditPayload::ReplayDetected(ReplayDetectedPayload {
                organization_id: text("alpha-lab"),
                agent_id: text("agent-1"),
                key_id: text("key-1"),
                nonce_hash: hash('c'),
                attempted_intent_id: text("intent-2"),
                attempted_intent_hash: hash('d'),
                bound_intent_id: text("intent-1"),
                bound_intent_hash: hash('a'),
                reason_code: text("NONCE_BINDING_CONFLICT"),
            }),
        ),
        (
            intent(),
            AuditPayload::IdentityVerificationSkipped(IdentityVerificationSkippedPayload {
                organization_id: text("alpha-lab"),
                agent_id: text("agent-1"),
                reason_code: text("IDENTITY_GATEWAY_NOT_WIRED"),
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
                risk_rule_set_version: Some(text("risk-rules-1.0.0")),
                risk_rule_set_hash: Some(hash('a')),
                history: Some(risk_history()),
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
                binding: Some(Box::new(decision_binding())),
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
                organization_id: None,
                environment: None,
                policy_bundle_id: text("bundle-1"),
                policy_version: None,
                previous_policy_bundle_hash: None,
                policy_bundle_hash: hash('5'),
                change_kind: None,
                lifecycle_version: None,
                actor_id: text("operator-1"),
            }),
        ),
        (
            None,
            AuditPayload::PolicyChanged(PolicyChangedPayload {
                organization_id: Some(text("alpha-lab")),
                environment: Some(text("production")),
                policy_bundle_id: text("bundle-1"),
                policy_version: Some(text("1.1.0")),
                previous_policy_bundle_hash: Some(hash('4')),
                policy_bundle_hash: hash('5'),
                change_kind: Some(text("ROLLED_BACK")),
                lifecycle_version: Some(3),
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
            AuditPayload::AgentRegistered(AgentRegisteredPayload {
                organization_id: text("alpha-lab"),
                agent_id: text("agent-1"),
                status: text("ACTIVE"),
                record_hash: hash('6'),
                lifecycle_version: 1,
                actor_id: text("operator-1"),
            }),
        ),
        (
            None,
            AuditPayload::AgentStatusChanged(AgentStatusChangedPayload {
                organization_id: text("alpha-lab"),
                agent_id: text("agent-1"),
                previous_status: text("ACTIVE"),
                status: text("PAUSED"),
                record_hash: hash('7'),
                lifecycle_version: 2,
                actor_id: text("operator-1"),
                reason_code: text("OPERATOR_PAUSE"),
            }),
        ),
        (
            None,
            AuditPayload::IdentityKeyRegistered(IdentityKeyRegisteredPayload {
                organization_id: text("alpha-lab"),
                agent_id: text("agent-1"),
                key_id: text("key-1"),
                algorithm: text("ED25519"),
                public_key_fingerprint: hash('8'),
                key_record_hash: hash('9'),
                activates_at: Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
                expires_at: Some(Timestamp::from_str("2026-09-08T12:00:00Z").unwrap()),
                lifecycle_version: 1,
                actor_id: text("operator-1"),
            }),
        ),
        (
            None,
            AuditPayload::IdentityKeyRevoked(IdentityKeyRevokedPayload {
                organization_id: text("alpha-lab"),
                agent_id: text("agent-1"),
                key_id: text("key-1"),
                public_key_fingerprint: hash('8'),
                key_record_hash: hash('a'),
                revoked_at: Timestamp::from_str("2026-08-08T12:00:00Z").unwrap(),
                lifecycle_version: 2,
                actor_id: text("operator-1"),
                reason_code: text("KEY_COMPROMISED"),
            }),
        ),
        (
            None,
            AuditPayload::OperatorRegistered(OperatorRegisteredPayload {
                organization_id: text("alpha-lab"),
                operator_id: text("operator-1"),
                issuer_id: text("corp-idp"),
                subject_fingerprint: hash('b'),
                principal_kind: text("HUMAN"),
                status: text("ACTIVE"),
                record_hash: hash('c'),
                lifecycle_version: 1,
                actor_id: text("db-admin-1"),
            }),
        ),
        (
            None,
            AuditPayload::OperatorStatusChanged(OperatorStatusChangedPayload {
                organization_id: text("alpha-lab"),
                operator_id: text("operator-1"),
                previous_status: text("ACTIVE"),
                status: text("DISABLED"),
                record_hash: hash('d'),
                lifecycle_version: 2,
                actor_id: text("db-admin-1"),
                reason_code: text("INCIDENT_RESPONSE"),
            }),
        ),
        (
            None,
            AuditPayload::OperatorRoleGranted(OperatorRoleChangedPayload {
                organization_id: text("alpha-lab"),
                operator_id: text("operator-1"),
                role: text("auditor"),
                binding_status: text("ACTIVE"),
                binding_hash: hash('e'),
                lifecycle_version: 1,
                actor_id: text("db-admin-1"),
                reason_code: text("INITIAL_ACCESS"),
            }),
        ),
        (
            None,
            AuditPayload::OperatorRoleRevoked(OperatorRoleChangedPayload {
                organization_id: text("alpha-lab"),
                operator_id: text("operator-1"),
                role: text("auditor"),
                binding_status: text("REVOKED"),
                binding_hash: hash('f'),
                lifecycle_version: 2,
                actor_id: text("db-admin-1"),
                reason_code: text("ACCESS_REMOVED"),
            }),
        ),
        (
            None,
            AuditPayload::RiskRuleSetStored(RiskRuleSetStoredPayload {
                organization_id: text("alpha-lab"),
                environment: text("production"),
                engine_version: text("atf-risk-engine-v1"),
                rule_set_version: text("1.0.0"),
                rule_set_hash: hash('1'),
                artifact_hash: hash('2'),
                actor_id: text("operator-1"),
            }),
        ),
        (
            intent(),
            AuditPayload::OriginalReplayCompleted(OriginalReplayCompletedPayload {
                organization_id: text("alpha-lab"),
                replay_id: text("replay-1"),
                original_evaluation_id: text("evaluation-1"),
                original_decision_id: text("decision-1"),
                original_decision_hash: hash('3'),
                replayed_decision_hash: hash('3'),
                matched: true,
                authoritative: false,
                actor_id: text("operator-1"),
            }),
        ),
        (
            intent(),
            AuditPayload::CounterfactualReplayCompleted(CounterfactualReplayCompletedPayload {
                organization_id: text("alpha-lab"),
                replay_id: text("replay-2"),
                original_evaluation_id: text("evaluation-1"),
                original_decision_id: text("decision-1"),
                original_decision_hash: hash('3'),
                counterfactual_evaluation_id: text("evaluation-2"),
                evaluation_context_hash: hash('7'),
                counterfactual_evaluation_hash: hash('8'),
                counterfactual_decision_id: text("decision-2"),
                counterfactual_decision_hash: hash('4'),
                policy_bundle_id: text("payments"),
                policy_version: text("2.0.0"),
                policy_bundle_hash: hash('5'),
                risk_engine_version: text("atf-risk-engine-v1"),
                risk_rule_set_version: text("2.0.0"),
                risk_rule_set_hash: hash('6'),
                original_outcome: DecisionKind::Review,
                counterfactual_outcome: DecisionKind::Deny,
                outcome_changed: true,
                authoritative: false,
                actor_id: text("operator-1"),
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
