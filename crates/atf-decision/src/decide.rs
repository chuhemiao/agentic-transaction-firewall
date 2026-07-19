use atf_core::new_ulid;
use atf_intent::TransactionIntent;
use atf_policy::{PolicyDecision, PolicyError, PolicyOutcome};
use atf_risk::{RiskFinding, Severity};

use crate::types::{Decision, DecisionKind, Reason};

/// Merge a Policy Kernel result and a set of Risk Findings into an ATF
/// [`Decision`] (PRD §10.1).
///
/// This is a pure merge function — it does not call `atf-policy` or
/// `atf-risk` itself. The caller is expected to follow §10.1's own ordering
/// when producing its inputs: evaluate Policy first, and only compute Risk
/// Findings if Policy did not already `forbid` (there is no point risk-
/// scoring a request that's already denied). `atf-cli`'s `evaluate` command
/// is the reference caller.
///
/// Order implemented here, matching PRD §10.1 items 2-6 (item 1, Simulator,
/// is skipped entirely — there is no `atf-simulator` yet):
///
/// 1. Policy evaluation itself errored -> `ERROR` (fail closed, PRD §18.1.1).
/// 2. Cedar `forbid` (or Cedar's default-deny) -> `DENY`.
/// 3. Policy permits and some Risk Finding is `Critical` -> `DENY`.
/// 4. Policy permits and the worst Risk Finding is `High` -> `REVIEW`.
/// 5. Policy permits and no Risk Finding is `High` or worse -> `PERMIT`.
pub fn decide(
    intent: &TransactionIntent,
    policy: Result<PolicyOutcome, PolicyError>,
    risk_findings: &[RiskFinding],
) -> Decision {
    let policy_outcome = match policy {
        Ok(outcome) => outcome,
        Err(err) => return error_decision(intent, format!("policy evaluation error: {err}")),
    };

    let mut reasons: Vec<Reason> = policy_outcome
        .policy_ids
        .iter()
        .map(|id| Reason {
            code: id.clone(),
            severity: "info".to_string(),
            message: format!("Cedar policy `{id}` matched this request"),
        })
        .collect();

    if policy_outcome.decision == PolicyDecision::Forbid {
        return Decision {
            decision_id: new_ulid(),
            intent_id: intent.intent_id.clone(),
            decision: DecisionKind::Deny,
            reasons,
        };
    }

    reasons.extend(risk_findings.iter().map(|finding| Reason {
        code: finding.code.clone(),
        severity: finding.severity.to_string(),
        message: finding.message.clone(),
    }));

    let worst_risk = risk_findings.iter().map(|f| f.severity).max();
    let decision = match worst_risk {
        Some(Severity::Critical) => DecisionKind::Deny,
        Some(Severity::High) => DecisionKind::Review,
        _ => DecisionKind::Permit,
    };

    Decision {
        decision_id: new_ulid(),
        intent_id: intent.intent_id.clone(),
        decision,
        reasons,
    }
}

fn error_decision(intent: &TransactionIntent, message: String) -> Decision {
    Decision {
        decision_id: new_ulid(),
        intent_id: intent.intent_id.clone(),
        decision: DecisionKind::Error,
        reasons: vec![Reason {
            code: "POLICY_EVALUATION_ERROR".to_string(),
            severity: "critical".to_string(),
            message,
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atf_core::{Amount, Timestamp};
    use atf_intent::{Action, Mandate, Principal, Resource, Transaction};
    use atf_policy::PolicyBundle;
    use std::str::FromStr;

    fn sample_intent(amount: &str) -> TransactionIntent {
        TransactionIntent {
            spec_version: "1.0".into(),
            intent_id: "01J000000000000000000000".into(),
            idempotency_key: "idem-1".into(),
            created_at: Timestamp::from_str("2026-07-18T08:00:00Z").unwrap(),
            expires_at: Timestamp::from_str("2026-07-18T08:05:00Z").unwrap(),
            principal: Principal {
                organization_id: "alpha-lab".into(),
                user_id: None,
                agent_id: "research-agent-01".into(),
                agent_version: None,
                strategy_id: None,
            },
            mandate: Mandate {
                mandate_id: "mandate-001".into(),
                task_id: None,
                purpose: "purchase historical order-book data".into(),
                budget_id: None,
                human_authorized: true,
            },
            action: Action {
                category: "payment".into(),
                operation: "purchase_api_resource".into(),
            },
            resource: Resource {
                protocol: "x402".into(),
                venue: None,
                resource_id: "btc-orderbook-2026-07-01".into(),
                resource_type: None,
            },
            transaction: Transaction {
                network: "base".into(),
                asset: "eip155:8453/erc20:0x0".into(),
                amount: Amount::from_str(amount).unwrap(),
                destination: None,
                contract: None,
                calldata_hash: None,
                max_fee: None,
                slippage_bps: None,
                leverage: None,
            },
            context: serde_json::json!({}),
            metadata: serde_json::json!({}),
        }
    }

    const POLICY: &str = r#"
        permit (
            principal,
            action == Action::"payment/purchase_api_resource",
            resource
        )
        when {
            context.organization_id == "alpha-lab" &&
            context.amount.lessThanOrEqual(decimal("20.0000"))
        };
    "#;

    fn finding(severity: Severity) -> RiskFinding {
        RiskFinding {
            code: "TEST_FINDING".to_string(),
            severity,
            message: "test".to_string(),
        }
    }

    #[test]
    fn permit_with_no_findings_maps_to_permit() {
        let bundle: PolicyBundle = POLICY.parse().unwrap();
        let intent = sample_intent("12.50");
        let policy = bundle.evaluate(&intent);
        let decision = decide(&intent, policy, &[]);
        assert_eq!(decision.decision, DecisionKind::Permit);
        assert!(!decision.reasons.is_empty());
    }

    #[test]
    fn default_deny_maps_to_deny_regardless_of_risk() {
        let bundle: PolicyBundle = POLICY.parse().unwrap();
        let intent = sample_intent("999.00");
        let policy = bundle.evaluate(&intent);
        // Even a critical finding must not matter once Policy already denied
        // (PRD §10.1.2: "终止合并，不再评估Risk").
        let decision = decide(&intent, policy, &[finding(Severity::Critical)]);
        assert_eq!(decision.decision, DecisionKind::Deny);
    }

    #[test]
    fn critical_risk_finding_overrides_policy_permit_to_deny() {
        let bundle: PolicyBundle = POLICY.parse().unwrap();
        let intent = sample_intent("12.50");
        let policy = bundle.evaluate(&intent);
        let decision = decide(&intent, policy, &[finding(Severity::Critical)]);
        assert_eq!(decision.decision, DecisionKind::Deny);
    }

    #[test]
    fn high_risk_finding_sends_a_permit_to_review() {
        let bundle: PolicyBundle = POLICY.parse().unwrap();
        let intent = sample_intent("12.50");
        let policy = bundle.evaluate(&intent);
        let decision = decide(&intent, policy, &[finding(Severity::High)]);
        assert_eq!(decision.decision, DecisionKind::Review);
    }

    #[test]
    fn info_and_medium_findings_do_not_block_permit() {
        let bundle: PolicyBundle = POLICY.parse().unwrap();
        let intent = sample_intent("12.50");
        let policy = bundle.evaluate(&intent);
        let decision = decide(
            &intent,
            policy,
            &[finding(Severity::Info), finding(Severity::Medium)],
        );
        assert_eq!(decision.decision, DecisionKind::Permit);
    }

    #[test]
    fn policy_evaluation_error_fails_closed_to_error_not_permit() {
        let bundle: PolicyBundle = POLICY.parse().unwrap();
        // Cedar's `decimal` extension supports at most 4 fractional digits
        // (see atf-policy::mapping::decimal_value); an amount with finer
        // precision can't be turned into a Cedar context at all.
        let intent = sample_intent("12.123456");
        let policy = bundle.evaluate(&intent);
        let decision = decide(&intent, policy, &[]);
        assert_eq!(decision.decision, DecisionKind::Error);
        assert_ne!(decision.decision, DecisionKind::Permit);
    }

    #[test]
    fn decision_is_bound_to_the_intent_id() {
        let bundle: PolicyBundle = POLICY.parse().unwrap();
        let intent = sample_intent("12.50");
        let policy = bundle.evaluate(&intent);
        let decision = decide(&intent, policy, &[]);
        assert_eq!(decision.intent_id, intent.intent_id);
    }
}
