use atf_core::new_ulid;
use atf_intent::TransactionIntent;
use atf_policy::{PolicyBundle, PolicyDecision};

use crate::types::{Decision, DecisionKind, Reason};

/// Evaluate `intent` against `bundle` and produce an ATF [`Decision`].
///
/// This is today's decision path, not the full merge algorithm from PRD
/// §10.1: Cedar `forbid` (or Cedar's default-deny when nothing matches) maps
/// to `DENY`, Cedar `permit` maps to `PERMIT`, and any internal evaluation
/// error maps to `ERROR` — never silently to `PERMIT` (fail closed, PRD
/// §18.1.1). `REVIEW` is not reachable from this function yet: it requires
/// Risk Engine and Simulator input this crate doesn't have (see
/// `docs/architecture.md`).
pub fn decide(bundle: &PolicyBundle, intent: &TransactionIntent) -> Decision {
    match bundle.evaluate(intent) {
        Ok(outcome) => {
            let decision = match outcome.decision {
                PolicyDecision::Permit => DecisionKind::Permit,
                PolicyDecision::Forbid => DecisionKind::Deny,
            };
            let reasons = outcome
                .policy_ids
                .iter()
                .map(|id| Reason {
                    code: id.clone(),
                    severity: "info".to_string(),
                    message: format!("Cedar policy `{id}` matched this request"),
                })
                .collect();
            Decision {
                decision_id: new_ulid(),
                intent_id: intent.intent_id.clone(),
                decision,
                reasons,
            }
        }
        Err(err) => Decision {
            decision_id: new_ulid(),
            intent_id: intent.intent_id.clone(),
            decision: DecisionKind::Error,
            reasons: vec![Reason {
                code: "POLICY_EVALUATION_ERROR".to_string(),
                severity: "critical".to_string(),
                message: err.to_string(),
            }],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atf_core::{Amount, Timestamp};
    use atf_intent::{Action, Mandate, Principal, Resource, Transaction};
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

    #[test]
    fn permit_maps_to_permit() {
        let bundle: PolicyBundle = POLICY.parse().unwrap();
        let decision = decide(&bundle, &sample_intent("12.50"));
        assert_eq!(decision.decision, DecisionKind::Permit);
        assert!(!decision.reasons.is_empty());
    }

    #[test]
    fn default_deny_maps_to_deny_not_permit() {
        let bundle: PolicyBundle = POLICY.parse().unwrap();
        let decision = decide(&bundle, &sample_intent("999.00"));
        assert_eq!(decision.decision, DecisionKind::Deny);
    }

    #[test]
    fn evaluation_error_fails_closed_to_error_not_permit() {
        let bundle: PolicyBundle = POLICY.parse().unwrap();
        // Cedar's `decimal` extension supports at most 4 fractional digits
        // (see atf-policy::mapping::decimal_value); an amount with finer
        // precision can't be turned into a Cedar context at all.
        let decision = decide(&bundle, &sample_intent("12.123456"));
        assert_eq!(decision.decision, DecisionKind::Error);
        assert_ne!(decision.decision, DecisionKind::Permit);
    }

    #[test]
    fn decision_is_bound_to_the_intent_id() {
        let bundle: PolicyBundle = POLICY.parse().unwrap();
        let intent = sample_intent("12.50");
        let decision = decide(&bundle, &intent);
        assert_eq!(decision.intent_id, intent.intent_id);
    }
}
