use atf_audit::{AuditLedger, EventType};
use atf_core::Timestamp;
use atf_intent::TransactionIntent;
use chrono::Duration;

use crate::finding::RiskFinding;
use crate::severity::Severity;

/// Rules that need to look at prior events, not just the current Intent —
/// PRD §12.2's "duplicate purchase", "daily cumulative spend", "first-time
/// address", "order frequency" are all this shape. Only `duplicate_purchase`
/// is implemented so far; the rest need more than `IntentReceived`'s
/// `agent_id`/`resource_id`/`amount` payload carries today (e.g. a
/// destination-address history, or a reliable "was this Intent ultimately
/// PERMITted" signal, which `IntentReceived` alone doesn't have).
pub(crate) fn history_findings(
    intent: &TransactionIntent,
    ledger: &AuditLedger,
) -> Vec<RiskFinding> {
    duplicate_purchase_within_24h(intent, ledger)
        .into_iter()
        .collect()
}

/// Flags a request for the same Agent + Resource combination seen in the
/// ledger within the last 24 hours (PRD §12.2 "服务重复购买", §24.3.2's
/// concrete "same dataset within 24h" rule).
///
/// Reads `agent_id`/`resource_id` back out of `IntentReceived` events' data
/// payload — see `services/gateway`'s `create_intent` handler, which is
/// what puts them there. A ledger that doesn't record those fields (e.g. a
/// hand-built one in a test) just never matches, which is the correct
/// fail-safe direction: this rule can miss a real duplicate if the caller
/// didn't record enough to detect it, but it can't invent a false one.
fn duplicate_purchase_within_24h(
    intent: &TransactionIntent,
    ledger: &AuditLedger,
) -> Option<RiskFinding> {
    let window_start =
        Timestamp::from_datetime(Timestamp::now().as_datetime() - Duration::hours(24));

    let duplicate_of = ledger.iter().find(|event| {
        event.event_type == EventType::IntentReceived
            && event.intent_id.as_deref() != Some(intent.intent_id.as_str())
            && event.occurred_at >= window_start
            && event.data.get("agent_id").and_then(|v| v.as_str())
                == Some(intent.principal.agent_id.as_str())
            && event.data.get("resource_id").and_then(|v| v.as_str())
                == Some(intent.resource.resource_id.as_str())
    })?;

    Some(RiskFinding {
        code: "DUPLICATE_PURCHASE".to_string(),
        severity: Severity::High,
        message: format!(
            "Agent `{}` already requested resource `{}` at {} (intent {}), within the last 24h",
            intent.principal.agent_id,
            intent.resource.resource_id,
            duplicate_of.occurred_at,
            duplicate_of.intent_id.as_deref().unwrap_or("unknown"),
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use atf_core::Amount;
    use atf_intent::{Action, Mandate, Principal, Resource, Transaction};
    use std::str::FromStr;

    fn intent(intent_id: &str, agent_id: &str, resource_id: &str) -> TransactionIntent {
        TransactionIntent {
            spec_version: "1.0".into(),
            intent_id: intent_id.into(),
            idempotency_key: format!("idem-{intent_id}"),
            created_at: Timestamp::from_str("2026-07-18T08:00:00Z").unwrap(),
            expires_at: Timestamp::from_str("2099-01-01T00:00:00Z").unwrap(),
            principal: Principal {
                organization_id: "alpha-lab".into(),
                user_id: None,
                agent_id: agent_id.into(),
                agent_version: None,
                strategy_id: None,
            },
            mandate: Mandate {
                mandate_id: "mandate-001".into(),
                task_id: None,
                purpose: "test".into(),
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
                resource_id: resource_id.into(),
                resource_type: None,
            },
            transaction: Transaction {
                network: "base".into(),
                asset: "eip155:8453/erc20:0x0".into(),
                amount: Amount::from_str("12.50").unwrap(),
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

    fn ledger_with_prior_purchase(agent_id: &str, resource_id: &str) -> AuditLedger {
        let mut ledger = AuditLedger::new();
        ledger.append(
            EventType::IntentReceived,
            Some("01J0000000000000000000P0".to_string()),
            serde_json::json!({ "agent_id": agent_id, "resource_id": resource_id }),
        );
        ledger
    }

    #[test]
    fn flags_a_repeat_request_for_the_same_agent_and_resource() {
        let ledger = ledger_with_prior_purchase("research-agent-01", "btc-orderbook-2026-07-01");
        let new_intent = intent(
            "01J0000000000000000000P1",
            "research-agent-01",
            "btc-orderbook-2026-07-01",
        );

        let finding = duplicate_purchase_within_24h(&new_intent, &ledger);
        assert!(finding.is_some());
        assert_eq!(finding.unwrap().code, "DUPLICATE_PURCHASE");
    }

    #[test]
    fn does_not_flag_a_different_resource() {
        let ledger = ledger_with_prior_purchase("research-agent-01", "btc-orderbook-2026-07-01");
        let new_intent = intent(
            "01J0000000000000000000P2",
            "research-agent-01",
            "eth-orderbook-2026-07-01",
        );

        assert!(duplicate_purchase_within_24h(&new_intent, &ledger).is_none());
    }

    #[test]
    fn does_not_flag_a_different_agent() {
        let ledger = ledger_with_prior_purchase("research-agent-01", "btc-orderbook-2026-07-01");
        let new_intent = intent(
            "01J0000000000000000000P3",
            "research-agent-02",
            "btc-orderbook-2026-07-01",
        );

        assert!(duplicate_purchase_within_24h(&new_intent, &ledger).is_none());
    }

    #[test]
    fn does_not_flag_an_empty_ledger() {
        let ledger = AuditLedger::new();
        let new_intent = intent(
            "01J0000000000000000000P4",
            "research-agent-01",
            "btc-orderbook-2026-07-01",
        );

        assert!(duplicate_purchase_within_24h(&new_intent, &ledger).is_none());
    }

    #[test]
    fn does_not_flag_the_intents_own_already_recorded_event() {
        // A caller (services/gateway) records IntentReceived for the
        // current Intent *before* running Risk, so the ledger already
        // contains this exact intent_id. That must not count as its own
        // duplicate.
        let mut ledger = AuditLedger::new();
        let this_intent = intent(
            "01J0000000000000000000P5",
            "research-agent-01",
            "btc-orderbook-2026-07-01",
        );
        ledger.append(
            EventType::IntentReceived,
            Some(this_intent.intent_id.clone()),
            serde_json::json!({
                "agent_id": this_intent.principal.agent_id,
                "resource_id": this_intent.resource.resource_id,
            }),
        );

        assert!(duplicate_purchase_within_24h(&this_intent, &ledger).is_none());
    }
}
