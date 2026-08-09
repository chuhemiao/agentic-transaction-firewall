use atf_core::{EvaluationContext, RiskHistorySnapshot};
use atf_intent::TransactionIntent;

use crate::error::RiskEvaluationError;
use crate::finding::RiskFinding;
use crate::rule_set::RiskRuleSet;

pub(crate) fn validate_history_binding(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    context: &EvaluationContext,
    history: &RiskHistorySnapshot,
) -> Result<(), RiskEvaluationError> {
    let rule = &rule_set.rules().duplicate_purchase;
    match (rule.enabled, history.duplicate_purchase()) {
        (false, None) => Ok(()),
        (false, Some(_)) => Err(binding(
            "disabled duplicate-purchase rule received query data",
        )),
        (true, None) => Err(binding("enabled duplicate-purchase rule lacks query data")),
        (true, Some(snapshot)) => {
            let query = snapshot.query();
            if query.organization_id() != intent.principal.organization_id
                || query.agent_id() != intent.principal.agent_id
                || query.resource_id() != intent.resource.resource_id
                || query.current_intent_id() != intent.intent_id
                || query.evaluation_time() != context.evaluation_time()
                || query.window_seconds() != rule.window_seconds
                || query.accounting_boundary() != rule.accounting_boundary
            {
                return Err(binding(
                    "duplicate-purchase query does not match Intent, Context, or Rule Set",
                ));
            }
            Ok(())
        }
    }
}

pub(crate) fn history_findings(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    history: &RiskHistorySnapshot,
) -> Vec<RiskFinding> {
    let rule = &rule_set.rules().duplicate_purchase;
    let Some(prior) = history
        .duplicate_purchase()
        .and_then(|snapshot| snapshot.result())
    else {
        return Vec::new();
    };
    vec![RiskFinding {
        code: "DUPLICATE_PURCHASE".into(),
        severity: rule.severity,
        message: format!(
            "Agent `{}` previously crossed the {:?} boundary for resource `{}` at {} (intent {}), within {} seconds",
            intent.principal.agent_id,
            rule.accounting_boundary,
            intent.resource.resource_id,
            prior.occurred_at(),
            prior.intent_id(),
            rule.window_seconds,
        ),
    }]
}

fn binding(reason: impl Into<String>) -> RiskEvaluationError {
    RiskEvaluationError::HistoryBinding(reason.into())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use atf_core::{
        AccountingBoundary, DuplicatePurchaseHistory, DuplicatePurchaseMatch,
        DuplicatePurchaseQuery, RepositorySnapshot, RiskHistorySnapshot, Timestamp,
    };
    use atf_intent::{Action, Mandate, Principal, Resource, Transaction};

    use super::*;
    use atf_core::Amount;

    fn at(value: &str) -> Timestamp {
        Timestamp::from_str(value).unwrap()
    }

    fn intent() -> TransactionIntent {
        TransactionIntent {
            spec_version: "1.0".into(),
            intent_id: "01J0000000000000000000NOW0".into(),
            idempotency_key: "idem-now".into(),
            created_at: at("2026-08-09T11:59:00Z"),
            expires_at: at("2026-08-09T12:05:00Z"),
            principal: Principal {
                organization_id: "alpha-lab".into(),
                user_id: None,
                agent_id: "agent-a".into(),
                agent_version: None,
                strategy_id: None,
            },
            mandate: Mandate {
                mandate_id: "mandate-a".into(),
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
                resource_id: "dataset-a".into(),
                resource_type: Some("dataset".into()),
            },
            transaction: Transaction {
                network: "eip155:8453".into(),
                asset: "eip155:8453/slip44:60".into(),
                amount: Amount::from_str("1.00").unwrap(),
                destination: Some("eip155:8453:0x1111111111111111111111111111111111111111".into()),
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

    #[test]
    fn duplicate_finding_consumes_only_the_recorded_bounded_result() {
        let intent = intent();
        let rule_set = RiskRuleSet::default();
        let query = DuplicatePurchaseQuery::new(
            "alpha-lab",
            "agent-a",
            "dataset-a",
            &intent.intent_id,
            at("2026-08-09T12:00:00Z"),
            86_400,
            AccountingBoundary::Permitted,
        )
        .unwrap();
        let prior = DuplicatePurchaseMatch::new(
            "01J0000000000000000000OLD0",
            "01J0000000000000000000DEC0",
            "01J0000000000000000000EVT0",
            8,
            at("2026-08-09T11:00:00Z"),
        )
        .unwrap();
        let history = RiskHistorySnapshot::new(
            RepositorySnapshot::new("audit-chain:alpha-lab:10", 10, "a".repeat(64)).unwrap(),
            Some(DuplicatePurchaseHistory::new(query, Some(prior)).unwrap()),
        )
        .unwrap();

        let findings = history_findings(&intent, &rule_set, &history);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "DUPLICATE_PURCHASE");
    }
}
