use atf_core::{Amount, DestinationNormalization, EvaluationContext, RiskHistorySnapshot};
use atf_intent::{normalize_destination, TransactionIntent};

use crate::context::{RiskContext, RiskContextIssue};
use crate::error::RiskEvaluationError;
use crate::finding::RiskFinding;
use crate::rule_set::{MissingDataBehavior, RiskRuleSet};

pub(crate) fn validate_history_binding(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    context: &EvaluationContext,
    history: &RiskHistorySnapshot,
) -> Result<(), RiskEvaluationError> {
    let duplicate_rule = &rule_set.rules().duplicate_purchase;
    match (duplicate_rule.enabled, history.duplicate_purchase()) {
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
                || query.window_seconds() != duplicate_rule.window_seconds
                || query.accounting_boundary() != duplicate_rule.accounting_boundary
            {
                return Err(binding(
                    "duplicate-purchase query does not match Intent, Context, or Rule Set",
                ));
            }
            Ok(())
        }
    }?;

    let daily_rule = rule_set.rules().daily_cumulative_spend.as_ref();
    match (
        daily_rule.is_some_and(|rule| rule.enabled),
        history.daily_cumulative_spend(),
    ) {
        (false, None) => Ok(()),
        (false, Some(_)) => Err(binding("disabled daily-spend rule received query data")),
        (true, None) => Err(binding("enabled daily-spend rule lacks query data")),
        (true, Some(snapshot)) => {
            let rule = daily_rule.expect("enabled daily-spend rule is present");
            let query = snapshot.query();
            if query.organization_id() != intent.principal.organization_id
                || query.agent_id() != intent.principal.agent_id
                || query.current_intent_id() != intent.intent_id
                || query.valuation_asset() != rule.valuation_asset
                || query.evaluation_time() != context.evaluation_time()
                || query.window_seconds() != rule.window_seconds
                || query.accounting_boundary() != rule.accounting_boundary
            {
                return Err(binding(
                    "daily-spend query does not match Intent, Context, or Rule Set",
                ));
            }
            Ok(())
        }
    }?;

    let first_rule = rule_set.rules().first_time_destination.as_ref();
    match (
        first_rule.is_some_and(|rule| rule.enabled),
        history.first_destination(),
    ) {
        (false, None) => Ok(()),
        (false, Some(_)) => Err(binding(
            "disabled first-destination rule received query data",
        )),
        (true, None) => Err(binding("enabled first-destination rule lacks query data")),
        (true, Some(snapshot)) => {
            let rule = first_rule.expect("enabled first-destination rule is present");
            let query = snapshot.query();
            let expected_destination = destination_normalization(intent)?;
            if query.organization_id() != intent.principal.organization_id
                || query.current_intent_id() != intent.intent_id
                || query.profile_id() != context.profile_id()
                || query.profile_version() != context.profile_version()
                || query.normalizer_id() != rule.normalizer_id
                || query.normalizer_version() != rule.normalizer_version
                || query.destination() != &expected_destination
                || query.evaluation_time() != context.evaluation_time()
                || query.accounting_boundary() != rule.accounting_boundary
            {
                return Err(binding(
                    "first-destination query does not match Intent, Context, or Rule Set",
                ));
            }
            Ok(())
        }
    }
}

pub(crate) fn history_findings(
    intent: &TransactionIntent,
    context: &RiskContext,
    rule_set: &RiskRuleSet,
    history: &RiskHistorySnapshot,
) -> Vec<RiskFinding> {
    let mut findings = Vec::new();
    findings.extend(duplicate_finding(intent, rule_set, history));
    findings.extend(first_destination_finding(rule_set, history));

    let Some(rule) = rule_set
        .rules()
        .daily_cumulative_spend
        .as_ref()
        .filter(|rule| rule.enabled)
    else {
        return findings;
    };
    let snapshot = history
        .daily_cumulative_spend()
        .expect("history binding requires enabled daily-spend query data");
    if snapshot.unresolved_asset_decision_count() > 0 {
        push_missing(
            &mut findings,
            rule.missing_data,
            rule.severity,
            "DAILY_SPEND_HISTORY_INSUFFICIENT_DATA",
            format!(
                "{} prior permitted Decision(s) lack a bound asset and cannot be valued",
                snapshot.unresolved_asset_decision_count()
            ),
        );
        return findings;
    }

    let mut cumulative = match value_in_asset(
        intent,
        context,
        &intent.transaction.asset,
        intent.transaction.amount,
        &rule.valuation_asset,
    ) {
        Ok(value) => value,
        Err(issue) => {
            push_quote_issue(&mut findings, rule, &intent.transaction.asset, issue);
            return findings;
        }
    };
    for total in snapshot.totals() {
        let converted = match value_in_asset(
            intent,
            context,
            total.asset(),
            total.amount(),
            &rule.valuation_asset,
        ) {
            Ok(value) => value,
            Err(issue) => {
                push_quote_issue(&mut findings, rule, total.asset(), issue);
                return findings;
            }
        };
        let Some(next) = cumulative.checked_add(converted) else {
            push_missing(
                &mut findings,
                rule.missing_data,
                rule.severity,
                "DAILY_SPEND_ARITHMETIC_INSUFFICIENT_DATA",
                "daily cumulative-spend fixed-point addition overflowed",
            );
            return findings;
        };
        cumulative = next;
    }
    if cumulative > rule.max_amount {
        findings.push(RiskFinding {
            code: "DAILY_CUMULATIVE_SPEND_EXCEEDED".into(),
            severity: rule.severity,
            message: format!(
                "Agent `{}` cumulative {:?} spend is {} {}, over the configured limit of {} within {} seconds",
                intent.principal.agent_id,
                rule.accounting_boundary,
                cumulative,
                rule.valuation_asset,
                rule.max_amount,
                rule.window_seconds,
            ),
        });
    }
    findings
}

fn destination_normalization(
    intent: &TransactionIntent,
) -> Result<DestinationNormalization, RiskEvaluationError> {
    match normalize_destination(intent) {
        Ok(destination) => DestinationNormalization::available(destination.value()),
        Err(error) => DestinationNormalization::unavailable(error.code()),
    }
    .map_err(|error| binding(error.to_string()))
}

fn first_destination_finding(
    rule_set: &RiskRuleSet,
    history: &RiskHistorySnapshot,
) -> Option<RiskFinding> {
    let rule = rule_set
        .rules()
        .first_time_destination
        .as_ref()
        .filter(|rule| rule.enabled)?;
    let snapshot = history
        .first_destination()
        .expect("history binding requires enabled first-destination query data");
    if let Some(reason_code) = snapshot.query().destination().reason_code() {
        return (rule.missing_data == MissingDataBehavior::Finding).then(|| RiskFinding {
            code: "FIRST_DESTINATION_NORMALIZATION_FAILED".into(),
            severity: rule.severity,
            message: format!(
                "destination familiarity cannot be established with normalizer {}@{}: {reason_code}",
                rule.normalizer_id, rule.normalizer_version
            ),
        });
    }
    snapshot.result().is_none().then(|| RiskFinding {
        code: "FIRST_TIME_DESTINATION".into(),
        severity: rule.severity,
        message: format!(
            "organization has no prior {:?} Decision for this normalized destination under {}@{}",
            rule.accounting_boundary, rule.normalizer_id, rule.normalizer_version
        ),
    })
}

fn duplicate_finding(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    history: &RiskHistorySnapshot,
) -> Option<RiskFinding> {
    let duplicate_rule = &rule_set.rules().duplicate_purchase;
    history
        .duplicate_purchase()
        .and_then(|snapshot| snapshot.result())
        .map(|prior| RiskFinding {
            code: "DUPLICATE_PURCHASE".into(),
            severity: duplicate_rule.severity,
            message: format!(
                "Agent `{}` previously crossed the {:?} boundary for resource `{}` at {} (intent {}), within {} seconds",
                intent.principal.agent_id,
                duplicate_rule.accounting_boundary,
                intent.resource.resource_id,
                prior.occurred_at(),
                prior.intent_id(),
                duplicate_rule.window_seconds,
            ),
        })
}

fn value_in_asset(
    intent: &TransactionIntent,
    context: &RiskContext,
    source_asset: &str,
    amount: Amount,
    valuation_asset: &str,
) -> Result<Amount, RiskContextIssue> {
    if source_asset == valuation_asset {
        return Ok(amount);
    }
    let rate = context.asset_quote(intent, source_asset, valuation_asset)?;
    amount
        .checked_mul_exact(rate)
        .ok_or(RiskContextIssue::ValueInvalid)
}

fn push_quote_issue(
    findings: &mut Vec<RiskFinding>,
    rule: &crate::rule_set::DailySpendRule,
    source_asset: &str,
    issue: RiskContextIssue,
) {
    let code = if issue == RiskContextIssue::Missing {
        "DAILY_SPEND_QUOTE_MISSING"
    } else {
        "DAILY_SPEND_QUOTE_INSUFFICIENT_DATA"
    };
    push_missing(
        findings,
        rule.missing_data,
        rule.severity,
        code,
        format!(
            "trusted direct quote from `{source_asset}` to `{}` is unavailable or unusable: {}",
            rule.valuation_asset,
            issue.code()
        ),
    );
}

fn push_missing(
    findings: &mut Vec<RiskFinding>,
    behavior: MissingDataBehavior,
    severity: crate::Severity,
    code: &'static str,
    message: impl Into<String>,
) {
    if behavior == MissingDataBehavior::Finding {
        findings.push(RiskFinding {
            code: code.into(),
            severity,
            message: message.into(),
        });
    }
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

        let finding = duplicate_finding(&intent, &rule_set, &history).unwrap();
        assert_eq!(finding.code, "DUPLICATE_PURCHASE");
    }
}
