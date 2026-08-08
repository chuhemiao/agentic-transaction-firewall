#[cfg(test)]
use std::str::FromStr;

use atf_audit::{AuditEvent, AuditLedger};
#[cfg(test)]
use atf_core::Amount;
use atf_core::Timestamp;
use atf_intent::TransactionIntent;
use rust_decimal::Decimal;

use crate::finding::RiskFinding;
use crate::history_rules;
use crate::rule_set::{MissingDataBehavior, RiskEvaluation, RiskRuleSet};
use crate::severity::Severity;
use crate::{RiskContext, RiskContextIssue};

/// Run every stateless MVP rule against `intent` and return the findings
/// that fired.
///
/// This is a deliberately small, *stateless* rule set (PRD §12.1: "确定性优先"):
/// every rule here can be decided from the Intent (plus `now`) alone, with no
/// database, history, or external service lookup. Rules that need history —
/// duplicate purchase, daily cumulative spend, first-time address, order
/// frequency (PRD §12.2) — are `evaluate_with_history`'s job instead.
pub fn evaluate(intent: &TransactionIntent, rule_set: &RiskRuleSet) -> RiskEvaluation {
    evaluate_at(intent, rule_set, Timestamp::now())
}

/// Evaluate stateless rules at one caller-selected time. DS-023 will place
/// this timestamp inside the immutable Evaluation Context; exposing it now
/// prevents individual rules from sampling different clocks.
pub fn evaluate_at(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    evaluated_at: Timestamp,
) -> RiskEvaluation {
    let context = RiskContext::agent_only(intent);
    evaluate_with_context_at(intent, rule_set, &context, evaluated_at)
}

pub fn evaluate_with_context_at(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    context: &RiskContext,
    evaluated_at: Timestamp,
) -> RiskEvaluation {
    let rules = rule_set.rules();
    let findings = [
        request_expired(intent, &rules.request_expired, evaluated_at),
        single_amount_cap(intent, &rules.single_amount_cap),
        max_fee_ratio(intent, &rules.max_fee_ratio),
        vendor_price_deviation(intent, context, &rules.vendor_price_deviation),
        high_risk_network_or_protocol(intent, &rules.high_risk_network_or_protocol),
    ]
    .into_iter()
    .flatten()
    .collect();
    rule_set.evaluation(findings)
}

/// Everything [`evaluate`] does, plus configured history-dependent rules.
pub fn evaluate_with_history(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    ledger: &AuditLedger,
) -> RiskEvaluation {
    evaluate_with_history_at(intent, rule_set, ledger, Timestamp::now())
}

pub fn evaluate_with_history_at(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    ledger: &AuditLedger,
    evaluated_at: Timestamp,
) -> RiskEvaluation {
    evaluate_with_events_at(intent, rule_set, ledger.iter(), evaluated_at)
}

/// Evaluate against Audit events that were loaded and verified by a durable
/// store. This keeps history authority outside the Risk crate.
pub fn evaluate_with_events<'a>(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    events: impl IntoIterator<Item = &'a AuditEvent>,
) -> RiskEvaluation {
    evaluate_with_events_at(intent, rule_set, events, Timestamp::now())
}

pub fn evaluate_with_events_at<'a>(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    events: impl IntoIterator<Item = &'a AuditEvent>,
    evaluated_at: Timestamp,
) -> RiskEvaluation {
    let context = RiskContext::agent_only(intent);
    evaluate_with_events_and_context_at(intent, rule_set, &context, events, evaluated_at)
}

pub fn evaluate_with_events_and_context_at<'a>(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    context: &RiskContext,
    events: impl IntoIterator<Item = &'a AuditEvent>,
    evaluated_at: Timestamp,
) -> RiskEvaluation {
    let mut result = evaluate_with_context_at(intent, rule_set, context, evaluated_at);
    result
        .findings
        .extend(history_rules::history_findings_from_events(
            intent,
            rule_set,
            events,
            evaluated_at,
        ));
    result
}

fn request_expired(
    intent: &TransactionIntent,
    rule: &crate::rule_set::ToggleRule,
    now: Timestamp,
) -> Option<RiskFinding> {
    (rule.enabled && intent.expires_at < now).then(|| RiskFinding {
        code: "REQUEST_EXPIRED".to_string(),
        severity: rule.severity,
        message: format!("Intent expired at {} (now {now})", intent.expires_at),
    })
}

fn single_amount_cap(
    intent: &TransactionIntent,
    rule: &crate::rule_set::AmountCapRule,
) -> Option<RiskFinding> {
    if !rule.enabled {
        return None;
    }
    let cap = rule
        .max_amount
        .expect("validated enabled amount-cap rules have a maximum");
    (intent.transaction.amount.as_decimal() > cap.as_decimal()).then(|| RiskFinding {
        code: "SINGLE_AMOUNT_CAP_EXCEEDED".to_string(),
        severity: rule.severity,
        message: format!(
            "Amount {} exceeds the configured single-transaction cap of {cap}",
            intent.transaction.amount
        ),
    })
}

fn max_fee_ratio(
    intent: &TransactionIntent,
    rule: &crate::rule_set::BasisPointRule,
) -> Option<RiskFinding> {
    if !rule.enabled {
        return None;
    }
    let Some(max_fee) = intent.transaction.max_fee else {
        return missing_finding(
            rule.missing_data,
            rule.severity,
            "MAX_FEE_DATA_MISSING",
            "max_fee is unavailable for the enabled fee-ratio rule",
        );
    };
    let amount = intent.transaction.amount.as_decimal();
    if amount.is_zero() {
        return missing_finding(
            rule.missing_data,
            rule.severity,
            "MAX_FEE_DATA_MISSING",
            "amount is zero for the enabled fee-ratio rule",
        );
    }
    let ratio_bps = ((max_fee.as_decimal() / amount) * Decimal::from(10_000)).round_dp(2);
    (ratio_bps > Decimal::from(rule.threshold_bps)).then(|| RiskFinding {
        code: "FEE_RATIO_TOO_HIGH".to_string(),
        severity: rule.severity,
        message: format!(
            "max_fee {max_fee} is {ratio_bps} bps of amount {}, over the {} bps threshold",
            intent.transaction.amount, rule.threshold_bps
        ),
    })
}

fn vendor_price_deviation(
    intent: &TransactionIntent,
    context: &RiskContext,
    rule: &crate::rule_set::BasisPointRule,
) -> Option<RiskFinding> {
    if !rule.enabled {
        return None;
    }
    let median = match context.historical_vendor_median(intent) {
        Ok(amount) => amount.as_decimal(),
        Err(RiskContextIssue::Missing) => {
            return missing_finding(
                rule.missing_data,
                rule.severity,
                "VENDOR_PRICE_DATA_MISSING",
                "trusted historical_vendor_median evidence is unavailable for the enabled price-deviation rule",
            );
        }
        Err(issue) => {
            return Some(RiskFinding {
                code: "VENDOR_PRICE_INSUFFICIENT_DATA".into(),
                severity: rule.severity,
                message: format!(
                    "trusted historical_vendor_median evidence was rejected: {}",
                    issue.code()
                ),
            });
        }
    };
    let amount = intent.transaction.amount.as_decimal();
    let deviation_bps = (((amount - median).abs() / median) * Decimal::from(10_000)).round_dp(2);
    (deviation_bps > Decimal::from(rule.threshold_bps)).then(|| RiskFinding {
        code: "VENDOR_PRICE_DEVIATION".to_string(),
        severity: rule.severity,
        message: format!(
            "Amount {} deviates from the historical vendor median {median} by {deviation_bps} bps, over the {} bps threshold",
            intent.transaction.amount, rule.threshold_bps
        ),
    })
}

fn high_risk_network_or_protocol(
    intent: &TransactionIntent,
    rule: &crate::rule_set::DenyListRule,
) -> Option<RiskFinding> {
    if !rule.enabled {
        return None;
    }
    let network_flagged = rule
        .networks
        .iter()
        .any(|network| network.eq_ignore_ascii_case(&intent.transaction.network));
    let protocol_flagged = rule
        .protocols
        .iter()
        .any(|protocol| protocol.eq_ignore_ascii_case(&intent.resource.protocol));
    (network_flagged || protocol_flagged).then(|| RiskFinding {
        code: "HIGH_RISK_NETWORK_OR_PROTOCOL".to_string(),
        severity: rule.severity,
        message: format!(
            "network `{}` or protocol `{}` is on the configured high-risk list",
            intent.transaction.network, intent.resource.protocol
        ),
    })
}

fn missing_finding(
    behavior: MissingDataBehavior,
    severity: Severity,
    code: &'static str,
    message: &'static str,
) -> Option<RiskFinding> {
    (behavior == MissingDataBehavior::Finding).then(|| RiskFinding {
        code: code.into(),
        severity,
        message: message.into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use atf_audit::{EventType, NewAuditEvent};
    use atf_intent::{Action, Mandate, Principal, Resource, Transaction};

    fn configured_rule_set(pointer: &str, value: serde_json::Value) -> RiskRuleSet {
        let mut document: serde_json::Value =
            serde_json::from_str(include_str!("../../../risk-rules/default.json")).unwrap();
        *document.pointer_mut(pointer).unwrap() = value;
        RiskRuleSet::from_json(&document.to_string()).unwrap()
    }

    fn base_intent() -> TransactionIntent {
        TransactionIntent {
            spec_version: "1.0".into(),
            intent_id: "01J00000000000000000000000".into(),
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
                network: "eip155:8453".into(),
                asset: "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".into(),
                amount: Amount::from_str("12.50").unwrap(),
                destination: Some("eip155:8453:0x1111111111111111111111111111111111111111".into()),
                contract: None,
                calldata_hash: None,
                max_fee: Some(Amount::from_str("0.25").unwrap()),
                slippage_bps: None,
                leverage: None,
            },
            context: serde_json::json!({}),
            metadata: serde_json::json!({}),
        }
    }

    #[test]
    fn verified_audit_events_can_drive_history_without_a_process_ledger() {
        let mut intent = base_intent();
        intent.intent_id = "01J0000000000000000000N200".into();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        let prior = NewAuditEvent::new(
            EventType::DecisionRecorded,
            Timestamp::now(),
            Some("01J0000000000000000000N100".into()),
            serde_json::json!({
                "decision": "PERMIT",
                "organization_id": "alpha-lab",
                "agent_id": "research-agent-01",
                "resource_id": "btc-orderbook-2026-07-01",
            }),
        )
        .chain(None);

        let findings = evaluate_with_events(&intent, &RiskRuleSet::default(), [&prior]);

        assert!(findings
            .iter()
            .any(|finding| finding.code == "DUPLICATE_PURCHASE"));
    }

    #[test]
    fn flags_expired_requests_as_critical() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2000-01-01T00:00:00Z").unwrap();
        let findings = evaluate(&intent, &RiskRuleSet::default());
        assert!(findings
            .iter()
            .any(|f| f.code == "REQUEST_EXPIRED" && f.severity == Severity::Critical));
    }

    #[test]
    fn does_not_flag_a_future_request() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        let findings = evaluate(&intent, &RiskRuleSet::default());
        assert!(!findings.iter().any(|f| f.code == "REQUEST_EXPIRED"));
    }

    #[test]
    fn single_amount_cap_disabled_by_default() {
        let intent = base_intent();
        let findings = evaluate(&intent, &RiskRuleSet::default());
        assert!(!findings
            .iter()
            .any(|f| f.code == "SINGLE_AMOUNT_CAP_EXCEEDED"));
    }

    #[test]
    fn single_amount_cap_fires_when_configured() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        let mut document: serde_json::Value =
            serde_json::from_str(include_str!("../../../risk-rules/default.json")).unwrap();
        document["rules"]["single_amount_cap"]["enabled"] = serde_json::json!(true);
        document["rules"]["single_amount_cap"]["max_amount"] = serde_json::json!("10.00");
        let rule_set = RiskRuleSet::from_json(&document.to_string()).unwrap();
        let findings = evaluate(&intent, &rule_set);
        assert!(findings
            .iter()
            .any(|f| f.code == "SINGLE_AMOUNT_CAP_EXCEEDED"));
    }

    #[test]
    fn flags_disproportionate_fee() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        intent.transaction.max_fee = Some(Amount::from_str("5.00").unwrap()); // 40% of 12.50
        let findings = evaluate(&intent, &RiskRuleSet::default());
        assert!(findings.iter().any(|f| f.code == "FEE_RATIO_TOO_HIGH"));
    }

    #[test]
    fn rejects_agent_vendor_price_context_as_insufficient_data() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        intent.context = serde_json::json!({"historical_vendor_median": "8.50"});
        // (12.50 - 8.50) / 8.50 = ~47%, over the 30% default threshold.
        let findings = evaluate(&intent, &RiskRuleSet::default());
        assert!(findings
            .iter()
            .any(|f| f.code == "VENDOR_PRICE_INSUFFICIENT_DATA"));
        assert!(!findings.iter().any(|f| f.code == "VENDOR_PRICE_DEVIATION"));
    }

    #[test]
    fn agent_vendor_price_cannot_silently_suppress_review() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        intent.context = serde_json::json!({"historical_vendor_median": "12.00"});
        // (12.50 - 12.00) / 12.00 = ~4%, well under the 30% default threshold.
        let findings = evaluate(&intent, &RiskRuleSet::default());
        assert!(findings
            .iter()
            .any(|f| f.code == "VENDOR_PRICE_INSUFFICIENT_DATA"));
        assert!(!findings.iter().any(|f| f.code == "VENDOR_PRICE_DEVIATION"));
    }

    #[test]
    fn flags_high_risk_network() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        let rule_set = configured_rule_set(
            "/rules/high_risk_network_or_protocol/networks",
            serde_json::json!(["eip155:8453"]),
        );
        let findings = evaluate(&intent, &rule_set);
        assert!(findings
            .iter()
            .any(|f| f.code == "HIGH_RISK_NETWORK_OR_PROTOCOL"));
    }

    #[test]
    fn every_evaluation_returns_the_exact_rule_set_identity() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        let rule_set = RiskRuleSet::default();

        let result = evaluate_at(
            &intent,
            &rule_set,
            Timestamp::from_str("2026-07-18T08:01:00Z").unwrap(),
        );

        assert_eq!(result.rule_set_version, rule_set.version());
        assert_eq!(result.rule_set_hash, rule_set.rule_set_hash());
    }

    #[test]
    fn configured_missing_data_behavior_is_executable_not_only_metadata() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        intent.transaction.max_fee = None;
        let strict = evaluate_at(
            &intent,
            &RiskRuleSet::default(),
            Timestamp::from_str("2026-07-18T08:01:00Z").unwrap(),
        );
        assert!(strict
            .iter()
            .any(|finding| finding.code == "MAX_FEE_DATA_MISSING"));

        let permissive_rule_set = configured_rule_set(
            "/rules/max_fee_ratio/missing_data",
            serde_json::json!("NOT_APPLICABLE"),
        );
        let permissive = evaluate_at(
            &intent,
            &permissive_rule_set,
            Timestamp::from_str("2026-07-18T08:01:00Z").unwrap(),
        );
        assert!(!permissive
            .iter()
            .any(|finding| finding.code == "MAX_FEE_DATA_MISSING"));
    }

    #[test]
    fn every_declared_accounting_boundary_selects_its_exact_lifecycle_fact() {
        let prior_intent_id = "01J0000000000000000000H100";
        let at = Timestamp::from_str("2026-07-18T08:01:00Z").unwrap();
        let evaluated_at = Timestamp::from_str("2026-07-18T08:02:00Z").unwrap();
        let received = NewAuditEvent::new(
            EventType::IntentReceived,
            at,
            Some(prior_intent_id.into()),
            serde_json::json!({
                "organization_id": "alpha-lab",
                "agent_id": "research-agent-01",
                "resource_id": "btc-orderbook-2026-07-01"
            }),
        )
        .chain(None);
        let boundary_cases = [
            (
                "REQUESTED",
                NewAuditEvent::new(
                    EventType::IntentReceived,
                    at,
                    Some(prior_intent_id.into()),
                    received.data.clone(),
                )
                .chain(None),
            ),
            (
                "PERMITTED",
                NewAuditEvent::new(
                    EventType::DecisionRecorded,
                    at,
                    Some(prior_intent_id.into()),
                    serde_json::json!({"decision": "PERMIT"}),
                )
                .chain(None),
            ),
            (
                "EXECUTED",
                NewAuditEvent::new(
                    EventType::ExecutionConfirmed,
                    at,
                    Some(prior_intent_id.into()),
                    serde_json::json!({}),
                )
                .chain(None),
            ),
            (
                "SETTLED",
                NewAuditEvent::new(
                    EventType::SettlementVerified,
                    at,
                    Some(prior_intent_id.into()),
                    serde_json::json!({}),
                )
                .chain(None),
            ),
        ];
        let mut intent = base_intent();
        intent.intent_id = "01J0000000000000000000H200".into();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();

        for (boundary, boundary_event) in boundary_cases {
            let rule_set = configured_rule_set(
                "/rules/duplicate_purchase/accounting_boundary",
                serde_json::json!(boundary),
            );
            let result = evaluate_with_events_at(
                &intent,
                &rule_set,
                [&received, &boundary_event],
                evaluated_at,
            );
            assert!(
                result
                    .iter()
                    .any(|finding| finding.code == "DUPLICATE_PURCHASE"),
                "{boundary} must select the matching lifecycle event"
            );
        }
    }
}
