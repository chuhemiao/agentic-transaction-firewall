use std::str::FromStr;

use atf_audit::AuditLedger;
use atf_core::{Amount, Timestamp};
use atf_intent::TransactionIntent;
use rust_decimal::Decimal;

use crate::config::RiskConfig;
use crate::finding::RiskFinding;
use crate::history_rules;
use crate::severity::Severity;

/// Run every stateless MVP rule against `intent` and return the findings
/// that fired.
///
/// This is a deliberately small, *stateless* rule set (PRD §12.1: "确定性优先"):
/// every rule here can be decided from the Intent (plus `now`) alone, with no
/// database, history, or external service lookup. Rules that need history —
/// duplicate purchase, daily cumulative spend, first-time address, order
/// frequency (PRD §12.2) — are `evaluate_with_history`'s job instead.
pub fn evaluate(intent: &TransactionIntent, config: &RiskConfig) -> Vec<RiskFinding> {
    let now = Timestamp::now();
    [
        request_expired(intent, now),
        single_amount_cap(intent, config),
        max_fee_ratio(intent, config),
        vendor_price_deviation(intent, config),
        high_risk_network_or_protocol(intent, config),
    ]
    .into_iter()
    .flatten()
    .collect()
}

/// Everything `evaluate` does, plus the history-dependent rules in
/// `history_rules` that need to look at prior events in `ledger` (PRD
/// §12.2). Callers that don't have a ledger (e.g. `atf-cli evaluate`, which
/// is a one-shot local tool) should keep using `evaluate` instead —
/// `services/gateway` is the reference caller of this function.
pub fn evaluate_with_history(
    intent: &TransactionIntent,
    config: &RiskConfig,
    ledger: &AuditLedger,
) -> Vec<RiskFinding> {
    let mut findings = evaluate(intent, config);
    findings.extend(history_rules::history_findings(intent, ledger));
    findings
}

fn request_expired(intent: &TransactionIntent, now: Timestamp) -> Option<RiskFinding> {
    (intent.expires_at < now).then(|| RiskFinding {
        code: "REQUEST_EXPIRED".to_string(),
        severity: Severity::Critical,
        message: format!("Intent expired at {} (now {now})", intent.expires_at),
    })
}

fn single_amount_cap(intent: &TransactionIntent, config: &RiskConfig) -> Option<RiskFinding> {
    let cap = config.max_single_amount?;
    (intent.transaction.amount.as_decimal() > cap.as_decimal()).then(|| RiskFinding {
        code: "SINGLE_AMOUNT_CAP_EXCEEDED".to_string(),
        severity: Severity::High,
        message: format!(
            "Amount {} exceeds the configured single-transaction cap of {cap}",
            intent.transaction.amount
        ),
    })
}

fn max_fee_ratio(intent: &TransactionIntent, config: &RiskConfig) -> Option<RiskFinding> {
    let threshold_bps = config.max_fee_ratio_bps?;
    let max_fee = intent.transaction.max_fee?;
    let amount = intent.transaction.amount.as_decimal();
    if amount.is_zero() {
        return None;
    }
    let ratio_bps = ((max_fee.as_decimal() / amount) * Decimal::from(10_000)).round_dp(2);
    (ratio_bps > Decimal::from(threshold_bps)).then(|| RiskFinding {
        code: "FEE_RATIO_TOO_HIGH".to_string(),
        severity: Severity::High,
        message: format!(
            "max_fee {max_fee} is {ratio_bps} bps of amount {}, over the {threshold_bps} bps threshold",
            intent.transaction.amount
        ),
    })
}

fn vendor_price_deviation(intent: &TransactionIntent, config: &RiskConfig) -> Option<RiskFinding> {
    let threshold_bps = config.vendor_price_deviation_bps?;
    let median = intent
        .context
        .get("historical_vendor_median")
        .and_then(|v| v.as_str())
        .and_then(|s| Amount::from_str(s).ok())?
        .as_decimal();
    if median.is_zero() {
        return None;
    }
    let amount = intent.transaction.amount.as_decimal();
    let deviation_bps = (((amount - median).abs() / median) * Decimal::from(10_000)).round_dp(2);
    (deviation_bps > Decimal::from(threshold_bps)).then(|| RiskFinding {
        code: "VENDOR_PRICE_DEVIATION".to_string(),
        severity: Severity::High,
        message: format!(
            "Amount {} deviates from the historical vendor median {median} by {deviation_bps} bps, over the {threshold_bps} bps threshold",
            intent.transaction.amount
        ),
    })
}

fn high_risk_network_or_protocol(
    intent: &TransactionIntent,
    config: &RiskConfig,
) -> Option<RiskFinding> {
    let network_flagged = config
        .high_risk_networks
        .iter()
        .any(|n| n.eq_ignore_ascii_case(&intent.transaction.network));
    let protocol_flagged = config
        .high_risk_protocols
        .iter()
        .any(|p| p.eq_ignore_ascii_case(&intent.resource.protocol));
    (network_flagged || protocol_flagged).then(|| RiskFinding {
        code: "HIGH_RISK_NETWORK_OR_PROTOCOL".to_string(),
        severity: Severity::High,
        message: format!(
            "network `{}` or protocol `{}` is on the configured high-risk list",
            intent.transaction.network, intent.resource.protocol
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use atf_intent::{Action, Mandate, Principal, Resource, Transaction};

    fn base_intent() -> TransactionIntent {
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
                amount: Amount::from_str("12.50").unwrap(),
                destination: None,
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
    fn flags_expired_requests_as_critical() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2000-01-01T00:00:00Z").unwrap();
        let findings = evaluate(&intent, &RiskConfig::default());
        assert!(findings
            .iter()
            .any(|f| f.code == "REQUEST_EXPIRED" && f.severity == Severity::Critical));
    }

    #[test]
    fn does_not_flag_a_future_request() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        let findings = evaluate(&intent, &RiskConfig::default());
        assert!(!findings.iter().any(|f| f.code == "REQUEST_EXPIRED"));
    }

    #[test]
    fn single_amount_cap_disabled_by_default() {
        let intent = base_intent();
        let findings = evaluate(&intent, &RiskConfig::default());
        assert!(!findings
            .iter()
            .any(|f| f.code == "SINGLE_AMOUNT_CAP_EXCEEDED"));
    }

    #[test]
    fn single_amount_cap_fires_when_configured() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        let config = RiskConfig {
            max_single_amount: Some(Amount::from_str("10.00").unwrap()),
            ..RiskConfig::default()
        };
        let findings = evaluate(&intent, &config);
        assert!(findings
            .iter()
            .any(|f| f.code == "SINGLE_AMOUNT_CAP_EXCEEDED"));
    }

    #[test]
    fn flags_disproportionate_fee() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        intent.transaction.max_fee = Some(Amount::from_str("5.00").unwrap()); // 40% of 12.50
        let findings = evaluate(&intent, &RiskConfig::default());
        assert!(findings.iter().any(|f| f.code == "FEE_RATIO_TOO_HIGH"));
    }

    #[test]
    fn flags_vendor_price_deviation_from_context() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        intent.context = serde_json::json!({"historical_vendor_median": "8.50"});
        // (12.50 - 8.50) / 8.50 = ~47%, over the 30% default threshold.
        let findings = evaluate(&intent, &RiskConfig::default());
        assert!(findings.iter().any(|f| f.code == "VENDOR_PRICE_DEVIATION"));
    }

    #[test]
    fn does_not_flag_vendor_price_within_threshold() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        intent.context = serde_json::json!({"historical_vendor_median": "12.00"});
        // (12.50 - 12.00) / 12.00 = ~4%, well under the 30% default threshold.
        let findings = evaluate(&intent, &RiskConfig::default());
        assert!(!findings.iter().any(|f| f.code == "VENDOR_PRICE_DEVIATION"));
    }

    #[test]
    fn flags_high_risk_network() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        let config = RiskConfig {
            high_risk_networks: vec!["BASE".to_string()],
            ..RiskConfig::default()
        };
        let findings = evaluate(&intent, &config);
        assert!(findings
            .iter()
            .any(|f| f.code == "HIGH_RISK_NETWORK_OR_PROTOCOL"));
    }
}
