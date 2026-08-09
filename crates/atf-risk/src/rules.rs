#[cfg(test)]
use atf_core::Amount;
use atf_core::{EvaluationContext, RiskHistorySnapshot, Timestamp};
use atf_intent::{validate_profile, TransactionIntent};
use rust_decimal::Decimal;

use crate::context::{RiskContext, RiskContextIssue};
use crate::error::RiskEvaluationError;
use crate::finding::RiskFinding;
use crate::history_rules;
use crate::rule_set::{MissingDataBehavior, RiskEvaluation, RiskRuleSet};
use crate::severity::Severity;

/// Evaluate the exact Intent, Rule Set, Evidence and bounded history snapshot
/// bound by one immutable Evaluation Context. All decision-affecting inputs
/// are validated before a rule runs; a mismatch is an error and must fail
/// closed upstream.
pub fn evaluate_context(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    evaluation_context: &EvaluationContext,
    history: &RiskHistorySnapshot,
) -> Result<RiskEvaluation, RiskEvaluationError> {
    validate_context_binding(intent, rule_set, evaluation_context, history)?;
    let context = RiskContext::from_evaluation_context(intent, evaluation_context);
    let evaluated_at = evaluation_context.evaluation_time();
    let rules = rule_set.rules();
    let mut findings = [
        request_expired(intent, &rules.request_expired, evaluated_at),
        single_amount_cap(intent, &rules.single_amount_cap),
        max_fee_ratio(intent, &rules.max_fee_ratio),
        vendor_price_deviation(intent, &context, &rules.vendor_price_deviation),
        high_risk_network_or_protocol(intent, &rules.high_risk_network_or_protocol),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    findings.extend(history_rules::history_findings(
        intent, &context, rule_set, history,
    ));
    Ok(rule_set.evaluation(findings, history.clone()))
}

fn validate_context_binding(
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    context: &EvaluationContext,
    history: &RiskHistorySnapshot,
) -> Result<(), RiskEvaluationError> {
    if context.intent_id() != intent.intent_id || context.intent_hash() != intent.canonical_hash() {
        return Err(RiskEvaluationError::ContextBinding(
            "Intent ID/hash binding does not match".into(),
        ));
    }
    context.verify_agent_context(&intent.context).map_err(|_| {
        RiskEvaluationError::ContextBinding("Agent context hash does not match".into())
    })?;
    let profile = validate_profile(intent).map_err(|error| {
        RiskEvaluationError::ContextBinding(format!("Intent Profile is invalid: {error}"))
    })?;
    if context.profile_id() != profile.id() || context.profile_version() != profile.version() {
        return Err(RiskEvaluationError::ContextBinding(
            "Intent Profile binding does not match".into(),
        ));
    }
    let Some(actual) = context.risk().available_parts() else {
        return Err(RiskEvaluationError::RuleSetUnavailable);
    };
    let expected = (
        rule_set.engine_version(),
        rule_set.version(),
        rule_set.rule_set_hash(),
    );
    if actual != expected {
        return Err(RiskEvaluationError::RuleSetMismatch);
    }

    history
        .validate()
        .map_err(|error| RiskEvaluationError::HistoryBinding(error.to_string()))?;
    if history.repository() != context.history() {
        return Err(RiskEvaluationError::HistoryBinding(
            "repository snapshot does not match Evaluation Context".into(),
        ));
    }
    history_rules::validate_history_binding(intent, rule_set, context, history)?;
    Ok(())
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
    use atf_core::{
        AccountingBoundary, DailySpendHistory, DailySpendQuery, DestinationNormalization,
        DuplicatePurchaseHistory, DuplicatePurchaseMatch, DuplicatePurchaseQuery,
        EvaluationContextInput, EvidenceTrustPolicyReference, ExternalSnapshotReference,
        FirstDestinationHistory, FirstDestinationQuery, RepositorySnapshot,
        RequestFrequencyHistory, RequestFrequencyQuery, RiskHistorySnapshot, SimulationReference,
        VersionedArtifactReference,
    };
    use atf_intent::{normalize_destination, Action, Mandate, Principal, Resource, Transaction};
    use std::str::FromStr;

    fn default_evaluation_time() -> Timestamp {
        Timestamp::from_str("2026-08-08T12:00:00Z").unwrap()
    }

    fn evaluate(intent: &TransactionIntent, rule_set: &RiskRuleSet) -> RiskEvaluation {
        evaluate_at(intent, rule_set, default_evaluation_time())
    }

    fn evaluate_at(
        intent: &TransactionIntent,
        rule_set: &RiskRuleSet,
        evaluated_at: Timestamp,
    ) -> RiskEvaluation {
        evaluate_with_match_at(intent, rule_set, None, evaluated_at)
    }

    fn evaluate_with_match(
        intent: &TransactionIntent,
        rule_set: &RiskRuleSet,
        prior: Option<DuplicatePurchaseMatch>,
    ) -> RiskEvaluation {
        evaluate_with_match_at(intent, rule_set, prior, default_evaluation_time())
    }

    fn evaluate_with_match_at(
        intent: &TransactionIntent,
        rule_set: &RiskRuleSet,
        prior: Option<DuplicatePurchaseMatch>,
        evaluated_at: Timestamp,
    ) -> RiskEvaluation {
        let profile = validate_profile(intent).unwrap();
        let repository = RepositorySnapshot::new(
            format!("audit-chain:{}:10", intent.principal.organization_id),
            10,
            "a".repeat(64),
        )
        .unwrap();
        let context = EvaluationContext::new(EvaluationContextInput {
            evaluation_id: "01J0000000000000000000EVAL".into(),
            intent_id: intent.intent_id.clone(),
            intent_hash: intent.canonical_hash(),
            evaluation_time: evaluated_at,
            environment: "development".into(),
            profile_id: profile.id().into(),
            profile_version: profile.version().into(),
            policy: VersionedArtifactReference::unavailable("POLICY_NOT_USED").unwrap(),
            risk: VersionedArtifactReference::available(
                rule_set.engine_version(),
                rule_set.version(),
                rule_set.rule_set_hash(),
            )
            .unwrap(),
            context_snapshot_id: "01J0000000000000000000SNAP".into(),
            agent_context: intent.context.clone(),
            evidence: Vec::new(),
            evidence_trust_policy: EvidenceTrustPolicyReference::not_configured(
                "TRUST_POLICY_NOT_CONFIGURED",
            )
            .unwrap(),
            history: repository.clone(),
            market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_UNAVAILABLE").unwrap(),
            simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED").unwrap(),
        })
        .unwrap();
        let duplicate = rule_set.duplicate_purchase_enabled().then(|| {
            DuplicatePurchaseHistory::new(
                DuplicatePurchaseQuery::new(
                    &intent.principal.organization_id,
                    &intent.principal.agent_id,
                    &intent.resource.resource_id,
                    &intent.intent_id,
                    evaluated_at,
                    rule_set.duplicate_purchase_window_seconds(),
                    rule_set.duplicate_purchase_accounting_boundary(),
                )
                .unwrap(),
                prior,
            )
            .unwrap()
        });
        let daily = rule_set.daily_spend_enabled().then(|| {
            DailySpendHistory::new(
                DailySpendQuery::new(
                    &intent.principal.organization_id,
                    &intent.principal.agent_id,
                    &intent.intent_id,
                    rule_set
                        .daily_spend_valuation_asset()
                        .expect("enabled daily-spend rule has an asset"),
                    evaluated_at,
                    rule_set
                        .daily_spend_window_seconds()
                        .expect("enabled daily-spend rule has a window"),
                    rule_set
                        .daily_spend_accounting_boundary()
                        .expect("enabled daily-spend rule has a boundary"),
                )
                .unwrap(),
                Vec::new(),
                0,
            )
            .unwrap()
        });
        let first = rule_set.first_destination_enabled().then(|| {
            let destination = match normalize_destination(intent) {
                Ok(value) => DestinationNormalization::available(value.value()).unwrap(),
                Err(error) => DestinationNormalization::unavailable(error.code()).unwrap(),
            };
            FirstDestinationHistory::new(
                FirstDestinationQuery::new(
                    &intent.principal.organization_id,
                    &intent.intent_id,
                    profile.id(),
                    profile.version(),
                    rule_set.first_destination_normalizer_id().unwrap(),
                    rule_set.first_destination_normalizer_version().unwrap(),
                    destination,
                    evaluated_at,
                    rule_set.first_destination_accounting_boundary().unwrap(),
                )
                .unwrap(),
                None,
            )
            .unwrap()
        });
        let frequency = rule_set.request_frequency_enabled().then(|| {
            RequestFrequencyHistory::new(
                RequestFrequencyQuery::new(
                    &intent.principal.organization_id,
                    &intent.principal.agent_id,
                    &intent.intent_id,
                    profile.id(),
                    profile.version(),
                    &intent.action.category,
                    &intent.action.operation,
                    rule_set.request_frequency_subject().unwrap(),
                    rule_set.request_frequency_action_scope().unwrap(),
                    evaluated_at,
                    rule_set.request_frequency_window_seconds().unwrap(),
                    rule_set.request_frequency_max_requests().unwrap(),
                    rule_set.request_frequency_accounting_boundary().unwrap(),
                )
                .unwrap(),
                1,
                0,
            )
            .unwrap()
        });
        let history = RiskHistorySnapshot::with_request_frequency(
            repository, duplicate, daily, first, frequency,
        )
        .unwrap();
        super::evaluate_context(intent, rule_set, &context, &history).unwrap()
    }

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
                resource_type: Some("dataset".into()),
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
    fn repository_snapshot_result_drives_history_without_a_process_ledger() {
        let mut intent = base_intent();
        intent.intent_id = "01J0000000000000000000N200".into();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        let prior = DuplicatePurchaseMatch::new(
            "01J0000000000000000000N100",
            "01J0000000000000000000DEC0",
            "01J0000000000000000000EVT0",
            8,
            Timestamp::from_str("2026-08-08T11:59:00Z").unwrap(),
        )
        .unwrap();

        let findings = evaluate_with_match(&intent, &RiskRuleSet::default(), Some(prior));

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
    fn treats_agent_vendor_price_context_as_missing_trusted_data() {
        let mut intent = base_intent();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();
        intent.context = serde_json::json!({"historical_vendor_median": "8.50"});
        // (12.50 - 8.50) / 8.50 = ~47%, over the 30% default threshold.
        let findings = evaluate(&intent, &RiskRuleSet::default());
        assert!(findings
            .iter()
            .any(|f| f.code == "VENDOR_PRICE_DATA_MISSING"));
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
            .any(|f| f.code == "VENDOR_PRICE_DATA_MISSING"));
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
    fn every_declared_accounting_boundary_must_match_the_snapshot_query() {
        let prior_intent_id = "01J0000000000000000000H100";
        let at = Timestamp::from_str("2026-07-18T08:01:00Z").unwrap();
        let evaluated_at = Timestamp::from_str("2026-07-18T08:02:00Z").unwrap();
        let prior = DuplicatePurchaseMatch::new(
            prior_intent_id,
            "01J0000000000000000000DEC0",
            "01J0000000000000000000EVT0",
            8,
            at,
        )
        .unwrap();
        let boundary_cases = [
            ("REQUESTED", AccountingBoundary::Requested),
            ("PERMITTED", AccountingBoundary::Permitted),
            ("EXECUTED", AccountingBoundary::Executed),
            ("SETTLED", AccountingBoundary::Settled),
        ];
        let mut intent = base_intent();
        intent.intent_id = "01J0000000000000000000H200".into();
        intent.expires_at = Timestamp::from_str("2999-01-01T00:00:00Z").unwrap();

        for (boundary, expected) in boundary_cases {
            let rule_set = configured_rule_set(
                "/rules/duplicate_purchase/accounting_boundary",
                serde_json::json!(boundary),
            );
            assert_eq!(rule_set.duplicate_purchase_accounting_boundary(), expected);
            let result =
                evaluate_with_match_at(&intent, &rule_set, Some(prior.clone()), evaluated_at);
            assert!(
                result
                    .iter()
                    .any(|finding| finding.code == "DUPLICATE_PURCHASE"),
                "{boundary} must select the matching lifecycle event"
            );
        }
    }
}
