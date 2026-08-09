use std::path::PathBuf;

use atf_core::{RequestFrequencyActionScope, RequestFrequencySubject};
use atf_risk::{AccountingBoundary, RiskRuleSet};

fn default_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../risk-rules/default.json")
}

fn default_value() -> serde_json::Value {
    serde_json::from_str(include_str!("../../../risk-rules/default.json"))
        .expect("default Rule Set is JSON")
}

fn parse(value: &serde_json::Value) -> RiskRuleSet {
    RiskRuleSet::from_json(&serde_json::to_string(value).unwrap())
        .expect("mutated fixture remains a valid Rule Set")
}

#[test]
fn default_rule_set_has_a_stable_canonical_identity() {
    let from_file = RiskRuleSet::from_file(&default_path()).unwrap();
    let from_json =
        RiskRuleSet::from_json(include_str!("../../../risk-rules/default.json")).unwrap();

    assert_eq!(from_file.version(), "risk-rules-1.3.0");
    assert_eq!(from_file.engine_version(), "atf-risk-engine-v1");
    assert_eq!(from_file.rule_set_hash(), from_json.rule_set_hash());
    assert_eq!(
        from_file.rule_set_hash(),
        "4e536d1609e6902e2a890bca49669ce56e7f5d5c3c4c9c747a1c7e2ee416bea5"
    );
    assert_eq!(from_file.canonical_bytes(), from_json.canonical_bytes());
    assert_eq!(from_file.rule_set_hash().len(), 64);
    assert!(from_file
        .rule_set_hash()
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')));
    assert_eq!(
        from_file.duplicate_purchase_accounting_boundary(),
        AccountingBoundary::Permitted
    );
    assert!(from_file.daily_spend_enabled());
    assert_eq!(
        from_file.daily_spend_accounting_boundary(),
        Some(AccountingBoundary::Permitted)
    );
    assert_eq!(from_file.daily_spend_window_seconds(), Some(86_400));
    assert_eq!(
        from_file.daily_spend_valuation_asset(),
        Some("eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913")
    );
    assert!(from_file.first_destination_enabled());
    assert_eq!(
        from_file.first_destination_accounting_boundary(),
        Some(AccountingBoundary::Permitted)
    );
    assert_eq!(
        from_file.first_destination_normalizer_id(),
        Some("atf.agent-commerce.payment.destination.eip155")
    );
    assert_eq!(from_file.first_destination_normalizer_version(), Some("1"));
    assert!(from_file.request_frequency_enabled());
    assert_eq!(
        from_file.request_frequency_subject(),
        Some(RequestFrequencySubject::Agent)
    );
    assert_eq!(
        from_file.request_frequency_action_scope(),
        Some(RequestFrequencyActionScope::Profile)
    );
    assert_eq!(from_file.request_frequency_max_requests(), Some(10));
    assert_eq!(from_file.request_frequency_window_seconds(), Some(60));
    assert_eq!(
        from_file.request_frequency_accounting_boundary(),
        Some(AccountingBoundary::Requested)
    );
}

#[test]
fn ds030_rule_set_without_request_frequency_preserves_its_canonical_identity() {
    let mut ds030 = default_value();
    ds030["rule_set_version"] = serde_json::json!("risk-rules-1.2.0");
    ds030["rules"]
        .as_object_mut()
        .unwrap()
        .remove("request_frequency");

    let parsed = RiskRuleSet::from_json(&ds030.to_string()).unwrap();
    assert!(!parsed.request_frequency_enabled());
    assert_eq!(
        parsed.rule_set_hash(),
        "435d227b4c2d4d3a9d69600b7d48539d0758315e8abe2e823b5fd8fbaabc6ddc"
    );
}

#[test]
fn legacy_rule_set_without_daily_spend_preserves_its_canonical_identity() {
    let mut legacy = default_value();
    legacy["rule_set_version"] = serde_json::json!("risk-rules-1.0.0");
    legacy["rules"]
        .as_object_mut()
        .unwrap()
        .remove("daily_cumulative_spend");
    legacy["rules"]
        .as_object_mut()
        .unwrap()
        .remove("first_time_destination");
    legacy["rules"]
        .as_object_mut()
        .unwrap()
        .remove("request_frequency");

    let parsed = RiskRuleSet::from_json(&legacy.to_string()).unwrap();
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/risk-rule-set.schema.json")).unwrap();
    assert!(jsonschema::validator_for(&schema)
        .unwrap()
        .is_valid(&legacy));
    assert!(!parsed.daily_spend_enabled());
    assert_eq!(parsed.daily_spend_accounting_boundary(), None);
    assert_eq!(
        parsed.rule_set_hash(),
        "f16a028c749c061753cee5876d8325dbfb7e01fec3d6642ed08181d025dacbb5"
    );
}

#[test]
fn ds029_rule_set_without_first_destination_preserves_its_canonical_identity() {
    let mut ds029 = default_value();
    ds029["rule_set_version"] = serde_json::json!("risk-rules-1.1.0");
    ds029["rules"]
        .as_object_mut()
        .unwrap()
        .remove("first_time_destination");
    ds029["rules"]
        .as_object_mut()
        .unwrap()
        .remove("request_frequency");

    let parsed = RiskRuleSet::from_json(&ds029.to_string()).unwrap();
    assert!(!parsed.first_destination_enabled());
    assert_eq!(
        parsed.rule_set_hash(),
        "e9b02993ad4a4a83311b9d22f33f0bb9b4e31dfa1ad1508f4e0872203754a9c5"
    );
}

#[test]
fn public_schema_accepts_the_same_default_contract() {
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/risk-rule-set.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();

    assert!(validator.is_valid(&default_value()));
}

#[test]
fn every_decision_affecting_configuration_change_changes_the_hash() {
    let baseline = default_value();
    let baseline_hash = parse(&baseline).rule_set_hash().to_owned();
    let mutations: &[(&str, serde_json::Value)] = &[
        ("/rule_set_version", serde_json::json!("risk-rules-1.0.1")),
        ("/rules/request_expired/enabled", serde_json::json!(false)),
        ("/rules/request_expired/severity", serde_json::json!("high")),
        (
            "/rules/single_amount_cap/max_amount",
            serde_json::json!("10.00"),
        ),
        (
            "/rules/single_amount_cap/severity",
            serde_json::json!("critical"),
        ),
        ("/rules/max_fee_ratio/enabled", serde_json::json!(false)),
        (
            "/rules/max_fee_ratio/severity",
            serde_json::json!("critical"),
        ),
        ("/rules/max_fee_ratio/threshold_bps", serde_json::json!(501)),
        (
            "/rules/max_fee_ratio/missing_data",
            serde_json::json!("NOT_APPLICABLE"),
        ),
        (
            "/rules/vendor_price_deviation/threshold_bps",
            serde_json::json!(3001),
        ),
        (
            "/rules/vendor_price_deviation/enabled",
            serde_json::json!(false),
        ),
        (
            "/rules/vendor_price_deviation/severity",
            serde_json::json!("critical"),
        ),
        (
            "/rules/high_risk_network_or_protocol/enabled",
            serde_json::json!(false),
        ),
        (
            "/rules/high_risk_network_or_protocol/severity",
            serde_json::json!("critical"),
        ),
        (
            "/rules/high_risk_network_or_protocol/networks",
            serde_json::json!(["eip155:1"]),
        ),
        (
            "/rules/high_risk_network_or_protocol/protocols",
            serde_json::json!(["x402"]),
        ),
        (
            "/rules/duplicate_purchase/enabled",
            serde_json::json!(false),
        ),
        (
            "/rules/duplicate_purchase/severity",
            serde_json::json!("critical"),
        ),
        (
            "/rules/duplicate_purchase/window_seconds",
            serde_json::json!(3600),
        ),
        (
            "/rules/duplicate_purchase/accounting_boundary",
            serde_json::json!("EXECUTED"),
        ),
        (
            "/rules/daily_cumulative_spend/enabled",
            serde_json::json!(false),
        ),
        (
            "/rules/daily_cumulative_spend/severity",
            serde_json::json!("critical"),
        ),
        (
            "/rules/daily_cumulative_spend/max_amount",
            serde_json::json!("25000.01"),
        ),
        (
            "/rules/daily_cumulative_spend/valuation_asset",
            serde_json::json!("eip155:1/slip44:60"),
        ),
        (
            "/rules/daily_cumulative_spend/window_seconds",
            serde_json::json!(3600),
        ),
        (
            "/rules/first_time_destination/enabled",
            serde_json::json!(false),
        ),
        (
            "/rules/first_time_destination/severity",
            serde_json::json!("critical"),
        ),
        (
            "/rules/request_frequency/max_requests",
            serde_json::json!(11),
        ),
        (
            "/rules/request_frequency/window_seconds",
            serde_json::json!(61),
        ),
    ];

    for (pointer, replacement) in mutations {
        let mut candidate = baseline.clone();
        *candidate
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("fixture contains {pointer}")) = replacement.clone();
        assert_ne!(
            parse(&candidate).rule_set_hash(),
            baseline_hash,
            "mutation at {pointer} must change the Rule Set identity"
        );
    }

    let mut enabled_cap = baseline.clone();
    enabled_cap["rules"]["single_amount_cap"]["enabled"] = serde_json::json!(true);
    enabled_cap["rules"]["single_amount_cap"]["max_amount"] = serde_json::json!("10.00");
    assert_ne!(parse(&enabled_cap).rule_set_hash(), baseline_hash);
}

#[test]
fn enabled_vendor_price_rule_cannot_silently_ignore_missing_trusted_data() {
    let mut candidate = default_value();
    candidate["rules"]["vendor_price_deviation"]["missing_data"] =
        serde_json::json!("NOT_APPLICABLE");

    assert!(RiskRuleSet::from_json(&candidate.to_string()).is_err());
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/risk-rule-set.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();
    assert!(!validator.is_valid(&candidate));
}

#[test]
fn enabled_daily_spend_rule_is_high_permitted_and_fail_closed() {
    let invalid_mutations = [
        ("severity", serde_json::json!("medium")),
        ("max_amount", serde_json::json!("0")),
        ("valuation_asset", serde_json::json!("not an asset")),
        ("window_seconds", serde_json::json!(0)),
        ("accounting_boundary", serde_json::json!("REQUESTED")),
        ("missing_data", serde_json::json!("NOT_APPLICABLE")),
    ];
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/risk-rule-set.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();

    for (field, replacement) in invalid_mutations {
        let mut candidate = default_value();
        candidate["rules"]["daily_cumulative_spend"][field] = replacement;
        assert!(
            RiskRuleSet::from_json(&candidate.to_string()).is_err(),
            "invalid daily-spend field {field} must fail closed"
        );
        assert!(
            !validator.is_valid(&candidate),
            "Schema must reject invalid daily-spend field {field}"
        );
    }
}

#[test]
fn enabled_first_destination_rule_is_versioned_permitted_and_fail_closed() {
    let invalid_mutations = [
        ("severity", serde_json::json!("medium")),
        ("normalizer_id", serde_json::json!("unsupported-normalizer")),
        ("normalizer_version", serde_json::json!("2")),
        ("accounting_boundary", serde_json::json!("REQUESTED")),
        ("missing_data", serde_json::json!("NOT_APPLICABLE")),
    ];
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/risk-rule-set.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();

    for (field, replacement) in invalid_mutations {
        let mut candidate = default_value();
        candidate["rules"]["first_time_destination"][field] = replacement;
        assert!(
            RiskRuleSet::from_json(&candidate.to_string()).is_err(),
            "invalid first-destination field {field} must fail closed"
        );
        assert!(
            !validator.is_valid(&candidate),
            "Schema must reject invalid first-destination field {field}"
        );
    }
}

#[test]
fn enabled_request_frequency_rule_has_closed_requested_profile_scope() {
    let invalid_mutations = [
        ("severity", serde_json::json!("medium")),
        ("subject", serde_json::json!("USER")),
        ("action_scope", serde_json::json!("GLOBAL")),
        ("max_requests", serde_json::json!(0)),
        ("window_seconds", serde_json::json!(0)),
        ("accounting_boundary", serde_json::json!("PERMITTED")),
        ("missing_data", serde_json::json!("NOT_APPLICABLE")),
    ];
    let schema: serde_json::Value =
        serde_json::from_str(include_str!("../../../schemas/risk-rule-set.schema.json")).unwrap();
    let validator = jsonschema::validator_for(&schema).unwrap();

    for (field, replacement) in invalid_mutations {
        let mut candidate = default_value();
        candidate["rules"]["request_frequency"][field] = replacement;
        assert!(
            RiskRuleSet::from_json(&candidate.to_string()).is_err(),
            "invalid request-frequency field {field} must fail closed"
        );
        assert!(
            !validator.is_valid(&candidate),
            "Schema must reject invalid request-frequency field {field}"
        );
    }
}

#[test]
fn object_key_order_does_not_change_the_canonical_hash() {
    fn reverse_objects(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => serde_json::Value::Object(
                map.into_iter()
                    .rev()
                    .map(|(key, value)| (key, reverse_objects(value)))
                    .collect(),
            ),
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(reverse_objects).collect())
            }
            scalar => scalar,
        }
    }

    let baseline = default_value();
    assert_eq!(
        parse(&baseline).rule_set_hash(),
        parse(&reverse_objects(baseline)).rule_set_hash()
    );
}

#[test]
fn unknown_fields_and_invalid_thresholds_fail_closed() {
    let invalid_mutations: &[(&str, serde_json::Value)] = &[
        ("/unexpected", serde_json::json!(true)),
        ("/rules/unexpected", serde_json::json!({"enabled": true})),
        ("/rules/request_expired/unexpected", serde_json::json!(true)),
        (
            "/rules/max_fee_ratio/threshold_bps",
            serde_json::json!(1_000_001),
        ),
        (
            "/rules/vendor_price_deviation/missing_data",
            serde_json::json!("IGNORE"),
        ),
        (
            "/rules/single_amount_cap/max_amount",
            serde_json::json!("-1.00"),
        ),
        (
            "/rules/duplicate_purchase/window_seconds",
            serde_json::json!(0),
        ),
        (
            "/rules/high_risk_network_or_protocol/networks",
            serde_json::json!(["eip155:8453", "eip155:1"]),
        ),
    ];

    for (pointer, replacement) in invalid_mutations {
        let mut candidate = default_value();
        if candidate.pointer(pointer).is_some() {
            *candidate.pointer_mut(pointer).unwrap() = replacement.clone();
        } else {
            let (parent, field) = pointer.rsplit_once('/').unwrap();
            candidate
                .pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(field.into(), replacement.clone());
        }
        assert!(
            RiskRuleSet::from_json(&serde_json::to_string(&candidate).unwrap()).is_err(),
            "invalid mutation at {pointer} must be rejected"
        );
    }

    let mut missing_boundary = default_value();
    missing_boundary["rules"]["duplicate_purchase"]
        .as_object_mut()
        .unwrap()
        .remove("accounting_boundary");
    assert!(RiskRuleSet::from_json(&missing_boundary.to_string()).is_err());

    let mut enabled_without_amount = default_value();
    enabled_without_amount["rules"]["single_amount_cap"]["enabled"] = serde_json::json!(true);
    assert!(RiskRuleSet::from_json(&enabled_without_amount.to_string()).is_err());
}
