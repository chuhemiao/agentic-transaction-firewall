use std::path::PathBuf;

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

    assert_eq!(from_file.version(), "risk-rules-1.0.0");
    assert_eq!(from_file.engine_version(), "atf-risk-engine-v1");
    assert_eq!(from_file.rule_set_hash(), from_json.rule_set_hash());
    assert_eq!(
        from_file.rule_set_hash(),
        "f16a028c749c061753cee5876d8325dbfb7e01fec3d6642ed08181d025dacbb5"
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
