use atf_intent::{validate, IntentError, SemanticErrorCode};
use serde_json::{json, Value};

const V1_FIXTURE: &str = include_str!("../../../examples/x402-research-agent/intent.json");
const PREFIX: &str = "intent failed semantic validation: ";

fn valid_value() -> Value {
    let mut value: Value = serde_json::from_str(V1_FIXTURE).expect("fixture is valid JSON");
    value["created_at"] = json!("2098-12-31T23:55:00Z");
    value["expires_at"] = json!("2099-01-01T00:00:00Z");
    value
}

fn semantic_message(value: &Value) -> String {
    validate(&value.to_string())
        .expect_err("the semantic mutation must be rejected")
        .to_string()
}

#[test]
fn financial_boundaries_fail_closed_with_stable_codes() {
    let cases = [
        (
            "/transaction/amount",
            json!("0"),
            "AMOUNT_NOT_POSITIVE (transaction.amount)",
        ),
        (
            "/transaction/amount",
            json!("-0"),
            "AMOUNT_NOT_POSITIVE (transaction.amount)",
        ),
        (
            "/transaction/amount",
            json!("-0.01"),
            "AMOUNT_NOT_POSITIVE (transaction.amount)",
        ),
        (
            "/transaction/max_fee",
            json!("-0.01"),
            "MAX_FEE_NEGATIVE (transaction.max_fee)",
        ),
        (
            "/transaction/leverage",
            json!("0"),
            "LEVERAGE_NOT_POSITIVE (transaction.leverage)",
        ),
        (
            "/transaction/leverage",
            json!("-1"),
            "LEVERAGE_NOT_POSITIVE (transaction.leverage)",
        ),
        (
            "/transaction/slippage_bps",
            json!(-1),
            "SLIPPAGE_BPS_OUT_OF_RANGE (transaction.slippage_bps)",
        ),
        (
            "/transaction/slippage_bps",
            json!(10_001),
            "SLIPPAGE_BPS_OUT_OF_RANGE (transaction.slippage_bps)",
        ),
    ];

    for (pointer, replacement, expected) in cases {
        let mut value = valid_value();
        *value.pointer_mut(pointer).expect("fixture contains field") = replacement;
        assert_eq!(semantic_message(&value), format!("{PREFIX}{expected}"));
    }

    for (pointer, boundary) in [
        (
            "/transaction/amount",
            json!("0.0000000000000000000000000001"),
        ),
        ("/transaction/max_fee", json!("0")),
        ("/transaction/leverage", json!("0.0001")),
        ("/transaction/slippage_bps", json!(0)),
        ("/transaction/slippage_bps", json!(10_000)),
    ] {
        let mut value = valid_value();
        *value.pointer_mut(pointer).expect("fixture contains field") = boundary;
        validate(&value.to_string())
            .unwrap_or_else(|error| panic!("valid boundary at {pointer} was rejected: {error}"));
    }
}

#[test]
fn timestamp_order_precision_and_ttl_are_enforced_without_normalization() {
    let cases = [
        (
            "2099-01-01T00:00:00Z",
            "2099-01-01T00:00:00Z",
            "TIME_ORDER_INVALID (expires_at)",
        ),
        (
            "2099-01-01T00:00:01Z",
            "2099-01-01T00:00:00Z",
            "TIME_ORDER_INVALID (expires_at)",
        ),
        (
            "2098-12-31T00:00:00Z",
            "2099-01-01T00:00:00.001Z",
            "TTL_EXCEEDS_LIMIT (expires_at)",
        ),
        (
            "2098-12-31T00:00:00.000001Z",
            "2098-12-31T00:05:00Z",
            "TIMESTAMP_PRECISION_UNSUPPORTED (created_at)",
        ),
        (
            "2098-12-31T00:00:00Z",
            "2098-12-31T00:05:00.000001Z",
            "TIMESTAMP_PRECISION_UNSUPPORTED (expires_at)",
        ),
    ];

    for (created_at, expires_at, expected) in cases {
        let mut value = valid_value();
        value["created_at"] = json!(created_at);
        value["expires_at"] = json!(expires_at);
        assert_eq!(semantic_message(&value), format!("{PREFIX}{expected}"));
    }

    let mut exact_limit = valid_value();
    exact_limit["created_at"] = json!("2098-12-31T00:00:00Z");
    exact_limit["expires_at"] = json!("2099-01-01T00:00:00Z");
    validate(&exact_limit.to_string()).expect("an exact 24-hour TTL is valid");
}

#[test]
fn intent_id_must_be_a_valid_ulid() {
    for invalid in [
        "",
        "not-a-ulid",
        "01J00000000000000000000I00",
        "01J00000000000000000000",
    ] {
        let mut value = valid_value();
        value["intent_id"] = json!(invalid);
        assert_eq!(
            semantic_message(&value),
            format!("{PREFIX}INTENT_ID_INVALID (intent_id)")
        );
    }
}

#[test]
fn every_common_identifier_rejects_blank_input_without_trimming() {
    let fields = [
        ("/idempotency_key", "idempotency_key"),
        ("/principal/organization_id", "principal.organization_id"),
        ("/principal/user_id", "principal.user_id"),
        ("/principal/agent_id", "principal.agent_id"),
        ("/principal/agent_version", "principal.agent_version"),
        ("/principal/strategy_id", "principal.strategy_id"),
        ("/mandate/mandate_id", "mandate.mandate_id"),
        ("/mandate/task_id", "mandate.task_id"),
        ("/mandate/budget_id", "mandate.budget_id"),
        ("/action/operation", "action.operation"),
        ("/resource/protocol", "resource.protocol"),
        ("/resource/venue", "resource.venue"),
        ("/resource/resource_id", "resource.resource_id"),
        ("/resource/resource_type", "resource.resource_type"),
        ("/transaction/network", "transaction.network"),
        ("/transaction/asset", "transaction.asset"),
        ("/transaction/destination", "transaction.destination"),
        ("/transaction/contract", "transaction.contract"),
        ("/transaction/calldata_hash", "transaction.calldata_hash"),
    ];

    for (pointer, field) in fields {
        for blank in ["", " \t "] {
            let mut value = valid_value();
            *value.pointer_mut(pointer).expect("fixture contains field") = json!(blank);
            assert_eq!(
                semantic_message(&value),
                format!("{PREFIX}FIELD_BLANK ({field})")
            );
        }
    }
}

#[test]
fn identifier_and_purpose_size_and_character_boundaries_are_explicit() {
    let mut identifier_at_limit = valid_value();
    identifier_at_limit["idempotency_key"] = json!("a".repeat(256));
    validate(&identifier_at_limit.to_string()).expect("256-byte identifier is valid");

    let mut identifier_too_long = valid_value();
    identifier_too_long["principal"]["organization_id"] = json!("a".repeat(257));
    assert_eq!(
        semantic_message(&identifier_too_long),
        format!("{PREFIX}FIELD_TOO_LONG (principal.organization_id)")
    );

    let mut blank_identifier_too_long = valid_value();
    blank_identifier_too_long["principal"]["organization_id"] = json!(" ".repeat(257));
    assert_eq!(
        semantic_message(&blank_identifier_too_long),
        format!("{PREFIX}FIELD_TOO_LONG (principal.organization_id)")
    );

    let mut identifier_with_space = valid_value();
    identifier_with_space["idempotency_key"] = json!("do not trim me");
    assert_eq!(
        semantic_message(&identifier_with_space),
        format!("{PREFIX}FIELD_INVALID_CHARACTERS (idempotency_key)")
    );

    let mut purpose_at_limit = valid_value();
    purpose_at_limit["mandate"]["purpose"] = json!("p".repeat(1024));
    validate(&purpose_at_limit.to_string()).expect("1024-byte purpose is valid");

    let mut purpose_too_long = valid_value();
    purpose_too_long["mandate"]["purpose"] = json!("p".repeat(1025));
    assert_eq!(
        semantic_message(&purpose_too_long),
        format!("{PREFIX}FIELD_TOO_LONG (mandate.purpose)")
    );

    for blank in ["", " \n "] {
        let mut blank_purpose = valid_value();
        blank_purpose["mandate"]["purpose"] = json!(blank);
        assert_eq!(
            semantic_message(&blank_purpose),
            format!("{PREFIX}FIELD_BLANK (mandate.purpose)")
        );
    }

    let mut blank_purpose_too_long = valid_value();
    blank_purpose_too_long["mandate"]["purpose"] = json!(" ".repeat(1025));
    assert_eq!(
        semantic_message(&blank_purpose_too_long),
        format!("{PREFIX}FIELD_TOO_LONG (mandate.purpose)")
    );

    let mut control_in_purpose = valid_value();
    control_in_purpose["mandate"]["purpose"] = json!("research\u{0000}dataset");
    assert_eq!(
        semantic_message(&control_in_purpose),
        format!("{PREFIX}FIELD_INVALID_CHARACTERS (mandate.purpose)")
    );
}

#[test]
fn multiple_violations_are_reported_once_in_deterministic_rule_order() {
    let mut value = valid_value();
    value["transaction"]["amount"] = json!("0");
    value["transaction"]["max_fee"] = json!("-1");
    value["transaction"]["leverage"] = json!("0");
    value["transaction"]["slippage_bps"] = json!(10_001);
    value["expires_at"] = value["created_at"].clone();
    value["intent_id"] = json!("bad-ulid");
    value["idempotency_key"] = json!("   ");
    value["principal"]["organization_id"] = json!("a".repeat(257));
    value["mandate"]["purpose"] = json!("\t");

    let expected = concat!(
        "intent failed semantic validation: ",
        "AMOUNT_NOT_POSITIVE (transaction.amount); ",
        "MAX_FEE_NEGATIVE (transaction.max_fee); ",
        "LEVERAGE_NOT_POSITIVE (transaction.leverage); ",
        "SLIPPAGE_BPS_OUT_OF_RANGE (transaction.slippage_bps); ",
        "TIME_ORDER_INVALID (expires_at); ",
        "INTENT_ID_INVALID (intent_id); ",
        "FIELD_BLANK (idempotency_key); ",
        "FIELD_TOO_LONG (principal.organization_id); ",
        "FIELD_BLANK (mandate.purpose)"
    );

    assert_eq!(semantic_message(&value), expected);
    assert_eq!(semantic_message(&value), expected);
}

#[test]
fn semantic_failures_expose_stable_structured_codes_and_fields() {
    let mut value = valid_value();
    value["transaction"]["amount"] = json!("0");
    value["idempotency_key"] = json!("contains spaces");

    let IntentError::Semantic(errors) =
        validate(&value.to_string()).expect_err("semantic failures must be structured")
    else {
        panic!("semantic input returned a non-semantic error variant");
    };

    let violations = errors.violations();
    assert_eq!(violations.len(), 2);
    assert_eq!(violations[0].code, SemanticErrorCode::AmountNotPositive);
    assert_eq!(violations[0].code.as_str(), "AMOUNT_NOT_POSITIVE");
    assert_eq!(violations[0].field, "transaction.amount");
    assert_eq!(
        violations[1].code,
        SemanticErrorCode::FieldInvalidCharacters
    );
    assert_eq!(violations[1].code.as_str(), "FIELD_INVALID_CHARACTERS");
    assert_eq!(violations[1].field, "idempotency_key");
}
