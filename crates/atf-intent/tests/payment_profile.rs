use atf_intent::{
    validate, validate_profile, AGENT_COMMERCE_PAYMENT_PROFILE_ID,
    AGENT_COMMERCE_PAYMENT_PROFILE_VERSION,
};
use serde_json::{json, Value};

const V1_FIXTURE: &str = include_str!("../../../examples/x402-research-agent/intent.json");
const PROFILE_SCHEMA: &str =
    include_str!("../../../schemas/profiles/payment-intent-v1.schema.json");
const PREFIX: &str = "intent failed semantic validation: ";
const TOKEN: &str = "0x833589fcd6edb6e08f4c7c32d4f71b54bda02913";
const PAYEE: &str = "0x1111111111111111111111111111111111111111";

fn payment_value() -> Value {
    let mut value: Value = serde_json::from_str(V1_FIXTURE).expect("fixture is valid JSON");
    value["transaction"]["network"] = json!("eip155:8453");
    value["transaction"]["asset"] = json!(format!("eip155:8453/erc20:{TOKEN}"));
    value["transaction"]["destination"] = json!(format!("eip155:8453:{PAYEE}"));
    value
}

fn profile_message(value: &Value) -> String {
    validate(&value.to_string())
        .expect_err("the profile mutation must be rejected")
        .to_string()
}

#[test]
fn supported_agent_commerce_payment_shape_is_accepted() {
    let intent =
        validate(&payment_value().to_string()).expect("the supported payment profile is valid");
    let profile = validate_profile(&intent).expect("the profile remains derivable");

    assert_eq!(profile.id(), AGENT_COMMERCE_PAYMENT_PROFILE_ID);
    assert_eq!(profile.version(), AGENT_COMMERCE_PAYMENT_PROFILE_VERSION);
}

#[test]
fn public_profile_schema_matches_the_rust_selector_and_structural_boundary() {
    let schema_value: Value =
        serde_json::from_str(PROFILE_SCHEMA).expect("profile schema is valid JSON");
    assert_eq!(
        schema_value["x-atf-profile-id"],
        AGENT_COMMERCE_PAYMENT_PROFILE_ID
    );
    assert_eq!(
        schema_value["x-atf-profile-version"],
        AGENT_COMMERCE_PAYMENT_PROFILE_VERSION
    );
    let schema =
        jsonschema::validator_for(&schema_value).expect("profile schema is a valid JSON Schema");
    assert!(schema.is_valid(&payment_value()));

    let mut unsupported = payment_value();
    unsupported["action"]["operation"] = json!("send_funds");
    assert!(!schema.is_valid(&unsupported));

    let mut missing_destination = payment_value();
    missing_destination["transaction"]["destination"] = Value::Null;
    assert!(!schema.is_valid(&missing_destination));

    let mut hidden_contract_call = payment_value();
    hidden_contract_call["transaction"]["contract"] =
        json!("eip155:8453:0x2222222222222222222222222222222222222222");
    assert!(!schema.is_valid(&hidden_contract_call));
}

#[test]
fn every_unimplemented_action_or_operation_fails_closed() {
    for (category, operation) in [
        ("payment", "send_funds"),
        ("transfer", "transfer_asset"),
        ("token_approval", "approve"),
        ("contract_call", "call"),
        ("exchange_order", "place_order"),
        ("treasury_rebalance", "rebalance"),
        ("swap", "swap"),
        ("borrow", "borrow"),
        ("lend", "lend"),
        ("stake", "stake"),
        ("bridge", "bridge"),
        ("prediction_market_order", "place_order"),
        ("subscription", "subscribe"),
        ("recurring_payment", "schedule"),
        ("refund", "refund"),
        ("withdrawal", "withdraw"),
    ] {
        let mut value = payment_value();
        value["action"]["category"] = json!(category);
        value["action"]["operation"] = json!(operation);

        assert_eq!(
            profile_message(&value),
            format!("{PREFIX}UNSUPPORTED_INTENT_PROFILE (action)"),
            "unexpected profile result for {category}/{operation}"
        );
    }
}

#[test]
fn payment_requires_a_typed_resource_and_chain_bound_destination() {
    let mut value = payment_value();
    value["resource"]["resource_type"] = Value::Null;
    value["transaction"]["destination"] = Value::Null;

    assert_eq!(
        profile_message(&value),
        concat!(
            "intent failed semantic validation: ",
            "PROFILE_FIELD_REQUIRED (resource.resource_type); ",
            "PROFILE_FIELD_REQUIRED (transaction.destination)"
        )
    );
}

#[test]
fn payment_rejects_fields_owned_by_other_financial_profiles() {
    let mut value = payment_value();
    value["transaction"]["contract"] =
        json!("eip155:8453:0x2222222222222222222222222222222222222222");
    value["transaction"]["calldata_hash"] =
        json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    value["transaction"]["slippage_bps"] = json!(1);
    value["transaction"]["leverage"] = json!("1");

    assert_eq!(
        profile_message(&value),
        concat!(
            "intent failed semantic validation: ",
            "PROFILE_FIELD_FORBIDDEN (transaction.contract); ",
            "PROFILE_FIELD_FORBIDDEN (transaction.calldata_hash); ",
            "PROFILE_FIELD_FORBIDDEN (transaction.slippage_bps); ",
            "PROFILE_FIELD_FORBIDDEN (transaction.leverage)"
        )
    );
}

#[test]
fn caip_identifiers_are_syntax_checked_and_bound_to_one_chain() {
    let cases = [
        (
            "/transaction/network",
            json!("base"),
            "NETWORK_ID_INVALID (transaction.network)",
        ),
        (
            "/transaction/asset",
            json!("USDC"),
            "ASSET_ID_INVALID (transaction.asset)",
        ),
        (
            "/transaction/asset",
            json!(format!("eip155:1/erc20:{TOKEN}")),
            "ASSET_NETWORK_MISMATCH (transaction.asset)",
        ),
        (
            "/transaction/asset",
            json!("eip155:8453/erc20:token%2f"),
            "ASSET_ID_INVALID (transaction.asset)",
        ),
        (
            "/transaction/destination",
            json!(PAYEE),
            "DESTINATION_ID_INVALID (transaction.destination)",
        ),
        (
            "/transaction/destination",
            json!(format!("eip155:1:{PAYEE}")),
            "DESTINATION_NETWORK_MISMATCH (transaction.destination)",
        ),
        (
            "/transaction/destination",
            json!("eip155:8453:account%2falias"),
            "DESTINATION_ID_INVALID (transaction.destination)",
        ),
    ];

    for (pointer, replacement, expected) in cases {
        let mut value = payment_value();
        *value.pointer_mut(pointer).expect("fixture contains field") = replacement;
        assert_eq!(profile_message(&value), format!("{PREFIX}{expected}"));
    }
}

#[test]
fn caip_boundaries_are_accepted_without_normalization() {
    let mut value = payment_value();
    value["transaction"]["network"] = json!("chainstd:8c3444cf8970a9e41a706fab93e7a6c4");
    value["transaction"]["asset"] = json!(format!(
        "chainstd:8c3444cf8970a9e41a706fab93e7a6c4/assetstd:{}",
        "r".repeat(128)
    ));
    value["transaction"]["destination"] = json!(format!(
        "chainstd:8c3444cf8970a9e41a706fab93e7a6c4:{}",
        "a".repeat(128)
    ));

    validate(&value.to_string()).expect("documented CAIP length boundaries are valid");

    let mut token = payment_value();
    token["transaction"]["asset"] =
        json!(format!("eip155:8453/erc721:collection/{}", "t".repeat(78)));
    validate(&token.to_string()).expect("a 78-byte CAIP token ID is valid");

    let mut escaped = payment_value();
    escaped["transaction"]["asset"] = json!("eip155:8453/erc20:token%2Falias");
    escaped["transaction"]["destination"] = json!("eip155:8453:account%2Falias");
    validate(&escaped.to_string()).expect("uppercase percent-encoded octets are valid");
}
