use atf_intent::{validate, IntentError, TransactionIntent, SUPPORTED_SPEC_VERSIONS};
use serde_json::{json, Value};

const V1_FIXTURE: &str = include_str!("../../../examples/x402-research-agent/intent.json");
const INTENT_SCHEMA: &str = include_str!("../../../schemas/transaction-intent.schema.json");

fn fixture_value() -> Value {
    serde_json::from_str(V1_FIXTURE).expect("the checked-in v1 fixture is valid JSON")
}

#[test]
fn unknown_core_fields_are_rejected_by_schema_and_rust_deserialization() {
    for object_pointer in [
        "",
        "/principal",
        "/mandate",
        "/action",
        "/resource",
        "/transaction",
    ] {
        let mut value = fixture_value();
        value
            .pointer_mut(object_pointer)
            .expect("fixture contains every core object")
            .as_object_mut()
            .expect("core value is an object")
            .insert("unrecognized_constraint".into(), json!("must-be-bound"));

        let schema_error = validate(&value.to_string())
            .expect_err("unknown core fields must fail at the public validation boundary");
        assert!(
            matches!(schema_error, IntentError::SchemaViolation(_)),
            "unexpected error for {object_pointer:?}: {schema_error}"
        );

        let rust_result = serde_json::from_value::<TransactionIntent>(value);
        assert!(
            rust_result.is_err(),
            "direct Rust deserialization silently accepted an unknown field at {object_pointer:?}"
        );
    }
}

#[test]
fn only_the_declared_v1_spec_version_is_accepted() {
    assert_eq!(SUPPORTED_SPEC_VERSIONS, &["1.0"]);
    let schema: Value =
        serde_json::from_str(INTENT_SCHEMA).expect("the checked-in Intent Schema is valid JSON");
    let schema_versions: Vec<&str> = schema["properties"]["spec_version"]["enum"]
        .as_array()
        .expect("spec_version declares an explicit enum")
        .iter()
        .map(|version| version.as_str().expect("Schema versions are strings"))
        .collect();
    assert_eq!(schema_versions, SUPPORTED_SPEC_VERSIONS);

    for supported in SUPPORTED_SPEC_VERSIONS {
        let mut value = fixture_value();
        value["spec_version"] = json!(supported);
        validate(&value.to_string()).unwrap_or_else(|error| {
            panic!("Rust-supported version {supported:?} is missing from the Schema: {error}")
        });
    }

    for unsupported in ["", "0.9", "1", "1.1", "2.0"] {
        let mut value = fixture_value();
        value["spec_version"] = json!(unsupported);

        let schema_error = validate(&value.to_string())
            .expect_err("unsupported versions must fail at the public validation boundary");
        assert!(
            matches!(schema_error, IntentError::SchemaViolation(_)),
            "unexpected error for version {unsupported:?}: {schema_error}"
        );

        assert!(
            serde_json::from_value::<TransactionIntent>(value).is_err(),
            "direct Rust deserialization accepted unsupported version {unsupported:?}"
        );
    }
}

#[test]
fn accepted_v1_fields_survive_typed_round_trip() {
    let intent = validate(V1_FIXTURE).expect("existing v1 fixture remains compatible");
    let serialized = serde_json::to_string(&intent).expect("typed Intent serializes");
    let reparsed = validate(&serialized).expect("typed output remains Schema-valid");

    assert_eq!(reparsed, intent);
    assert_eq!(reparsed.canonical_hash(), intent.canonical_hash());
    assert_eq!(
        intent.canonical_hash(),
        "4d34e15d03e2d56353d42d41fc1f136c41e8edf4464299737f5d52949d5b3d4c",
        "the profile-compatible v1 fixture's canonical identity must not drift"
    );
    assert_eq!(
        reparsed.context,
        fixture_value()["context"],
        "context extensions must survive"
    );
    assert_eq!(
        reparsed.metadata,
        fixture_value()["metadata"],
        "metadata extensions must survive"
    );
    assert_eq!(intent.canonical_value()["spec_version"], json!("1.0"));
}

#[test]
fn every_typed_v1_field_is_bound_even_when_the_current_profile_forbids_it() {
    let original = validate(V1_FIXTURE).expect("existing v1 fixture remains compatible");
    let mutations = [
        ("/intent_id", json!("01J00000000000000000000900")),
        ("/idempotency_key", json!("research-2026-07-18-002")),
        ("/created_at", json!("2098-12-31T23:54:59Z")),
        ("/expires_at", json!("2099-01-01T00:00:01Z")),
        ("/principal/organization_id", json!("beta-lab")),
        ("/principal/user_id", json!("user-002")),
        ("/principal/agent_id", json!("research-agent-02")),
        ("/principal/agent_version", json!("1.4.3")),
        ("/principal/strategy_id", json!("strategy-001")),
        ("/mandate/mandate_id", json!("mandate-002")),
        ("/mandate/task_id", json!("research-task-002")),
        ("/mandate/purpose", json!("purchase a different dataset")),
        ("/mandate/budget_id", json!("research-budget-august")),
        ("/mandate/human_authorized", json!(false)),
        ("/action/category", json!("transfer")),
        ("/action/operation", json!("transfer_asset")),
        ("/resource/protocol", json!("x402-v2")),
        ("/resource/venue", json!("alternate-provider")),
        ("/resource/resource_id", json!("eth-orderbook-2026-07-01")),
        ("/resource/resource_type", json!("report")),
        ("/transaction/network", json!("ethereum")),
        ("/transaction/asset", json!("eip155:1/erc20:0xUSDC")),
        ("/transaction/amount", json!("12.51")),
        ("/transaction/destination", json!("0xalternate")),
        ("/transaction/contract", json!("0xcontract")),
        ("/transaction/calldata_hash", json!("sha256:calldata")),
        ("/transaction/max_fee", json!("0.26")),
        ("/transaction/slippage_bps", json!(25)),
        ("/transaction/leverage", json!("2")),
        ("/context/requested_by_tool", json!("mcp-alternate-tool")),
        ("/metadata/labels/0", json!("alternate-label")),
    ];

    for (pointer, replacement) in mutations {
        let mut value = fixture_value();
        *value
            .pointer_mut(pointer)
            .unwrap_or_else(|| panic!("fixture must contain {pointer}")) = replacement;
        let changed: TransactionIntent = serde_json::from_value(value)
            .unwrap_or_else(|error| panic!("mutation at {pointer} must stay typed: {error}"));
        assert_ne!(
            changed.canonical_hash(),
            original.canonical_hash(),
            "field at {pointer} was not bound into the canonical hash"
        );
    }
}

#[test]
fn arbitrary_extensions_are_accepted_only_inside_context_and_metadata() {
    let mut value = fixture_value();
    value["context"]["com.example/risk-hint@v1"] = json!({
        "nested": [true, 7, {"constraint": "preserve me"}]
    });
    value["metadata"]["com.example/labels@v1"] = json!({"tier": "research"});

    let extended = validate(&value.to_string()).expect("extension objects remain open");
    let baseline = validate(V1_FIXTURE).expect("fixture remains valid");

    assert_ne!(extended.canonical_hash(), baseline.canonical_hash());
    assert_eq!(
        extended.context["com.example/risk-hint@v1"]["nested"][2]["constraint"],
        json!("preserve me")
    );
    assert_eq!(
        extended.metadata["com.example/labels@v1"]["tier"],
        json!("research")
    );
}

#[test]
fn extension_namespaces_must_remain_json_objects_on_every_parse_path() {
    for field in ["context", "metadata"] {
        let mut value = fixture_value();
        value[field] = json!(["not", "an", "object"]);

        assert!(
            matches!(
                validate(&value.to_string()),
                Err(IntentError::SchemaViolation(_))
            ),
            "public validation accepted a non-object {field}"
        );
        assert!(
            serde_json::from_value::<TransactionIntent>(value).is_err(),
            "direct Rust deserialization accepted a non-object {field}"
        );
    }
}
