use std::sync::OnceLock;

use jsonschema::Validator;

use crate::error::IntentError;
use crate::types::TransactionIntent;

const SCHEMA_STR: &str = include_str!("../../../schemas/transaction-intent.schema.json");

fn schema() -> &'static Validator {
    static SCHEMA: OnceLock<Validator> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        let schema_value: serde_json::Value =
            serde_json::from_str(SCHEMA_STR).expect("bundled schema is valid JSON");
        jsonschema::validator_for(&schema_value).expect("bundled schema is a valid JSON Schema")
    })
}

/// Validate a raw JSON document against `schemas/transaction-intent.schema.json`,
/// then parse it into a [`TransactionIntent`].
///
/// Schema validation and Rust-type parsing are two separate, deliberately
/// redundant checks: the schema is the contract external tooling validates
/// against (PRD §9), while the Rust type is what the rest of ATF consumes.
/// An input that passes one but not the other is a bug in this crate, not a
/// caller error — the two must stay in lockstep.
pub fn validate(raw: &str) -> Result<TransactionIntent, IntentError> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(IntentError::InvalidJson)?;

    let errors: Vec<String> = schema()
        .iter_errors(&value)
        .map(|e| format!("{} (at {})", e, e.instance_path))
        .collect();
    if !errors.is_empty() {
        return Err(IntentError::SchemaViolation(errors.join("; ")));
    }

    serde_json::from_value(value).map_err(IntentError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_intent_json() -> &'static str {
        r#"{
            "spec_version": "1.0",
            "intent_id": "01J000000000000000000000",
            "idempotency_key": "idem-1",
            "created_at": "2026-07-18T08:00:00Z",
            "expires_at": "2026-07-18T08:05:00Z",
            "principal": {
                "organization_id": "alpha-lab",
                "agent_id": "research-agent-01"
            },
            "mandate": {
                "mandate_id": "mandate-001",
                "purpose": "purchase historical order-book data",
                "human_authorized": true
            },
            "action": { "category": "payment", "operation": "purchase_api_resource" },
            "resource": { "protocol": "x402", "resource_id": "btc-orderbook-2026-07-01" },
            "transaction": { "network": "base", "asset": "eip155:8453/erc20:0x0", "amount": "12.50" }
        }"#
    }

    #[test]
    fn accepts_a_valid_intent() {
        let intent = validate(valid_intent_json()).expect("should validate");
        assert_eq!(intent.spec_version, "1.0");
        assert_eq!(intent.transaction.amount.to_string(), "12.50");
    }

    #[test]
    fn rejects_missing_required_field() {
        let err = validate("{}").unwrap_err();
        assert!(matches!(err, IntentError::SchemaViolation(_)));
    }

    #[test]
    fn rejects_bad_action_category() {
        let mut value: serde_json::Value = serde_json::from_str(valid_intent_json()).unwrap();
        value["action"]["category"] = serde_json::json!("not_a_real_category");
        let err = validate(&value.to_string()).unwrap_err();
        assert!(matches!(err, IntentError::SchemaViolation(_)));
    }

    #[test]
    fn rejects_non_json() {
        let err = validate("not json").unwrap_err();
        assert!(matches!(err, IntentError::InvalidJson(_)));
    }
}
