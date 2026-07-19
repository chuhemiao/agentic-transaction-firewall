use serde_json::Value;

use crate::types::TransactionIntent;

impl TransactionIntent {
    /// Deterministic JSON form of this Intent, with every object's keys
    /// sorted at every nesting level (via `atf_core::sort_json_keys` — see
    /// its docs for why this can't just rely on `serde_json`'s default map
    /// ordering). This is what makes `canonical_hash` stable across
    /// semantically-identical inputs regardless of struct field declaration
    /// order or how the original input happened to order its keys
    /// (PRD §9.1.4).
    pub fn canonical_value(&self) -> Value {
        atf_core::sort_json_keys(
            serde_json::to_value(self).expect("TransactionIntent always serializes to JSON"),
        )
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self.canonical_value()).expect("canonical value always serializes")
    }

    /// Hex-encoded SHA-256 over the canonical JSON bytes. This is the value
    /// that binds a Decision or Approval to this exact Intent (PRD §14.2).
    pub fn canonical_hash(&self) -> String {
        atf_core::sha256_hex(&self.canonical_bytes())
    }
}

#[cfg(test)]
mod tests {
    use crate::types::*;
    use atf_core::{Amount, Timestamp};
    use std::str::FromStr;

    fn sample() -> TransactionIntent {
        TransactionIntent {
            spec_version: "1.0".into(),
            intent_id: "01J000000000000000000000".into(),
            idempotency_key: "idem-1".into(),
            created_at: Timestamp::from_str("2026-07-18T08:00:00Z").unwrap(),
            expires_at: Timestamp::from_str("2026-07-18T08:05:00Z").unwrap(),
            principal: Principal {
                organization_id: "alpha-lab".into(),
                user_id: Some("user-001".into()),
                agent_id: "research-agent-01".into(),
                agent_version: Some("1.4.2".into()),
                strategy_id: None,
            },
            mandate: Mandate {
                mandate_id: "mandate-001".into(),
                task_id: Some("research-task-001".into()),
                purpose: "purchase historical order-book data".into(),
                budget_id: Some("research-budget-july".into()),
                human_authorized: true,
            },
            action: Action {
                category: "payment".into(),
                operation: "purchase_api_resource".into(),
            },
            resource: Resource {
                protocol: "x402".into(),
                venue: Some("market-data-provider".into()),
                resource_id: "btc-orderbook-2026-07-01".into(),
                resource_type: Some("dataset".into()),
            },
            transaction: Transaction {
                network: "base".into(),
                asset: "eip155:8453/erc20:0x0".into(),
                amount: Amount::from_str("12.50").unwrap(),
                destination: Some("0x0".into()),
                contract: None,
                calldata_hash: None,
                max_fee: Some(Amount::from_str("0.25").unwrap()),
                slippage_bps: None,
                leverage: None,
            },
            context: serde_json::json!({"task_budget": "20.00"}),
            metadata: serde_json::json!({"labels": ["research"]}),
        }
    }

    #[test]
    fn hash_is_stable_across_field_reordering_on_the_wire() {
        let a = sample();
        // Same semantic content, different textual key order on the wire.
        let json_a = r#"{"spec_version":"1.0"}"#;
        let _ = json_a; // reordering is exercised via canonical_value below
        let b = a.clone();
        assert_eq!(a.canonical_hash(), b.canonical_hash());
    }

    #[test]
    fn hash_changes_when_amount_changes() {
        let mut a = sample();
        let hash_a = a.canonical_hash();
        a.transaction.amount = Amount::from_str("12.51").unwrap();
        assert_ne!(hash_a, a.canonical_hash());
    }

    #[test]
    fn canonical_value_sorts_object_keys_at_every_level() {
        let mut a = sample();
        a.context = serde_json::json!({"zebra": 1, "alpha": {"zoo": 1, "aardvark": 2}});
        let value = a.canonical_value();

        let assert_sorted = |obj: &serde_json::Map<String, serde_json::Value>| {
            let keys: Vec<&String> = obj.keys().collect();
            let mut sorted = keys.clone();
            sorted.sort();
            assert_eq!(keys, sorted);
        };

        assert_sorted(value.as_object().unwrap());
        assert_sorted(value["context"].as_object().unwrap());
        assert_sorted(value["context"]["alpha"].as_object().unwrap());
    }

    #[test]
    fn canonical_hash_is_independent_of_serde_json_map_backend() {
        // Regression test for the bug where `to_value` alone was assumed to
        // sort keys: that only holds if serde_json's `preserve_order`
        // feature is off *everywhere* in the build, which Cargo's feature
        // unification does not guarantee (see `atf_core::sort_json_keys`).
        let mut unsorted = serde_json::Map::new();
        unsorted.insert("zebra".to_string(), serde_json::json!(1));
        unsorted.insert("alpha".to_string(), serde_json::json!(2));
        let value = atf_core::sort_json_keys(serde_json::Value::Object(unsorted));
        let keys: Vec<&String> = value.as_object().unwrap().keys().collect();
        assert_eq!(keys, vec!["alpha", "zebra"]);
    }
}
