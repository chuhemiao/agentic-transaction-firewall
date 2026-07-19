use atf_core::{Amount, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Canonical Transaction Intent (PRD §9.2).
///
/// Field shapes here are the "core fields" the PRD says must not change
/// without a compatibility plan (§9.1.6, §37). `context` and `metadata` are
/// deliberately untyped JSON objects — they are the extension points.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransactionIntent {
    pub spec_version: String,
    pub intent_id: String,
    pub idempotency_key: String,
    pub created_at: Timestamp,
    pub expires_at: Timestamp,
    pub principal: Principal,
    pub mandate: Mandate,
    pub action: Action,
    pub resource: Resource,
    pub transaction: Transaction,
    #[serde(default = "empty_object")]
    pub context: Value,
    #[serde(default = "empty_object")]
    pub metadata: Value,
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Principal {
    pub organization_id: String,
    #[serde(default)]
    pub user_id: Option<String>,
    pub agent_id: String,
    #[serde(default)]
    pub agent_version: Option<String>,
    #[serde(default)]
    pub strategy_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mandate {
    pub mandate_id: String,
    #[serde(default)]
    pub task_id: Option<String>,
    pub purpose: String,
    #[serde(default)]
    pub budget_id: Option<String>,
    pub human_authorized: bool,
}

/// `category` intentionally stays a plain string rather than a Rust enum:
/// the MVP/next-phase category list (PRD §9.3) is expected to grow, and the
/// JSON Schema (`schemas/transaction-intent.schema.json`) is the place that
/// enumerates allowed values without requiring a Rust code change per entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Action {
    pub category: String,
    pub operation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    pub protocol: String,
    #[serde(default)]
    pub venue: Option<String>,
    pub resource_id: String,
    #[serde(default)]
    pub resource_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    pub network: String,
    pub asset: String,
    pub amount: Amount,
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub contract: Option<String>,
    #[serde(default)]
    pub calldata_hash: Option<String>,
    #[serde(default)]
    pub max_fee: Option<Amount>,
    #[serde(default)]
    pub slippage_bps: Option<i64>,
    #[serde(default)]
    pub leverage: Option<Amount>,
}
