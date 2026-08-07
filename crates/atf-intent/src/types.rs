use atf_core::{Amount, Timestamp};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

/// Intent wire versions accepted by this release.
///
/// Adding a value is a compatibility decision: the JSON Schema, Rust parser,
/// fixtures, profiles, and Gateway support must advance together.
pub const SUPPORTED_SPEC_VERSIONS: &[&str] = &["1.0"];

/// Canonical Transaction Intent (PRD §9.2).
///
/// Field shapes here are the "core fields" the PRD says must not change
/// without a compatibility plan (§9.1.6, §37). `context` and `metadata` are
/// deliberately untyped JSON objects — they are the extension points.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransactionIntent {
    #[serde(deserialize_with = "deserialize_supported_spec_version")]
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
    #[serde(
        default = "empty_object",
        deserialize_with = "deserialize_extension_object"
    )]
    pub context: Value,
    #[serde(
        default = "empty_object",
        deserialize_with = "deserialize_extension_object"
    )]
    pub metadata: Value,
}

fn empty_object() -> Value {
    Value::Object(Map::new())
}

fn deserialize_supported_spec_version<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let version = String::deserialize(deserializer)?;
    if SUPPORTED_SPEC_VERSIONS.contains(&version.as_str()) {
        Ok(version)
    } else {
        Err(D::Error::custom(format!(
            "unsupported spec_version {version:?}; supported versions: {}",
            SUPPORTED_SPEC_VERSIONS.join(", ")
        )))
    }
}

fn deserialize_extension_object<'de, D>(deserializer: D) -> Result<Value, D::Error>
where
    D: Deserializer<'de>,
{
    let value = Value::deserialize(deserializer)?;
    if value.is_object() {
        Ok(value)
    } else {
        Err(D::Error::custom(
            "extension namespace must be a JSON object",
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
pub struct Mandate {
    pub mandate_id: String,
    #[serde(default)]
    pub task_id: Option<String>,
    pub purpose: String,
    #[serde(default)]
    pub budget_id: Option<String>,
    pub human_authorized: bool,
}

/// `category` intentionally stays a plain string rather than a Rust enum.
/// The common JSON Schema enumerates the envelope vocabulary; the closed
/// profile dispatcher separately decides which category/operation pairs have
/// enforceable semantics in this release.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub category: String,
    pub operation: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resource {
    pub protocol: String,
    #[serde(default)]
    pub venue: Option<String>,
    pub resource_id: String,
    #[serde(default)]
    pub resource_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
