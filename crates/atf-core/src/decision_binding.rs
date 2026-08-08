use serde::{Deserialize, Serialize};

use crate::Amount;

/// Stable Intent Profile identity carried by Evaluation Context, Decision and
/// DecisionRecorded evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileBinding {
    pub id: String,
    pub version: String,
}

/// Future Approval requirements remain explicit in Decision v1. The current
/// Shadow Gateway emits an empty list because no Approval Engine exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequiredApproval {
    pub role: String,
    pub count: u32,
}

/// Future post-decision obligations remain explicit and hash-bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionObligation {
    #[serde(rename = "type")]
    pub obligation_type: String,
}

/// Closed constraints for any future execution request. `adapter_id` is
/// explicitly absent until Adapter selection exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionConstraints {
    pub action_category: String,
    pub action_operation: String,
    pub resource_id: String,
    pub resource_protocol: String,
    pub network: String,
    pub asset: String,
    pub max_amount: Amount,
    pub destination: Option<String>,
    pub adapter_id: Option<String>,
}
