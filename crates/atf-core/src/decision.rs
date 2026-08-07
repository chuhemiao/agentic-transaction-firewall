use serde::{Deserialize, Serialize};

/// The stable outcome shared by Decision, lifecycle, and Audit contracts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionKind {
    Permit,
    Deny,
    Review,
    Error,
}
