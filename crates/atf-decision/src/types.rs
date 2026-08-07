use serde::{Deserialize, Serialize};

/// PRD §10.2. `Review` is produced when the Risk Engine returns a `High`
/// finding; the future Simulator branch can also produce it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionKind {
    Permit,
    Deny,
    Review,
    Error,
}

/// A single contributing reason for a Decision (PRD §10 `reasons`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reason {
    pub code: String,
    pub severity: String,
    pub message: String,
}

/// PRD §10: today this reflects the merged Policy/Risk outcome. Strong
/// binding fields (`intent_hash`, policy/risk/context/simulation hashes,
/// expiry, constraints, `decision_hash`) and Approval output are omitted
/// until their versioned inputs exist; see `docs/audit-gap-matrix.md`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub decision_id: String,
    pub intent_id: String,
    pub decision: DecisionKind,
    pub reasons: Vec<Reason>,
}
