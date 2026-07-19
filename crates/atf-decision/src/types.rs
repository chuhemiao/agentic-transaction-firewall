use serde::{Deserialize, Serialize};

/// PRD §10.2. `Review` exists as a variant today even though nothing in this
/// crate can produce it yet — see `docs/architecture.md` for why (no Risk
/// Engine or Simulator wired in).
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

/// PRD §10: today this only reflects the Policy Kernel result. `risk_score`,
/// `policy_version`, `required_approvals`, and `obligations` are omitted
/// rather than stubbed out, since nothing produces real values for them yet
/// (Risk Engine, Approval Engine — Phase 2/4). Add them when those crates
/// exist instead of guessing their shape now.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub decision_id: String,
    pub intent_id: String,
    pub decision: DecisionKind,
    pub reasons: Vec<Reason>,
}
