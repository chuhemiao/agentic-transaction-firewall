use atf_core::{Amount, Timestamp};
use serde::{Deserialize, Serialize};

/// Agent status (PRD §17.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AgentStatus {
    Active,
    ShadowOnly,
    Paused,
    Revoked,
    Expired,
}

impl AgentStatus {
    /// Whether an Agent in this status may submit requests at all, through
    /// any mode including Shadow Mode. `PAUSED`/`REVOKED`/`EXPIRED` never
    /// may — this is a registry-level circuit breaker independent of, and
    /// checked before, any Policy or Risk evaluation.
    pub fn may_submit_requests(self) -> bool {
        matches!(self, AgentStatus::Active | AgentStatus::ShadowOnly)
    }
}

/// Agent registration record (PRD §17.1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub agent_id: String,
    pub organization_id: String,
    pub owner_user_id: String,
    pub agent_type: String,
    pub model_provider: String,
    pub model_name: String,
    pub agent_version: String,
    pub code_hash: String,
    pub deployment_environment: String,
    pub allowed_tools: Vec<String>,
    pub allowed_adapters: Vec<String>,
    pub default_budget: Option<Amount>,
    pub risk_tier: String,
    pub status: AgentStatus,
    pub created_at: Timestamp,
    pub expires_at: Option<Timestamp>,
}
