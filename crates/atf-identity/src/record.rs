use atf_core::{Amount, Timestamp};
use serde::{Deserialize, Serialize};

use crate::envelope::is_canonical_identifier;

const MAX_CAPABILITY_COUNT: usize = 64;

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

    /// Enforce the persisted Agent lifecycle. Revoked and expired records are
    /// terminal, and writing the current state again is not a transition.
    pub fn validate_transition_to(self, next: Self) -> Result<(), crate::IdentityError> {
        if self == next || matches!(self, Self::Revoked | Self::Expired) {
            return Err(crate::IdentityError::InvalidAgentStatusTransition {
                from: self,
                to: next,
            });
        }
        Ok(())
    }
}

/// Agent registration record (PRD §17.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

impl AgentRecord {
    /// Validate the canonical record before it becomes durable authority.
    pub fn validate(&self) -> Result<(), crate::IdentityError> {
        for (field, value) in [
            ("agent_id", self.agent_id.as_str()),
            ("organization_id", self.organization_id.as_str()),
            ("owner_user_id", self.owner_user_id.as_str()),
            ("agent_type", self.agent_type.as_str()),
            ("model_provider", self.model_provider.as_str()),
            ("model_name", self.model_name.as_str()),
            ("agent_version", self.agent_version.as_str()),
            (
                "deployment_environment",
                self.deployment_environment.as_str(),
            ),
            ("risk_tier", self.risk_tier.as_str()),
        ] {
            if !is_canonical_identifier(value, 1) {
                return Err(crate::IdentityError::InvalidAgentField { field });
            }
        }
        if self.code_hash.len() != 64
            || !self
                .code_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(crate::IdentityError::InvalidAgentField { field: "code_hash" });
        }
        for (field, values) in [
            ("allowed_tools", self.allowed_tools.as_slice()),
            ("allowed_adapters", self.allowed_adapters.as_slice()),
        ] {
            if values.len() > MAX_CAPABILITY_COUNT
                || values
                    .iter()
                    .any(|value| !is_canonical_identifier(value, 1))
                || values.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(crate::IdentityError::InvalidAgentField { field });
            }
        }
        if self
            .default_budget
            .is_some_and(|amount| amount.is_negative())
        {
            return Err(crate::IdentityError::InvalidAgentField {
                field: "default_budget",
            });
        }
        if !millisecond_aligned(self.created_at) {
            return Err(crate::IdentityError::InvalidAgentField {
                field: "created_at",
            });
        }
        if let Some(expires_at) = self.expires_at {
            if !millisecond_aligned(expires_at) || expires_at <= self.created_at {
                return Err(crate::IdentityError::InvalidAgentField {
                    field: "expires_at",
                });
            }
        }
        Ok(())
    }

    /// Explicitly sorted compact JSON used by persistence and Audit binding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let value = serde_json::to_value(self).expect("AgentRecord always serializes to JSON");
        serde_json::to_vec(&atf_core::sort_json_keys(value))
            .expect("canonical AgentRecord always serializes")
    }

    pub fn canonical_hash(&self) -> String {
        atf_core::sha256_hex(&self.canonical_bytes())
    }
}

fn millisecond_aligned(timestamp: Timestamp) -> bool {
    timestamp.as_datetime().timestamp_subsec_nanos() % 1_000_000 == 0
}
