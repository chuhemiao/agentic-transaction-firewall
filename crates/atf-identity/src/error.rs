use thiserror::Error;

use crate::record::AgentStatus;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("identity envelope domain is not supported")]
    DomainMismatch,

    #[error("identity envelope field `{field}` is invalid")]
    InvalidEnvelopeField { field: &'static str },

    #[error("identity envelope organization does not match the Intent")]
    OrganizationMismatch,

    #[error("identity envelope Agent does not match the Intent")]
    AgentMismatch,

    #[error("identity envelope hash does not match the Intent")]
    IntentHashMismatch,

    #[error("identity envelope audience does not match the verifier")]
    AudienceMismatch,

    #[error("identity envelope environment does not match the verifier")]
    EnvironmentMismatch,

    #[error("identity envelope issued_at must precede expires_at")]
    EnvelopeTimeRangeInvalid,

    #[error("identity envelope lifetime exceeds the supported maximum")]
    EnvelopeLifetimeExceeded,

    #[error("identity envelope is not valid yet")]
    EnvelopeNotYetValid,

    #[error("identity envelope has expired")]
    EnvelopeExpired,

    #[error("identity envelope lifetime falls outside the Intent lifetime")]
    EnvelopeOutsideIntentLifetime,

    #[error("unknown agent `{0}`")]
    UnknownAgent(String),

    #[error("agent `{agent_id}` cannot submit requests while status is {status:?}")]
    AgentNotActive {
        agent_id: String,
        status: AgentStatus,
    },

    #[error("agent `{agent_id}` belongs to a different organization")]
    AgentOrganizationMismatch { agent_id: String },

    #[error("agent `{agent_id}` belongs to a different deployment environment")]
    AgentEnvironmentMismatch { agent_id: String },

    #[error("agent `{agent_id}` was not active when the envelope was issued")]
    AgentNotYetActive { agent_id: String },

    #[error("agent `{agent_id}` has expired")]
    AgentExpired { agent_id: String },

    #[error("identity envelope outlives agent `{agent_id}`")]
    EnvelopeExceedsAgentLifetime { agent_id: String },

    #[error("key `{key_id}` is already registered for agent `{agent_id}`")]
    DuplicateKeyId { agent_id: String, key_id: String },

    #[error("key `{key_id}` is not registered for agent `{agent_id}`")]
    UnknownKey { agent_id: String, key_id: String },

    #[error("signature verification failed for agent `{agent_id}` key `{key_id}`")]
    InvalidSignature { agent_id: String, key_id: String },
}

impl IdentityError {
    /// Stable machine-readable code for API/Audit mapping. Error text is for
    /// local diagnostics and must not be used as a protocol contract.
    pub fn code(&self) -> &'static str {
        match self {
            Self::DomainMismatch => "IDENTITY_DOMAIN_MISMATCH",
            Self::InvalidEnvelopeField { .. } => "IDENTITY_ENVELOPE_FIELD_INVALID",
            Self::OrganizationMismatch => "IDENTITY_ORGANIZATION_MISMATCH",
            Self::AgentMismatch => "IDENTITY_AGENT_MISMATCH",
            Self::IntentHashMismatch => "IDENTITY_INTENT_HASH_MISMATCH",
            Self::AudienceMismatch => "IDENTITY_AUDIENCE_MISMATCH",
            Self::EnvironmentMismatch => "IDENTITY_ENVIRONMENT_MISMATCH",
            Self::EnvelopeTimeRangeInvalid => "IDENTITY_ENVELOPE_TIME_RANGE_INVALID",
            Self::EnvelopeLifetimeExceeded => "IDENTITY_ENVELOPE_LIFETIME_EXCEEDED",
            Self::EnvelopeNotYetValid => "IDENTITY_ENVELOPE_NOT_YET_VALID",
            Self::EnvelopeExpired => "IDENTITY_ENVELOPE_EXPIRED",
            Self::EnvelopeOutsideIntentLifetime => "IDENTITY_ENVELOPE_OUTSIDE_INTENT_LIFETIME",
            Self::UnknownAgent(_) => "IDENTITY_AGENT_UNKNOWN",
            Self::AgentNotActive { .. } => "IDENTITY_AGENT_NOT_ACTIVE",
            Self::AgentOrganizationMismatch { .. } => "IDENTITY_AGENT_ORGANIZATION_MISMATCH",
            Self::AgentEnvironmentMismatch { .. } => "IDENTITY_AGENT_ENVIRONMENT_MISMATCH",
            Self::AgentNotYetActive { .. } => "IDENTITY_AGENT_NOT_YET_ACTIVE",
            Self::AgentExpired { .. } => "IDENTITY_AGENT_EXPIRED",
            Self::EnvelopeExceedsAgentLifetime { .. } => "IDENTITY_ENVELOPE_EXCEEDS_AGENT_LIFETIME",
            Self::DuplicateKeyId { .. } => "IDENTITY_KEY_ALREADY_REGISTERED",
            Self::UnknownKey { .. } => "IDENTITY_KEY_NOT_REGISTERED",
            Self::InvalidSignature { .. } => "IDENTITY_SIGNATURE_INVALID",
        }
    }
}
