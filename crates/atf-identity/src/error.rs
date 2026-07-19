use thiserror::Error;

use crate::record::AgentStatus;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum IdentityError {
    #[error("unknown agent `{0}`")]
    UnknownAgent(String),

    #[error("agent `{agent_id}` cannot submit requests while status is {status:?}")]
    AgentNotActive {
        agent_id: String,
        status: AgentStatus,
    },

    #[error("agent `{0}` has no registered signing key")]
    NoRegisteredKey(String),

    #[error("signature verification failed for agent `{0}`")]
    InvalidSignature(String),
}
