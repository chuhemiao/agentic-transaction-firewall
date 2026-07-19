use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to parse Cedar policy set: {0}")]
    Parse(String),

    #[error("failed to read policy bundle: {0}")]
    Io(String),

    #[error("failed to build Cedar request from intent: {0}")]
    RequestBuild(String),

    #[error("failed to build Cedar context from intent: {0}")]
    ContextBuild(String),
}
