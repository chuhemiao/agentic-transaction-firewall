use thiserror::Error;

#[derive(Debug, Error)]
pub enum IntentError {
    #[error("intent is not valid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),

    #[error("intent failed schema validation: {0}")]
    SchemaViolation(String),

    #[error("intent does not match the TransactionIntent shape: {0}")]
    Malformed(#[source] serde_json::Error),
}
