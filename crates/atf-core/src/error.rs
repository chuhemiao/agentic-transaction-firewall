use thiserror::Error;

/// Errors shared across ATF crates for the core domain primitives.
///
/// Every variant here represents an input that must be rejected rather than
/// coerced — per the project's fail-closed principle (PRD §18.1, §35.15),
/// callers must not paper over these with a default value.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CoreError {
    #[error("invalid amount `{0}`: must be a fixed-point decimal string")]
    InvalidAmount(String),

    #[error("invalid timestamp `{0}`: must be RFC 3339")]
    InvalidTimestamp(String),

    #[error("invalid id `{0}`: {1}")]
    InvalidId(String, String),
}
