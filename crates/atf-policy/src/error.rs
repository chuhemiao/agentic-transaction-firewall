use thiserror::Error;

use atf_core::Timestamp;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("failed to parse Cedar policy set: {0}")]
    Parse(String),

    #[error("failed to read policy bundle: {0}")]
    Io(String),

    #[error("policy bundle manifest is not valid JSON: {0}")]
    ManifestJson(String),

    #[error("policy bundle manifest failed JSON Schema validation: {0}")]
    ManifestSchema(String),

    #[error("policy bundle manifest is invalid: {0}")]
    Manifest(String),

    #[error("policy bundle load context is invalid")]
    InvalidLoadContext,

    #[error("policy bundle scope does not match organization/environment")]
    ScopeMismatch {
        expected_organization_id: String,
        expected_environment: String,
    },

    #[error(
        "policy bundle is inactive at {evaluated_at}; active from {activates_at} until {expires_at}"
    )]
    Inactive {
        activates_at: Timestamp,
        expires_at: Timestamp,
        evaluated_at: Timestamp,
    },

    #[error("invalid policy bundle file path: {0}")]
    InvalidFilePath(String),

    #[error("policy bundle file {path} exceeds the {max_bytes}-byte limit")]
    FileTooLarge { path: String, max_bytes: u64 },

    #[error("policy bundle files exceed the {max_bytes}-byte total limit")]
    BundleTooLarge { max_bytes: u64 },

    #[error("duplicate policy bundle file: {0}")]
    DuplicateFile(String),

    #[error("policy bundle files must be listed in ascending path order")]
    FilesNotSorted,

    #[error("unlisted Cedar policy file: {0}")]
    UnlistedPolicyFile(String),

    #[error("digest mismatch for policy bundle file {path}: expected {expected}, got {actual}")]
    FileDigestMismatch {
        path: String,
        expected: String,
        actual: String,
    },

    #[error("policy bundle hash mismatch: expected {expected}, got {actual}")]
    BundleHashMismatch { expected: String, actual: String },

    #[error("failed to parse Cedar schema: {0}")]
    CedarSchema(String),

    #[error("Cedar policy validation failed: {0}")]
    CedarValidation(String),

    #[error("Cedar authorization produced runtime diagnostics: {0}")]
    Authorization(String),

    #[error("failed to build Cedar request from intent: {0}")]
    RequestBuild(String),

    #[error("failed to build Cedar context from intent: {0}")]
    ContextBuild(String),
}
