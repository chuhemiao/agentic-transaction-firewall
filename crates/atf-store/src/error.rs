use sqlx::migrate::MigrateError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("typed Audit payload is invalid: {0}")]
    AuditPayload(#[from] atf_audit::AuditPayloadError),

    #[error("PostgreSQL operation failed: {0}")]
    Database(#[from] sqlx::Error),

    #[error("PostgreSQL migration failed: {0}")]
    Migration(#[from] MigrateError),

    #[error("ATF durable-state schema metadata is missing")]
    MissingSchemaMetadata,

    #[error(
        "incompatible ATF durable-state schema: binary={binary_version}, database={database_version}, minimum_reader={minimum_reader_version}, minimum_writer={minimum_writer_version}"
    )]
    IncompatibleSchema {
        binary_version: i32,
        database_version: i32,
        minimum_reader_version: i32,
        minimum_writer_version: i32,
    },

    #[error("invalid Audit event: {reason}")]
    InvalidAuditEvent { reason: &'static str },

    #[error("invalid durable-state input: {reason}")]
    InvalidRepositoryInput { reason: String },

    #[error("organization `{organization_id}` does not exist")]
    OrganizationNotFound { organization_id: String },

    #[error(
        "Intent admission conflicts with an immutable record in organization `{organization_id}` (intent `{intent_id}`, idempotency key `{idempotency_key}`)"
    )]
    IntentConflict {
        organization_id: String,
        intent_id: String,
        idempotency_key: String,
    },

    #[error("Intent `{intent_id}` does not exist in organization `{organization_id}`")]
    IntentNotFound {
        organization_id: String,
        intent_id: String,
    },

    #[error(
        "Intent hash mismatch for `{intent_id}` in organization `{organization_id}`: expected `{expected}`, stored `{stored}`"
    )]
    IntentHashMismatch {
        organization_id: String,
        intent_id: String,
        expected: String,
        stored: String,
    },

    #[error(
        "lifecycle conflict for Intent `{intent_id}` in organization `{organization_id}`: expected version {expected_version}, stored version {stored_version} at state {stored_state}"
    )]
    LifecycleConflict {
        organization_id: String,
        intent_id: String,
        expected_version: i64,
        stored_version: i64,
        stored_state: String,
    },

    #[error("Decision is not bound to the requested Intent: {reason}")]
    DecisionBindingMismatch { reason: String },

    #[error(
        "Intent `{intent_id}` in organization `{organization_id}` already has a final Decision"
    )]
    DecisionConflict {
        organization_id: String,
        intent_id: String,
    },

    #[error(
        "finalization for Intent `{intent_id}` in organization `{organization_id}` conflicts with an immutable Evaluation or Decision record"
    )]
    FinalizationConflict {
        organization_id: String,
        intent_id: String,
    },

    #[error("durable state for organization `{organization_id}` is corrupt: {reason}")]
    DurableStateCorrupt {
        organization_id: String,
        reason: String,
    },

    #[error(
        "admitted Intent `{intent_id}` in organization `{organization_id}` lacks complete Audit evidence"
    )]
    IncompleteAdmissionEvidence {
        organization_id: String,
        intent_id: String,
    },

    #[error(
        "Decision for Intent `{intent_id}` in organization `{organization_id}` lacks complete Evaluation/Audit evidence"
    )]
    IncompleteDecisionEvidence {
        organization_id: String,
        intent_id: String,
    },

    #[error("Audit chain for organization `{organization_id}` is corrupt: {reason}")]
    AuditChainCorrupt {
        organization_id: String,
        reason: String,
    },

    #[error("durable JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
}
