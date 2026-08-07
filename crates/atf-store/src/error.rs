use sqlx::migrate::MigrateError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("typed Audit payload is invalid: {0}")]
    AuditPayload(#[from] atf_audit::AuditPayloadError),

    #[error("identity domain rejected durable state: {0}")]
    IdentityDomain(#[from] atf_identity::IdentityError),

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

    #[error("Agent `{agent_id}` already exists in organization `{organization_id}`")]
    AgentConflict {
        organization_id: String,
        agent_id: String,
    },

    #[error("Agent `{agent_id}` does not exist in organization `{organization_id}`")]
    AgentNotFound {
        organization_id: String,
        agent_id: String,
    },

    #[error("identity key `{key_id}` already exists for Agent `{agent_id}` in organization `{organization_id}`")]
    IdentityKeyConflict {
        organization_id: String,
        agent_id: String,
        key_id: String,
    },

    #[error("identity key `{key_id}` does not exist for Agent `{agent_id}` in organization `{organization_id}`")]
    IdentityKeyNotFound {
        organization_id: String,
        agent_id: String,
        key_id: String,
    },

    #[error("durable identity state for Agent `{agent_id}` in organization `{organization_id}` is corrupt: {reason}")]
    IdentityStateCorrupt {
        organization_id: String,
        agent_id: String,
        reason: String,
    },

    #[error("request identity was rejected with stable reason `{reason_code}`")]
    IdentityRejected { reason_code: &'static str },

    #[error(
        "identity Nonce replay detected for Agent `{agent_id}` in organization `{organization_id}` (hash `{nonce_hash}`)"
    )]
    NonceReplay {
        organization_id: String,
        agent_id: String,
        nonce_hash: String,
    },

    #[error("durable identity Nonce state for Agent `{agent_id}` in organization `{organization_id}` is corrupt: {reason}")]
    NonceStateCorrupt {
        organization_id: String,
        agent_id: String,
        reason: String,
    },

    #[error(
        "Intent admission conflicts with an immutable record in organization `{organization_id}` (intent `{intent_id}`, idempotency key `{idempotency_key}`)"
    )]
    IntentConflict {
        organization_id: String,
        intent_id: String,
        idempotency_key: String,
    },

    #[error(
        "idempotency key `{idempotency_key}` in organization `{organization_id}` is already bound to a different Intent hash"
    )]
    IdempotencyConflict {
        organization_id: String,
        idempotency_key: String,
        submitted_hash: String,
        stored_hash: String,
    },

    #[error(
        "idempotency key `{idempotency_key}` does not exist in organization `{organization_id}`"
    )]
    IdempotencyNotFound {
        organization_id: String,
        idempotency_key: String,
    },

    #[error(
        "idempotency key `{idempotency_key}` in organization `{organization_id}` is already in progress for Intent `{intent_id}` until {lease_expires_at}"
    )]
    IdempotencyInProgress {
        organization_id: String,
        idempotency_key: String,
        intent_id: String,
        lease_expires_at: atf_core::Timestamp,
    },

    #[error(
        "idempotency key `{idempotency_key}` in organization `{organization_id}` is already completed by Decision `{decision_id}`"
    )]
    IdempotencyCompleted {
        organization_id: String,
        idempotency_key: String,
        intent_id: String,
        decision_id: String,
    },

    #[error(
        "evaluator lease generation {generation} was lost for idempotency key `{idempotency_key}` in organization `{organization_id}`"
    )]
    EvaluatorLeaseLost {
        organization_id: String,
        idempotency_key: String,
        intent_id: String,
        generation: i64,
    },

    #[error(
        "recovered idempotency work for Intent `{intent_id}` in organization `{organization_id}` must terminate with a fail-closed ERROR Decision before Evaluation Context snapshots exist"
    )]
    RecoveredWorkMustFailClosed {
        organization_id: String,
        intent_id: String,
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
