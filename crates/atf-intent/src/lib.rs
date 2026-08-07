//! The canonical Transaction Intent (PRD §9): its Rust type, JSON Schema
//! validation, and canonical hashing.

mod error;
mod hash;
mod semantic;
mod types;
mod validate;

pub use error::{IntentError, SemanticErrorCode, SemanticValidationErrors, SemanticViolation};
pub use semantic::{
    validate_semantics, MAX_IDENTIFIER_BYTES, MAX_INTENT_TTL_SECONDS, MAX_PURPOSE_BYTES,
};
pub use types::{
    Action, Mandate, Principal, Resource, Transaction, TransactionIntent, SUPPORTED_SPEC_VERSIONS,
};
pub use validate::validate;
