//! The canonical Transaction Intent (PRD §9): its Rust type, JSON Schema
//! validation, and canonical hashing.

mod destination;
mod error;
mod hash;
mod profile;
mod profiles;
mod semantic;
mod types;
mod validate;

pub use destination::{
    normalize_destination, normalize_destination_value, DestinationNormalizationError,
    ProfileNormalizedDestination, PAYMENT_DESTINATION_NORMALIZER_ID,
    PAYMENT_DESTINATION_NORMALIZER_VERSION,
};
pub use error::{IntentError, SemanticErrorCode, SemanticValidationErrors, SemanticViolation};
pub use profile::{
    validate_profile, IntentProfile, AGENT_COMMERCE_PAYMENT_PROFILE,
    AGENT_COMMERCE_PAYMENT_PROFILE_ID, AGENT_COMMERCE_PAYMENT_PROFILE_VERSION,
};
pub use semantic::{
    validate_semantics, MAX_IDENTIFIER_BYTES, MAX_INTENT_TTL_SECONDS, MAX_PURPOSE_BYTES,
};
pub use types::{
    Action, Mandate, Principal, Resource, Transaction, TransactionIntent, SUPPORTED_SPEC_VERSIONS,
};
pub use validate::validate;
