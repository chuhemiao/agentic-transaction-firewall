//! The canonical Transaction Intent (PRD §9): its Rust type, JSON Schema
//! validation, and canonical hashing.

mod error;
mod hash;
mod types;
mod validate;

pub use error::IntentError;
pub use types::{
    Action, Mandate, Principal, Resource, Transaction, TransactionIntent, SUPPORTED_SPEC_VERSIONS,
};
pub use validate::validate;
