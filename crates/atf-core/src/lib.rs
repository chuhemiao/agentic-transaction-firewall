//! Shared domain primitives used across all ATF crates.
//!
//! Nothing in this crate is transport-, storage-, or protocol-specific. It
//! exists so that "no floating point for money" and "timestamps are always
//! RFC 3339" (PRD §9.1, §35.8) are enforced in one place instead of being
//! re-implemented per crate.

mod amount;
mod error;
mod id;
mod time;

pub use amount::Amount;
pub use error::CoreError;
pub use id::new_ulid;
pub use time::Timestamp;
