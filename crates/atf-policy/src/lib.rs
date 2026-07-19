//! Minimal Cedar policy evaluation over a canonical Transaction Intent
//! (PRD §11). Loads a `PolicySet`, maps a `TransactionIntent` onto a Cedar
//! `Request`, and evaluates it.
//!
//! Not yet implemented: Policy Bundle versioning/signing, multi-bundle
//! conflict resolution (PRD §11.3), and Cedar schema-based validation of the
//! policy bundle itself — tracked in `docs/architecture.md`.

mod error;
mod eval;
mod mapping;

pub use error::PolicyError;
pub use eval::{PolicyBundle, PolicyDecision, PolicyOutcome};
