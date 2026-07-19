//! Agent identity: registration records and Ed25519 identity-signature
//! verification (PRD §17).
//!
//! This only answers "did this Agent send this Intent, and is it currently
//! allowed to send anything at all" — it says nothing about whether the
//! request itself should be permitted (that's `atf-policy` + `atf-risk`).
//! Persistence (a real Agent store, key rotation driven by an Admin API) is
//! not implemented — see `docs/architecture.md`.

mod error;
mod record;
mod registry;

pub use error::IdentityError;
pub use record::{AgentRecord, AgentStatus};
pub use registry::IdentityRegistry;
