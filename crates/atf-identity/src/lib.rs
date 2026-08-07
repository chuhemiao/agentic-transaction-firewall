//! Agent identity: registration records, canonical domain-separated Envelopes
//! and exact-key strict Ed25519 verification (PRD §17).
//!
//! This only answers "did this Agent send this Intent, and is it currently
//! allowed to send anything at all" — it says nothing about whether the
//! request itself should be permitted (that's `atf-policy` + `atf-risk`).
//! Persistent Agent/Key lifecycle and atomic Nonce consumption are not
//! implemented — see `docs/identity-envelope.md` and `docs/architecture.md`.

mod envelope;
mod error;
mod record;
mod registry;

pub use envelope::{EnvelopeVerificationContext, IdentityEnvelope, IDENTITY_ENVELOPE_DOMAIN};
pub use error::IdentityError;
pub use record::{AgentRecord, AgentStatus};
pub use registry::{IdentityRegistry, VerifiedIdentity};
