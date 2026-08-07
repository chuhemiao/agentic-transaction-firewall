//! Agent identity: registration records, canonical domain-separated Envelopes
//! and exact-key strict Ed25519 verification (PRD §17).
//!
//! This only answers "did this Agent send this Intent, and is it currently
//! allowed to send anything at all" — it says nothing about whether the
//! request itself should be permitted (that's `atf-policy` + `atf-risk`).
//! Persistent Agent/Key lifecycle is provided by `atf-store`; Gateway wiring
//! and atomic Nonce consumption remain separate admission concerns. See
//! `docs/identity.md` and `docs/identity-envelope.md`.

mod envelope;
mod error;
mod key;
mod record;
mod registry;

pub use envelope::{EnvelopeVerificationContext, IdentityEnvelope, IDENTITY_ENVELOPE_DOMAIN};
pub use error::IdentityError;
pub use key::IdentityKeyRecord;
pub use record::{AgentRecord, AgentStatus};
pub use registry::{IdentityRegistry, VerifiedIdentity};
