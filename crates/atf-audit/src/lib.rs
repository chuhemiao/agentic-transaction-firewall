//! The Audit Ledger: hash-chained events (PRD §16). This is the domain
//! logic — event shape, chaining, integrity verification — that a
//! persistent (PostgreSQL, per the PRD's MVP design) implementation would
//! wrap. `services/gateway` appends request/evaluation/decision events on
//! its live Shadow Mode path; the ledger itself is still process-local.

mod error;
mod event;
mod ledger;

pub use error::ChainVerificationError;
pub use event::{AuditEvent, EventType};
pub use ledger::AuditLedger;
