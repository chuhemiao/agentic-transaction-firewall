//! The Audit Ledger: hash-chained events (PRD §16). This is the domain
//! logic — event shape, chaining, integrity verification — wrapped by
//! `atf-store` for durable PostgreSQL append. `services/gateway` still uses
//! the process-local ledger on its current Shadow Mode path.

mod error;
mod event;
mod ledger;

pub use error::ChainVerificationError;
pub use event::{AuditEvent, EventType, NewAuditEvent};
pub use ledger::AuditLedger;
