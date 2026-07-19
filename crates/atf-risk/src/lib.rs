//! Financial Risk Engine (PRD §12): deterministic, versioned risk rules over
//! a Transaction Intent.
//!
//! Only the stateless MVP rules are implemented so far — see `rules.rs` for
//! which PRD §12.2 rules are still pending on `atf-audit`/persistence
//! (Phase 2).

mod config;
mod finding;
mod rules;
mod severity;

pub use config::RiskConfig;
pub use finding::RiskFinding;
pub use rules::evaluate;
pub use severity::Severity;
