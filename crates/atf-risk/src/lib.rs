//! Financial Risk Engine (PRD §12): deterministic, versioned risk rules over
//! a Transaction Intent.
//!
//! `evaluate` runs the stateless MVP rules; `evaluate_with_history` also
//! runs the rules in `history_rules` that need an `atf_audit::AuditLedger`
//! to check against. See `history_rules` for which PRD §12.2 history-based
//! rules are still not implemented, and why.

mod config;
mod finding;
mod history_rules;
mod rules;
mod severity;

pub use config::RiskConfig;
pub use finding::RiskFinding;
pub use rules::{evaluate, evaluate_with_history};
pub use severity::Severity;
