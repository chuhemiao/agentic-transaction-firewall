//! Financial Risk Engine (PRD §12): deterministic MVP risk rules over a
//! Transaction Intent. Rule-set version/hash binding is not implemented yet.
//!
//! `evaluate` runs the stateless MVP rules; `evaluate_with_history` and
//! `evaluate_with_events` also run rules that need verified Audit history.
//! See `history_rules` for which PRD §12.2 history-based rules are still not
//! implemented, and why.

mod config;
mod finding;
mod history_rules;
mod rules;
mod severity;

pub use config::RiskConfig;
pub use finding::RiskFinding;
pub use rules::{evaluate, evaluate_with_events, evaluate_with_history};
pub use severity::Severity;
