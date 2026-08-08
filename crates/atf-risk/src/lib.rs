//! Financial Risk Engine (PRD §12): deterministic MVP risk rules over a
//! Transaction Intent and one closed, versioned, canonically hashed Rule Set.
//!
//! `evaluate` runs the stateless MVP rules; `evaluate_with_history` and
//! `evaluate_with_events` also run rules that need verified Audit history.
//! See `history_rules` for which PRD §12.2 history-based rules are still not
//! implemented, and why.

mod config;
mod finding;
mod history_rules;
mod rule_set;
mod rules;
mod severity;

pub use config::RiskConfig;
pub use finding::RiskFinding;
pub use rule_set::{
    AccountingBoundary, MissingDataBehavior, RiskEvaluation, RiskRuleSet, RiskRuleSetError,
};
pub use rules::{
    evaluate, evaluate_at, evaluate_with_events, evaluate_with_events_at, evaluate_with_history,
    evaluate_with_history_at,
};
pub use severity::Severity;
