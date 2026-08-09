//! Financial Risk Engine (PRD §12): deterministic MVP risk rules over a
//! Transaction Intent and one closed, versioned, canonically hashed Rule Set.
//!
//! The public evaluator accepts one immutable `EvaluationContext` and one
//! typed bounded history snapshot at the repository boundary named by that
//! Context. It never reads Audit events, samples time, or accepts separately
//! supplied privileged financial inputs.

mod config;
mod context;
mod error;
mod finding;
mod history_rules;
mod rule_set;
mod rules;
mod severity;

pub use atf_core::AccountingBoundary;
pub use config::RiskConfig;
pub use error::RiskEvaluationError;
pub use finding::RiskFinding;
pub use rule_set::{MissingDataBehavior, RiskEvaluation, RiskRuleSet, RiskRuleSetError};
pub use rules::evaluate_context;
pub use severity::Severity;
