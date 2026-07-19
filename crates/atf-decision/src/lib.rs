//! The ATF Decision model (PRD §10) and today's (partial) merge path.
//!
//! See `docs/architecture.md` for what's implemented vs. still pending —
//! notably, the full Policy + Risk + Simulation merge algorithm (PRD §10.1)
//! is not implemented yet; this crate currently only reflects the Policy
//! Kernel's result.

mod decide;
mod types;

pub use decide::decide;
pub use types::{Decision, DecisionKind, Reason};
