//! The ATF Decision model (PRD §10) and today's (partial) merge algorithm.
//!
//! `decide` merges a Policy Kernel result and Risk Findings per PRD §10.1;
//! the Simulator branch of that algorithm is not implemented yet since
//! `atf-simulator` doesn't exist (Phase 3) — see `docs/architecture.md`.

mod decide;
mod types;

pub use decide::decide;
pub use types::{Decision, DecisionKind, Reason};
