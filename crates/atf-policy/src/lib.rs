//! Validated Cedar Policy Bundle loading and evaluation over canonical
//! Transaction Intents (PRD §11).

mod bundle;
mod error;
mod eval;
mod mapping;

pub use bundle::{PolicyBundle, PolicyBundleLoadContext};
pub use error::PolicyError;
pub use eval::{PolicyDecision, PolicyOutcome};
