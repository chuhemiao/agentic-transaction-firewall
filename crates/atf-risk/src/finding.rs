use serde::{Deserialize, Serialize};

use crate::severity::Severity;

/// A standardized Risk Finding (PRD §12.1.3): every rule that fires produces
/// one of these, regardless of which rule it was.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RiskFinding {
    pub code: String,
    pub severity: Severity,
    pub message: String,
}
