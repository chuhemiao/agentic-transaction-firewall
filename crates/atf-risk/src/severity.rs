use std::fmt;

use serde::{Deserialize, Serialize};

/// Ordered so that `Severity::Critical` is the maximum — the Decision merge
/// (PRD §10.1, implemented in `atf-decision`) picks the worst finding across
/// all rules that fired, and relies on this ordering to do it with a plain
/// `.max()`. Declaration order is the derive-order for `Ord`, so don't
/// reorder these variants without checking that call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Severity::Info => "info",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn critical_is_the_max() {
        let worst = [Severity::Info, Severity::Critical, Severity::High]
            .into_iter()
            .max()
            .unwrap();
        assert_eq!(worst, Severity::Critical);
    }
}
