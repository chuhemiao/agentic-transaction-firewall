#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RiskEvaluationError {
    #[error("Evaluation Context does not authorize this Risk evaluation: {0}")]
    ContextBinding(String),
    #[error("the authoritative Risk Rule Set is unavailable")]
    RuleSetUnavailable,
    #[error("Evaluation Context references a different Risk Rule Set")]
    RuleSetMismatch,
    #[error("Evaluation Context history does not match the supplied verified Audit chain: {0}")]
    HistoryBinding(String),
}

impl RiskEvaluationError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::ContextBinding(_) => "RISK_CONTEXT_BINDING_MISMATCH",
            Self::RuleSetUnavailable => "RISK_RULE_SET_UNAVAILABLE",
            Self::RuleSetMismatch => "RISK_RULE_SET_MISMATCH",
            Self::HistoryBinding(_) => "RISK_HISTORY_BINDING_MISMATCH",
        }
    }
}
