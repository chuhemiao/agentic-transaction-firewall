#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecisionError {
    #[error("Decision version is unsupported")]
    UnsupportedVersion,
    #[error("Decision shape is invalid")]
    InvalidShape,
    #[error("Decision Intent binding does not match")]
    IntentBindingMismatch,
    #[error("Decision Evaluation Context binding does not match")]
    ContextBindingMismatch,
    #[error("Policy output identity does not match the Evaluation Context")]
    PolicyBindingMismatch,
    #[error("Risk output identity does not match the Evaluation Context")]
    RiskBindingMismatch,
    #[error("Policy/Risk module ordering is invalid")]
    ModuleOrdering,
    #[error("Decision hash does not match its canonical payload")]
    HashMismatch,
}

impl DecisionError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "DECISION_VERSION_UNSUPPORTED",
            Self::InvalidShape => "DECISION_SHAPE_INVALID",
            Self::IntentBindingMismatch => "DECISION_INTENT_BINDING_MISMATCH",
            Self::ContextBindingMismatch => "DECISION_CONTEXT_BINDING_MISMATCH",
            Self::PolicyBindingMismatch => "DECISION_POLICY_BINDING_MISMATCH",
            Self::RiskBindingMismatch => "DECISION_RISK_BINDING_MISMATCH",
            Self::ModuleOrdering => "DECISION_MODULE_ORDERING_INVALID",
            Self::HashMismatch => "DECISION_HASH_MISMATCH",
        }
    }
}
