use std::fmt;

use thiserror::Error;

/// Stable machine-readable codes for common and profile Intent violations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticErrorCode {
    AmountNotPositive,
    MaxFeeNegative,
    LeverageNotPositive,
    SlippageBpsOutOfRange,
    TimestampPrecisionUnsupported,
    TimeOrderInvalid,
    TtlExceedsLimit,
    IntentIdInvalid,
    FieldBlank,
    FieldTooLong,
    FieldInvalidCharacters,
    UnsupportedIntentProfile,
    ProfileFieldRequired,
    ProfileFieldForbidden,
    NetworkIdInvalid,
    AssetIdInvalid,
    AssetNetworkMismatch,
    DestinationIdInvalid,
    DestinationNetworkMismatch,
}

impl SemanticErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AmountNotPositive => "AMOUNT_NOT_POSITIVE",
            Self::MaxFeeNegative => "MAX_FEE_NEGATIVE",
            Self::LeverageNotPositive => "LEVERAGE_NOT_POSITIVE",
            Self::SlippageBpsOutOfRange => "SLIPPAGE_BPS_OUT_OF_RANGE",
            Self::TimestampPrecisionUnsupported => "TIMESTAMP_PRECISION_UNSUPPORTED",
            Self::TimeOrderInvalid => "TIME_ORDER_INVALID",
            Self::TtlExceedsLimit => "TTL_EXCEEDS_LIMIT",
            Self::IntentIdInvalid => "INTENT_ID_INVALID",
            Self::FieldBlank => "FIELD_BLANK",
            Self::FieldTooLong => "FIELD_TOO_LONG",
            Self::FieldInvalidCharacters => "FIELD_INVALID_CHARACTERS",
            Self::UnsupportedIntentProfile => "UNSUPPORTED_INTENT_PROFILE",
            Self::ProfileFieldRequired => "PROFILE_FIELD_REQUIRED",
            Self::ProfileFieldForbidden => "PROFILE_FIELD_FORBIDDEN",
            Self::NetworkIdInvalid => "NETWORK_ID_INVALID",
            Self::AssetIdInvalid => "ASSET_ID_INVALID",
            Self::AssetNetworkMismatch => "ASSET_NETWORK_MISMATCH",
            Self::DestinationIdInvalid => "DESTINATION_ID_INVALID",
            Self::DestinationNetworkMismatch => "DESTINATION_NETWORK_MISMATCH",
        }
    }
}

impl fmt::Display for SemanticErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One semantic violation. `field` is a stable dotted path, never user input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticViolation {
    pub code: SemanticErrorCode,
    pub field: &'static str,
}

impl SemanticViolation {
    pub(crate) const fn new(code: SemanticErrorCode, field: &'static str) -> Self {
        Self { code, field }
    }
}

/// Deterministically ordered semantic violations for one Intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticValidationErrors {
    violations: Vec<SemanticViolation>,
}

impl SemanticValidationErrors {
    pub(crate) fn new(violations: Vec<SemanticViolation>) -> Self {
        debug_assert!(!violations.is_empty());
        Self { violations }
    }

    pub fn violations(&self) -> &[SemanticViolation] {
        &self.violations
    }
}

impl fmt::Display for SemanticValidationErrors {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("intent failed semantic validation: ")?;
        for (index, violation) in self.violations.iter().enumerate() {
            if index > 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{} ({})", violation.code, violation.field)?;
        }
        Ok(())
    }
}

impl std::error::Error for SemanticValidationErrors {}

#[derive(Debug, Error)]
pub enum IntentError {
    #[error("intent is not valid JSON: {0}")]
    InvalidJson(#[source] serde_json::Error),

    #[error("intent failed schema validation: {0}")]
    SchemaViolation(String),

    #[error("intent does not match the TransactionIntent shape: {0}")]
    Malformed(#[source] serde_json::Error),

    #[error(transparent)]
    Semantic(#[from] SemanticValidationErrors),
}
