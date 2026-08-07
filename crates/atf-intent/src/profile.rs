use crate::error::{SemanticErrorCode, SemanticValidationErrors, SemanticViolation};
use crate::profiles::payment;
use crate::types::TransactionIntent;

pub const AGENT_COMMERCE_PAYMENT_PROFILE_ID: &str = "atf.agent-commerce.payment";
pub const AGENT_COMMERCE_PAYMENT_PROFILE_VERSION: &str = "1.0";

/// Stable profile metadata derivable from a validated Intent.
///
/// Fields are intentionally read-only so callers bind the declared profile
/// rather than constructing an arbitrary ID/version pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntentProfile {
    id: &'static str,
    version: &'static str,
}

impl IntentProfile {
    pub const fn id(self) -> &'static str {
        self.id
    }

    pub const fn version(self) -> &'static str {
        self.version
    }
}

pub const AGENT_COMMERCE_PAYMENT_PROFILE: IntentProfile = IntentProfile {
    id: AGENT_COMMERCE_PAYMENT_PROFILE_ID,
    version: AGENT_COMMERCE_PAYMENT_PROFILE_VERSION,
};

/// Resolve and validate the one profile supported by this release.
///
/// Profile selection is closed. A category being present in the common JSON
/// Schema never implies that ATF knows how to evaluate its financial meaning.
pub fn validate_profile(
    intent: &TransactionIntent,
) -> Result<IntentProfile, SemanticValidationErrors> {
    match (
        intent.spec_version.as_str(),
        intent.action.category.as_str(),
        intent.action.operation.as_str(),
    ) {
        ("1.0", "payment", "purchase_api_resource") => {
            payment::validate(intent)?;
            Ok(AGENT_COMMERCE_PAYMENT_PROFILE)
        }
        _ => Err(SemanticValidationErrors::new(vec![SemanticViolation::new(
            SemanticErrorCode::UnsupportedIntentProfile,
            "action",
        )])),
    }
}
