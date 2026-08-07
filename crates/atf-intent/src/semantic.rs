use std::str::FromStr;

use atf_core::Amount;
use ulid::Ulid;

use crate::error::{SemanticErrorCode, SemanticValidationErrors, SemanticViolation};
use crate::types::TransactionIntent;

/// Hard common limit. Action Profiles may impose a shorter lifetime.
pub const MAX_INTENT_TTL_SECONDS: i64 = 24 * 60 * 60;
pub const MAX_IDENTIFIER_BYTES: usize = 256;
pub const MAX_PURPOSE_BYTES: usize = 1024;

const NANOS_PER_MILLISECOND: u32 = 1_000_000;
const MAX_INTENT_TTL_NANOS: i64 = MAX_INTENT_TTL_SECONDS * 1_000_000_000;

/// Validate cross-field invariants shared by every Intent Profile.
///
/// Violations are accumulated in this function's explicit rule order so the
/// same input always produces the same machine-readable result.
pub fn validate_semantics(intent: &TransactionIntent) -> Result<(), SemanticValidationErrors> {
    let mut violations = Vec::new();

    validate_financial_fields(intent, &mut violations);
    validate_time_fields(intent, &mut violations);
    validate_identity_and_text_fields(intent, &mut violations);

    if violations.is_empty() {
        Ok(())
    } else {
        Err(SemanticValidationErrors::new(violations))
    }
}

fn validate_financial_fields(intent: &TransactionIntent, violations: &mut Vec<SemanticViolation>) {
    if intent.transaction.amount <= Amount::ZERO {
        push(
            violations,
            SemanticErrorCode::AmountNotPositive,
            "transaction.amount",
        );
    }
    if intent
        .transaction
        .max_fee
        .is_some_and(|max_fee| max_fee.is_negative())
    {
        push(
            violations,
            SemanticErrorCode::MaxFeeNegative,
            "transaction.max_fee",
        );
    }
    if intent
        .transaction
        .leverage
        .is_some_and(|leverage| leverage <= Amount::ZERO)
    {
        push(
            violations,
            SemanticErrorCode::LeverageNotPositive,
            "transaction.leverage",
        );
    }
    if intent
        .transaction
        .slippage_bps
        .is_some_and(|slippage| !(0..=10_000).contains(&slippage))
    {
        push(
            violations,
            SemanticErrorCode::SlippageBpsOutOfRange,
            "transaction.slippage_bps",
        );
    }
}

fn validate_time_fields(intent: &TransactionIntent, violations: &mut Vec<SemanticViolation>) {
    let created_at = intent.created_at.as_datetime();
    let expires_at = intent.expires_at.as_datetime();

    if created_at.timestamp_subsec_nanos() % NANOS_PER_MILLISECOND != 0 {
        push(
            violations,
            SemanticErrorCode::TimestampPrecisionUnsupported,
            "created_at",
        );
    }
    if expires_at.timestamp_subsec_nanos() % NANOS_PER_MILLISECOND != 0 {
        push(
            violations,
            SemanticErrorCode::TimestampPrecisionUnsupported,
            "expires_at",
        );
    }

    if created_at >= expires_at {
        push(
            violations,
            SemanticErrorCode::TimeOrderInvalid,
            "expires_at",
        );
        return;
    }

    let lifetime = expires_at.signed_duration_since(created_at);
    if lifetime
        .num_nanoseconds()
        .is_none_or(|nanoseconds| nanoseconds > MAX_INTENT_TTL_NANOS)
    {
        push(violations, SemanticErrorCode::TtlExceedsLimit, "expires_at");
    }
}

fn validate_identity_and_text_fields(
    intent: &TransactionIntent,
    violations: &mut Vec<SemanticViolation>,
) {
    if Ulid::from_str(&intent.intent_id).is_err() {
        push(violations, SemanticErrorCode::IntentIdInvalid, "intent_id");
    }

    let fields = [
        ("idempotency_key", Some(intent.idempotency_key.as_str())),
        (
            "principal.organization_id",
            Some(intent.principal.organization_id.as_str()),
        ),
        ("principal.user_id", intent.principal.user_id.as_deref()),
        (
            "principal.agent_id",
            Some(intent.principal.agent_id.as_str()),
        ),
        (
            "principal.agent_version",
            intent.principal.agent_version.as_deref(),
        ),
        (
            "principal.strategy_id",
            intent.principal.strategy_id.as_deref(),
        ),
        (
            "mandate.mandate_id",
            Some(intent.mandate.mandate_id.as_str()),
        ),
        ("mandate.task_id", intent.mandate.task_id.as_deref()),
        ("mandate.budget_id", intent.mandate.budget_id.as_deref()),
        ("action.category", Some(intent.action.category.as_str())),
        ("action.operation", Some(intent.action.operation.as_str())),
        ("resource.protocol", Some(intent.resource.protocol.as_str())),
        ("resource.venue", intent.resource.venue.as_deref()),
        (
            "resource.resource_id",
            Some(intent.resource.resource_id.as_str()),
        ),
        (
            "resource.resource_type",
            intent.resource.resource_type.as_deref(),
        ),
        (
            "transaction.network",
            Some(intent.transaction.network.as_str()),
        ),
        ("transaction.asset", Some(intent.transaction.asset.as_str())),
        (
            "transaction.destination",
            intent.transaction.destination.as_deref(),
        ),
        (
            "transaction.contract",
            intent.transaction.contract.as_deref(),
        ),
        (
            "transaction.calldata_hash",
            intent.transaction.calldata_hash.as_deref(),
        ),
    ];

    for (field, value) in fields {
        if let Some(value) = value {
            validate_identifier(field, value, violations);
        }
    }
    validate_purpose(&intent.mandate.purpose, violations);
}

fn validate_identifier(field: &'static str, value: &str, violations: &mut Vec<SemanticViolation>) {
    if value.len() > MAX_IDENTIFIER_BYTES {
        push(violations, SemanticErrorCode::FieldTooLong, field);
    } else if value.trim().is_empty() {
        push(violations, SemanticErrorCode::FieldBlank, field);
    } else if !value.chars().all(is_identifier_character) {
        push(violations, SemanticErrorCode::FieldInvalidCharacters, field);
    }
}

fn validate_purpose(value: &str, violations: &mut Vec<SemanticViolation>) {
    if value.len() > MAX_PURPOSE_BYTES {
        push(
            violations,
            SemanticErrorCode::FieldTooLong,
            "mandate.purpose",
        );
    } else if value.trim().is_empty() {
        push(violations, SemanticErrorCode::FieldBlank, "mandate.purpose");
    } else if value.chars().any(char::is_control) {
        push(
            violations,
            SemanticErrorCode::FieldInvalidCharacters,
            "mandate.purpose",
        );
    }
}

fn is_identifier_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || "-._~:/?#[]@!$&'()*+,;=%".contains(character)
}

fn push(violations: &mut Vec<SemanticViolation>, code: SemanticErrorCode, field: &'static str) {
    violations.push(SemanticViolation::new(code, field));
}
