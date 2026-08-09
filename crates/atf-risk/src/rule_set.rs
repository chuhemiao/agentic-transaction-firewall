use std::fs;
use std::path::Path;

use atf_core::{sha256_hex, sort_json_keys, AccountingBoundary, Amount, RiskHistorySnapshot};
use serde::{Deserialize, Serialize};

use crate::{RiskFinding, Severity};

const HASH_DOMAIN: &[u8] = b"ATF_RISK_RULE_SET_V1\0";
const FORMAT_VERSION: &str = "1";
const ENGINE_VERSION: &str = "atf-risk-engine-v1";
const MAX_RULE_SET_BYTES: u64 = 64 * 1024;
const MAX_BASIS_POINTS: u32 = 1_000_000;
const MAX_HISTORY_WINDOW_SECONDS: u64 = 31 * 24 * 60 * 60;
const DEFAULT_RULE_SET: &str = include_str!("../../../risk-rules/default.json");

#[derive(Debug, thiserror::Error)]
pub enum RiskRuleSetError {
    #[error("Risk Rule Set I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("Risk Rule Set JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Risk Rule Set is invalid: {0}")]
    Invalid(String),
}

/// Explicit behavior when an enabled rule's optional input is absent or
/// unusable. `NotApplicable` preserves the current MVP semantics; `Finding`
/// emits the rule's configured severity instead of silently skipping it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MissingDataBehavior {
    NotApplicable,
    Finding,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RiskRuleSetDocument {
    rule_set_format_version: String,
    rule_set_version: String,
    engine_version: String,
    rules: RuleSetRules,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleSetRules {
    pub(crate) request_expired: ToggleRule,
    pub(crate) single_amount_cap: AmountCapRule,
    pub(crate) max_fee_ratio: BasisPointRule,
    pub(crate) vendor_price_deviation: BasisPointRule,
    pub(crate) high_risk_network_or_protocol: DenyListRule,
    pub(crate) duplicate_purchase: HistoryWindowRule,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) daily_cumulative_spend: Option<DailySpendRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ToggleRule {
    pub(crate) enabled: bool,
    pub(crate) severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AmountCapRule {
    pub(crate) enabled: bool,
    pub(crate) severity: Severity,
    pub(crate) max_amount: Option<Amount>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BasisPointRule {
    pub(crate) enabled: bool,
    pub(crate) severity: Severity,
    pub(crate) threshold_bps: u32,
    pub(crate) missing_data: MissingDataBehavior,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DenyListRule {
    pub(crate) enabled: bool,
    pub(crate) severity: Severity,
    pub(crate) networks: Vec<String>,
    pub(crate) protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HistoryWindowRule {
    pub(crate) enabled: bool,
    pub(crate) severity: Severity,
    pub(crate) window_seconds: u64,
    pub(crate) accounting_boundary: AccountingBoundary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DailySpendRule {
    pub(crate) enabled: bool,
    pub(crate) severity: Severity,
    pub(crate) max_amount: Amount,
    pub(crate) valuation_asset: String,
    pub(crate) window_seconds: u64,
    pub(crate) accounting_boundary: AccountingBoundary,
    pub(crate) missing_data: MissingDataBehavior,
}

/// Validated canonical identity and executable configuration of one Risk Rule
/// Set. The hash binds the closed document and the Risk engine compatibility
/// version, so replay never identifies behavior by a mutable process default.
#[derive(Debug, Clone)]
pub struct RiskRuleSet {
    document: RiskRuleSetDocument,
    canonical_bytes: Vec<u8>,
    rule_set_hash: String,
}

/// One Risk execution result bound to the exact Rule Set that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskEvaluation {
    pub rule_set_version: String,
    pub rule_set_hash: String,
    pub findings: Vec<RiskFinding>,
    pub history: RiskHistorySnapshot,
}

impl RiskEvaluation {
    pub fn iter(&self) -> std::slice::Iter<'_, RiskFinding> {
        self.findings.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.findings.is_empty()
    }
}

impl RiskRuleSet {
    pub fn from_file(path: &Path) -> Result<Self, RiskRuleSetError> {
        let metadata = fs::symlink_metadata(path)?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(RiskRuleSetError::Invalid(
                "path must be a regular non-symlink file".into(),
            ));
        }
        if metadata.len() > MAX_RULE_SET_BYTES {
            return Err(RiskRuleSetError::Invalid(format!(
                "file exceeds {MAX_RULE_SET_BYTES} bytes"
            )));
        }
        let bytes = fs::read(path)?;
        let raw = std::str::from_utf8(&bytes)
            .map_err(|error| RiskRuleSetError::Invalid(format!("file is not UTF-8: {error}")))?;
        Self::from_json(raw)
    }

    pub fn from_json(raw: &str) -> Result<Self, RiskRuleSetError> {
        if u64::try_from(raw.len()).unwrap_or(u64::MAX) > MAX_RULE_SET_BYTES {
            return Err(RiskRuleSetError::Invalid(format!(
                "document exceeds {MAX_RULE_SET_BYTES} bytes"
            )));
        }
        let document: RiskRuleSetDocument = serde_json::from_str(raw)?;
        validate_document(&document)?;
        let canonical_value = sort_json_keys(serde_json::to_value(&document)?);
        let canonical_bytes = serde_json::to_vec(&canonical_value)?;
        let mut hash_input = Vec::with_capacity(HASH_DOMAIN.len() + canonical_bytes.len());
        hash_input.extend_from_slice(HASH_DOMAIN);
        hash_input.extend_from_slice(&canonical_bytes);
        let rule_set_hash = sha256_hex(&hash_input);
        Ok(Self {
            document,
            canonical_bytes,
            rule_set_hash,
        })
    }

    pub fn version(&self) -> &str {
        &self.document.rule_set_version
    }

    pub fn engine_version(&self) -> &str {
        &self.document.engine_version
    }

    pub fn rule_set_hash(&self) -> &str {
        &self.rule_set_hash
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    pub fn duplicate_purchase_accounting_boundary(&self) -> AccountingBoundary {
        self.document.rules.duplicate_purchase.accounting_boundary
    }

    pub fn duplicate_purchase_enabled(&self) -> bool {
        self.document.rules.duplicate_purchase.enabled
    }

    pub fn duplicate_purchase_window_seconds(&self) -> u64 {
        self.document.rules.duplicate_purchase.window_seconds
    }

    pub fn daily_spend_enabled(&self) -> bool {
        self.document
            .rules
            .daily_cumulative_spend
            .as_ref()
            .is_some_and(|rule| rule.enabled)
    }

    pub fn daily_spend_accounting_boundary(&self) -> Option<AccountingBoundary> {
        self.document
            .rules
            .daily_cumulative_spend
            .as_ref()
            .map(|rule| rule.accounting_boundary)
    }

    pub fn daily_spend_window_seconds(&self) -> Option<u64> {
        self.document
            .rules
            .daily_cumulative_spend
            .as_ref()
            .map(|rule| rule.window_seconds)
    }

    pub fn daily_spend_valuation_asset(&self) -> Option<&str> {
        self.document
            .rules
            .daily_cumulative_spend
            .as_ref()
            .map(|rule| rule.valuation_asset.as_str())
    }

    pub(crate) fn rules(&self) -> &RuleSetRules {
        &self.document.rules
    }

    pub(crate) fn evaluation(
        &self,
        findings: Vec<RiskFinding>,
        history: RiskHistorySnapshot,
    ) -> RiskEvaluation {
        RiskEvaluation {
            rule_set_version: self.version().into(),
            rule_set_hash: self.rule_set_hash().into(),
            findings,
            history,
        }
    }
}

impl Default for RiskRuleSet {
    fn default() -> Self {
        Self::from_json(DEFAULT_RULE_SET).expect("the embedded default Risk Rule Set is valid")
    }
}

fn validate_document(document: &RiskRuleSetDocument) -> Result<(), RiskRuleSetError> {
    if document.rule_set_format_version != FORMAT_VERSION {
        return invalid("unsupported rule_set_format_version");
    }
    if document.engine_version != ENGINE_VERSION {
        return invalid("unsupported engine_version");
    }
    validate_version(&document.rule_set_version)?;
    let rules = &document.rules;
    if rules
        .single_amount_cap
        .max_amount
        .is_some_and(|amount| amount.as_decimal() <= rust_decimal::Decimal::ZERO)
    {
        return invalid("single_amount_cap.max_amount must be positive");
    }
    if rules.single_amount_cap.enabled && rules.single_amount_cap.max_amount.is_none() {
        return invalid("enabled single_amount_cap requires a positive max_amount");
    }
    for (name, rule) in [
        ("max_fee_ratio", &rules.max_fee_ratio),
        ("vendor_price_deviation", &rules.vendor_price_deviation),
    ] {
        if rule.threshold_bps > MAX_BASIS_POINTS {
            return invalid(format!("{name}.threshold_bps exceeds {MAX_BASIS_POINTS}"));
        }
    }
    if rules.vendor_price_deviation.enabled
        && rules.vendor_price_deviation.missing_data != MissingDataBehavior::Finding
    {
        return invalid(
            "enabled vendor_price_deviation must emit a FINDING when trusted data is missing",
        );
    }
    let history = &rules.duplicate_purchase;
    if !(1..=MAX_HISTORY_WINDOW_SECONDS).contains(&history.window_seconds) {
        return invalid(format!(
            "duplicate_purchase.window_seconds must be within 1..={MAX_HISTORY_WINDOW_SECONDS}"
        ));
    }
    if let Some(rule) = &rules.daily_cumulative_spend {
        if rule.max_amount <= Amount::ZERO {
            return invalid("daily_cumulative_spend.max_amount must be positive");
        }
        validate_asset_identifier(
            "daily_cumulative_spend.valuation_asset",
            &rule.valuation_asset,
        )?;
        if !(1..=MAX_HISTORY_WINDOW_SECONDS).contains(&rule.window_seconds) {
            return invalid(format!(
                "daily_cumulative_spend.window_seconds must be within 1..={MAX_HISTORY_WINDOW_SECONDS}"
            ));
        }
        if rule.accounting_boundary != AccountingBoundary::Permitted {
            return invalid("daily_cumulative_spend requires PERMITTED accounting");
        }
        if rule.enabled
            && (!matches!(rule.severity, Severity::High | Severity::Critical)
                || rule.missing_data != MissingDataBehavior::Finding)
        {
            return invalid(
                "enabled daily_cumulative_spend must be HIGH/CRITICAL and emit FINDING for missing data",
            );
        }
    }
    validate_canonical_list(
        "high_risk_network_or_protocol.networks",
        &rules.high_risk_network_or_protocol.networks,
    )?;
    validate_canonical_list(
        "high_risk_network_or_protocol.protocols",
        &rules.high_risk_network_or_protocol.protocols,
    )?;
    Ok(())
}

fn validate_version(value: &str) -> Result<(), RiskRuleSetError> {
    if value.is_empty()
        || value.len() > 64
        || !value.bytes().enumerate().all(|(index, byte)| {
            (index != 0 || byte.is_ascii_alphanumeric())
                && (byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
    {
        return invalid("rule_set_version is not a canonical identifier");
    }
    Ok(())
}

fn validate_canonical_list(field: &str, values: &[String]) -> Result<(), RiskRuleSetError> {
    for value in values {
        if value.is_empty()
            || value.len() > 256
            || value.trim() != value
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_uppercase())
        {
            return invalid(format!("{field} contains a non-canonical value"));
        }
    }
    if values.windows(2).any(|pair| pair[0] >= pair[1]) {
        return invalid(format!("{field} must be strictly sorted and unique"));
    }
    Ok(())
}

fn validate_asset_identifier(field: &str, value: &str) -> Result<(), RiskRuleSetError> {
    if value.is_empty()
        || value.len() > 256
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/' | b'%')
        })
        || !value.contains('/')
    {
        return invalid(format!("{field} is not a canonical asset identifier"));
    }
    Ok(())
}

fn invalid(reason: impl Into<String>) -> Result<(), RiskRuleSetError> {
    Err(RiskRuleSetError::Invalid(reason.into()))
}
