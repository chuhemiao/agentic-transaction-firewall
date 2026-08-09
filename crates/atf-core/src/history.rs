use chrono::Duration;
use serde::{Deserialize, Serialize};

use crate::{Amount, RepositorySnapshot, Timestamp};

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_HISTORY_WINDOW_SECONDS: u64 = 31 * 24 * 60 * 60;
pub const MAX_DAILY_SPEND_ASSET_GROUPS: usize = 256;
pub const MAX_REQUEST_FREQUENCY_REQUESTS: u64 = 1_000_000;

#[derive(Debug, thiserror::Error)]
pub enum HistorySnapshotError {
    #[error("Risk history snapshot is invalid: {0}")]
    Invalid(String),
}

/// Lifecycle fact counted by a history-dependent Risk rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AccountingBoundary {
    Requested,
    Permitted,
    Executed,
    Settled,
}

/// Exact inputs of the duplicate-purchase repository query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DuplicatePurchaseQuery {
    organization_id: String,
    agent_id: String,
    resource_id: String,
    current_intent_id: String,
    evaluation_time: Timestamp,
    window_start: Timestamp,
    window_seconds: u64,
    accounting_boundary: AccountingBoundary,
}

/// At most one prior lifecycle boundary returned by the bounded query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DuplicatePurchaseMatch {
    intent_id: String,
    decision_id: String,
    boundary_event_id: String,
    boundary_sequence: u64,
    occurred_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DuplicatePurchaseHistory {
    query: DuplicatePurchaseQuery,
    result: Option<DuplicatePurchaseMatch>,
}

/// Exact inputs of the organization/Agent daily cumulative-spend query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DailySpendQuery {
    organization_id: String,
    agent_id: String,
    current_intent_id: String,
    valuation_asset: String,
    evaluation_time: Timestamp,
    window_start: Timestamp,
    window_seconds: u64,
    accounting_boundary: AccountingBoundary,
}

/// One fixed-point aggregate returned by the bounded repository query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DailySpendAssetTotal {
    asset: String,
    amount: Amount,
    decision_count: u64,
}

/// Exact grouped result consumed by the daily cumulative-spend rule. Rows
/// without a trustworthy bound asset are counted separately so they can
/// produce a restrictive finding instead of disappearing from the sum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DailySpendHistory {
    query: DailySpendQuery,
    totals: Vec<DailySpendAssetTotal>,
    unresolved_asset_decision_count: u64,
}

/// Profile-owned destination normalization outcome. Unavailable values remain
/// explicit evidence so unsupported namespaces cannot silently look new or
/// familiar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum DestinationNormalization {
    Available { value: String },
    Unavailable { reason_code: String },
}

/// Exact organization-scoped inputs of the first-destination query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstDestinationQuery {
    organization_id: String,
    current_intent_id: String,
    profile_id: String,
    profile_version: String,
    normalizer_id: String,
    normalizer_version: String,
    destination: DestinationNormalization,
    evaluation_time: Timestamp,
    accounting_boundary: AccountingBoundary,
}

/// At most one prior permitted use of the normalized destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstDestinationMatch {
    intent_id: String,
    decision_id: String,
    boundary_event_id: String,
    boundary_sequence: u64,
    occurred_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirstDestinationHistory {
    query: FirstDestinationQuery,
    result: Option<FirstDestinationMatch>,
}

/// Closed principal dimension supported by the REQUESTED-boundary velocity
/// rule. Future subject dimensions require a new versioned contract instead of
/// broadening this query implicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestFrequencySubject {
    Agent,
}

/// Closed action dimension supported by the REQUESTED-boundary velocity rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RequestFrequencyActionScope {
    Profile,
}

/// Exact tenant, subject, Profile/action, time, threshold, and lifecycle inputs
/// of one accepted-request frequency query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestFrequencyQuery {
    organization_id: String,
    agent_id: String,
    current_intent_id: String,
    profile_id: String,
    profile_version: String,
    action_category: String,
    action_operation: String,
    subject: RequestFrequencySubject,
    action_scope: RequestFrequencyActionScope,
    evaluation_time: Timestamp,
    window_start: Timestamp,
    window_seconds: u64,
    max_requests: u64,
    accounting_boundary: AccountingBoundary,
}

/// Aggregate of immutable REQUESTED events at the repository boundary. Events
/// lacking a trustworthy Profile/action binding are kept explicit so Risk can
/// fail closed rather than silently undercounting them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestFrequencyHistory {
    query: RequestFrequencyQuery,
    request_count: u64,
    unresolved_scope_request_count: u64,
}

/// Repository boundary plus the exact bounded query inputs and result consumed
/// by history-dependent Risk rules. Optional query families allow later rules
/// to extend this closed snapshot without inventing an ambient database read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskHistorySnapshot {
    repository: RepositorySnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duplicate_purchase: Option<DuplicatePurchaseHistory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    daily_cumulative_spend: Option<DailySpendHistory>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    first_destination: Option<Box<FirstDestinationHistory>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_frequency: Option<Box<RequestFrequencyHistory>>,
}

impl DuplicatePurchaseQuery {
    pub fn new(
        organization_id: impl Into<String>,
        agent_id: impl Into<String>,
        resource_id: impl Into<String>,
        current_intent_id: impl Into<String>,
        evaluation_time: Timestamp,
        window_seconds: u64,
        accounting_boundary: AccountingBoundary,
    ) -> Result<Self, HistorySnapshotError> {
        if !(1..=MAX_HISTORY_WINDOW_SECONDS).contains(&window_seconds) {
            return invalid(format!(
                "duplicate-purchase window_seconds must be within 1..={MAX_HISTORY_WINDOW_SECONDS}"
            ));
        }
        let seconds = i64::try_from(window_seconds)
            .map_err(|_| HistorySnapshotError::Invalid("history window overflows i64".into()))?;
        let query = Self {
            organization_id: organization_id.into(),
            agent_id: agent_id.into(),
            resource_id: resource_id.into(),
            current_intent_id: current_intent_id.into(),
            evaluation_time,
            window_start: Timestamp::from_datetime(
                evaluation_time.as_datetime() - Duration::seconds(seconds),
            ),
            window_seconds,
            accounting_boundary,
        };
        query.validate()?;
        Ok(query)
    }

    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn resource_id(&self) -> &str {
        &self.resource_id
    }

    pub fn current_intent_id(&self) -> &str {
        &self.current_intent_id
    }

    pub fn evaluation_time(&self) -> Timestamp {
        self.evaluation_time
    }

    pub fn window_start(&self) -> Timestamp {
        self.window_start
    }

    pub fn window_seconds(&self) -> u64 {
        self.window_seconds
    }

    pub fn accounting_boundary(&self) -> AccountingBoundary {
        self.accounting_boundary
    }

    fn validate(&self) -> Result<(), HistorySnapshotError> {
        for (field, value) in [
            ("organization_id", self.organization_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
            ("resource_id", self.resource_id.as_str()),
            ("current_intent_id", self.current_intent_id.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        if !(1..=MAX_HISTORY_WINDOW_SECONDS).contains(&self.window_seconds) {
            return invalid("duplicate-purchase window_seconds is outside the supported range");
        }
        let seconds = i64::try_from(self.window_seconds)
            .map_err(|_| HistorySnapshotError::Invalid("history window overflows i64".into()))?;
        let expected = Timestamp::from_datetime(
            self.evaluation_time.as_datetime() - Duration::seconds(seconds),
        );
        if self.window_start != expected {
            return invalid("duplicate-purchase window_start disagrees with evaluation_time");
        }
        Ok(())
    }
}

impl DuplicatePurchaseMatch {
    pub fn new(
        intent_id: impl Into<String>,
        decision_id: impl Into<String>,
        boundary_event_id: impl Into<String>,
        boundary_sequence: u64,
        occurred_at: Timestamp,
    ) -> Result<Self, HistorySnapshotError> {
        let result = Self {
            intent_id: intent_id.into(),
            decision_id: decision_id.into(),
            boundary_event_id: boundary_event_id.into(),
            boundary_sequence,
            occurred_at,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn intent_id(&self) -> &str {
        &self.intent_id
    }

    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    pub fn boundary_event_id(&self) -> &str {
        &self.boundary_event_id
    }

    pub fn boundary_sequence(&self) -> u64 {
        self.boundary_sequence
    }

    pub fn occurred_at(&self) -> Timestamp {
        self.occurred_at
    }

    fn validate(&self) -> Result<(), HistorySnapshotError> {
        for (field, value) in [
            ("intent_id", self.intent_id.as_str()),
            ("decision_id", self.decision_id.as_str()),
            ("boundary_event_id", self.boundary_event_id.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        if self.boundary_sequence == 0 {
            return invalid("duplicate-purchase boundary_sequence must be positive");
        }
        Ok(())
    }
}

impl DuplicatePurchaseHistory {
    pub fn new(
        query: DuplicatePurchaseQuery,
        result: Option<DuplicatePurchaseMatch>,
    ) -> Result<Self, HistorySnapshotError> {
        query.validate()?;
        if let Some(result) = &result {
            result.validate()?;
        }
        Ok(Self { query, result })
    }

    pub fn query(&self) -> &DuplicatePurchaseQuery {
        &self.query
    }

    pub fn result(&self) -> Option<&DuplicatePurchaseMatch> {
        self.result.as_ref()
    }
}

impl DailySpendQuery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: impl Into<String>,
        agent_id: impl Into<String>,
        current_intent_id: impl Into<String>,
        valuation_asset: impl Into<String>,
        evaluation_time: Timestamp,
        window_seconds: u64,
        accounting_boundary: AccountingBoundary,
    ) -> Result<Self, HistorySnapshotError> {
        if !(1..=MAX_HISTORY_WINDOW_SECONDS).contains(&window_seconds) {
            return invalid(format!(
                "daily-spend window_seconds must be within 1..={MAX_HISTORY_WINDOW_SECONDS}"
            ));
        }
        let seconds = i64::try_from(window_seconds)
            .map_err(|_| HistorySnapshotError::Invalid("history window overflows i64".into()))?;
        let query = Self {
            organization_id: organization_id.into(),
            agent_id: agent_id.into(),
            current_intent_id: current_intent_id.into(),
            valuation_asset: valuation_asset.into(),
            evaluation_time,
            window_start: Timestamp::from_datetime(
                evaluation_time.as_datetime() - Duration::seconds(seconds),
            ),
            window_seconds,
            accounting_boundary,
        };
        query.validate()?;
        Ok(query)
    }

    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn current_intent_id(&self) -> &str {
        &self.current_intent_id
    }

    pub fn valuation_asset(&self) -> &str {
        &self.valuation_asset
    }

    pub fn evaluation_time(&self) -> Timestamp {
        self.evaluation_time
    }

    pub fn window_start(&self) -> Timestamp {
        self.window_start
    }

    pub fn window_seconds(&self) -> u64 {
        self.window_seconds
    }

    pub fn accounting_boundary(&self) -> AccountingBoundary {
        self.accounting_boundary
    }

    fn validate(&self) -> Result<(), HistorySnapshotError> {
        for (field, value) in [
            ("organization_id", self.organization_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
            ("current_intent_id", self.current_intent_id.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        validate_asset("valuation_asset", &self.valuation_asset)?;
        if !(1..=MAX_HISTORY_WINDOW_SECONDS).contains(&self.window_seconds) {
            return invalid("daily-spend window_seconds is outside the supported range");
        }
        let seconds = i64::try_from(self.window_seconds)
            .map_err(|_| HistorySnapshotError::Invalid("history window overflows i64".into()))?;
        let expected = Timestamp::from_datetime(
            self.evaluation_time.as_datetime() - Duration::seconds(seconds),
        );
        if self.window_start != expected {
            return invalid("daily-spend window_start disagrees with evaluation_time");
        }
        Ok(())
    }
}

impl DailySpendAssetTotal {
    pub fn new(
        asset: impl Into<String>,
        amount: Amount,
        decision_count: u64,
    ) -> Result<Self, HistorySnapshotError> {
        let total = Self {
            asset: asset.into(),
            amount,
            decision_count,
        };
        total.validate()?;
        Ok(total)
    }

    pub fn asset(&self) -> &str {
        &self.asset
    }

    pub fn amount(&self) -> Amount {
        self.amount
    }

    pub fn decision_count(&self) -> u64 {
        self.decision_count
    }

    fn validate(&self) -> Result<(), HistorySnapshotError> {
        validate_asset("daily-spend asset", &self.asset)?;
        if self.amount <= Amount::ZERO {
            return invalid("daily-spend aggregate amount must be positive");
        }
        if self.decision_count == 0 {
            return invalid("daily-spend aggregate decision_count must be positive");
        }
        Ok(())
    }
}

impl DailySpendHistory {
    pub fn new(
        query: DailySpendQuery,
        totals: Vec<DailySpendAssetTotal>,
        unresolved_asset_decision_count: u64,
    ) -> Result<Self, HistorySnapshotError> {
        let history = Self {
            query,
            totals,
            unresolved_asset_decision_count,
        };
        history.validate()?;
        Ok(history)
    }

    pub fn query(&self) -> &DailySpendQuery {
        &self.query
    }

    pub fn totals(&self) -> &[DailySpendAssetTotal] {
        &self.totals
    }

    pub fn unresolved_asset_decision_count(&self) -> u64 {
        self.unresolved_asset_decision_count
    }

    fn validate(&self) -> Result<(), HistorySnapshotError> {
        self.query.validate()?;
        if self.totals.len() > MAX_DAILY_SPEND_ASSET_GROUPS {
            return invalid(format!(
                "daily-spend totals exceed {MAX_DAILY_SPEND_ASSET_GROUPS} asset groups"
            ));
        }
        for total in &self.totals {
            total.validate()?;
        }
        if self
            .totals
            .windows(2)
            .any(|pair| pair[0].asset >= pair[1].asset)
        {
            return invalid("daily-spend totals must be strictly sorted and unique by asset");
        }
        Ok(())
    }
}

impl DestinationNormalization {
    pub fn available(value: impl Into<String>) -> Result<Self, HistorySnapshotError> {
        let normalization = Self::Available {
            value: value.into(),
        };
        normalization.validate()?;
        Ok(normalization)
    }

    pub fn unavailable(reason_code: impl Into<String>) -> Result<Self, HistorySnapshotError> {
        let normalization = Self::Unavailable {
            reason_code: reason_code.into(),
        };
        normalization.validate()?;
        Ok(normalization)
    }

    pub fn value(&self) -> Option<&str> {
        match self {
            Self::Available { value } => Some(value),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn reason_code(&self) -> Option<&str> {
        match self {
            Self::Available { .. } => None,
            Self::Unavailable { reason_code } => Some(reason_code),
        }
    }

    fn validate(&self) -> Result<(), HistorySnapshotError> {
        match self {
            Self::Available { value } => validate_destination("normalized destination", value),
            Self::Unavailable { reason_code } => {
                validate_identifier("destination normalization reason_code", reason_code)
            }
        }
    }
}

impl FirstDestinationQuery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: impl Into<String>,
        current_intent_id: impl Into<String>,
        profile_id: impl Into<String>,
        profile_version: impl Into<String>,
        normalizer_id: impl Into<String>,
        normalizer_version: impl Into<String>,
        destination: DestinationNormalization,
        evaluation_time: Timestamp,
        accounting_boundary: AccountingBoundary,
    ) -> Result<Self, HistorySnapshotError> {
        let query = Self {
            organization_id: organization_id.into(),
            current_intent_id: current_intent_id.into(),
            profile_id: profile_id.into(),
            profile_version: profile_version.into(),
            normalizer_id: normalizer_id.into(),
            normalizer_version: normalizer_version.into(),
            destination,
            evaluation_time,
            accounting_boundary,
        };
        query.validate()?;
        Ok(query)
    }

    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    pub fn current_intent_id(&self) -> &str {
        &self.current_intent_id
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn profile_version(&self) -> &str {
        &self.profile_version
    }

    pub fn normalizer_id(&self) -> &str {
        &self.normalizer_id
    }

    pub fn normalizer_version(&self) -> &str {
        &self.normalizer_version
    }

    pub fn destination(&self) -> &DestinationNormalization {
        &self.destination
    }

    pub fn evaluation_time(&self) -> Timestamp {
        self.evaluation_time
    }

    pub fn accounting_boundary(&self) -> AccountingBoundary {
        self.accounting_boundary
    }

    fn validate(&self) -> Result<(), HistorySnapshotError> {
        for (field, value) in [
            ("organization_id", self.organization_id.as_str()),
            ("current_intent_id", self.current_intent_id.as_str()),
            ("profile_id", self.profile_id.as_str()),
            ("profile_version", self.profile_version.as_str()),
            ("normalizer_id", self.normalizer_id.as_str()),
            ("normalizer_version", self.normalizer_version.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        self.destination.validate()
    }
}

impl FirstDestinationMatch {
    pub fn new(
        intent_id: impl Into<String>,
        decision_id: impl Into<String>,
        boundary_event_id: impl Into<String>,
        boundary_sequence: u64,
        occurred_at: Timestamp,
    ) -> Result<Self, HistorySnapshotError> {
        let result = Self {
            intent_id: intent_id.into(),
            decision_id: decision_id.into(),
            boundary_event_id: boundary_event_id.into(),
            boundary_sequence,
            occurred_at,
        };
        result.validate()?;
        Ok(result)
    }

    pub fn intent_id(&self) -> &str {
        &self.intent_id
    }

    pub fn decision_id(&self) -> &str {
        &self.decision_id
    }

    pub fn boundary_event_id(&self) -> &str {
        &self.boundary_event_id
    }

    pub fn boundary_sequence(&self) -> u64 {
        self.boundary_sequence
    }

    pub fn occurred_at(&self) -> Timestamp {
        self.occurred_at
    }

    fn validate(&self) -> Result<(), HistorySnapshotError> {
        for (field, value) in [
            ("intent_id", self.intent_id.as_str()),
            ("decision_id", self.decision_id.as_str()),
            ("boundary_event_id", self.boundary_event_id.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        if self.boundary_sequence == 0 {
            return invalid("first-destination boundary_sequence must be positive");
        }
        Ok(())
    }
}

impl FirstDestinationHistory {
    pub fn new(
        query: FirstDestinationQuery,
        result: Option<FirstDestinationMatch>,
    ) -> Result<Self, HistorySnapshotError> {
        query.validate()?;
        if let Some(result) = &result {
            result.validate()?;
            if query.destination.value().is_none() {
                return invalid(
                    "unavailable destination normalization cannot establish familiarity",
                );
            }
        }
        Ok(Self { query, result })
    }

    pub fn query(&self) -> &FirstDestinationQuery {
        &self.query
    }

    pub fn result(&self) -> Option<&FirstDestinationMatch> {
        self.result.as_ref()
    }
}

impl RequestFrequencyQuery {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        organization_id: impl Into<String>,
        agent_id: impl Into<String>,
        current_intent_id: impl Into<String>,
        profile_id: impl Into<String>,
        profile_version: impl Into<String>,
        action_category: impl Into<String>,
        action_operation: impl Into<String>,
        subject: RequestFrequencySubject,
        action_scope: RequestFrequencyActionScope,
        evaluation_time: Timestamp,
        window_seconds: u64,
        max_requests: u64,
        accounting_boundary: AccountingBoundary,
    ) -> Result<Self, HistorySnapshotError> {
        if !(1..=MAX_HISTORY_WINDOW_SECONDS).contains(&window_seconds) {
            return invalid(format!(
                "request-frequency window_seconds must be within 1..={MAX_HISTORY_WINDOW_SECONDS}"
            ));
        }
        let seconds = i64::try_from(window_seconds)
            .map_err(|_| HistorySnapshotError::Invalid("history window overflows i64".into()))?;
        let query = Self {
            organization_id: organization_id.into(),
            agent_id: agent_id.into(),
            current_intent_id: current_intent_id.into(),
            profile_id: profile_id.into(),
            profile_version: profile_version.into(),
            action_category: action_category.into(),
            action_operation: action_operation.into(),
            subject,
            action_scope,
            evaluation_time,
            window_start: Timestamp::from_datetime(
                evaluation_time.as_datetime() - Duration::seconds(seconds),
            ),
            window_seconds,
            max_requests,
            accounting_boundary,
        };
        query.validate()?;
        Ok(query)
    }

    pub fn organization_id(&self) -> &str {
        &self.organization_id
    }

    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }

    pub fn current_intent_id(&self) -> &str {
        &self.current_intent_id
    }

    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }

    pub fn profile_version(&self) -> &str {
        &self.profile_version
    }

    pub fn action_category(&self) -> &str {
        &self.action_category
    }

    pub fn action_operation(&self) -> &str {
        &self.action_operation
    }

    pub fn subject(&self) -> RequestFrequencySubject {
        self.subject
    }

    pub fn action_scope(&self) -> RequestFrequencyActionScope {
        self.action_scope
    }

    pub fn evaluation_time(&self) -> Timestamp {
        self.evaluation_time
    }

    pub fn window_start(&self) -> Timestamp {
        self.window_start
    }

    pub fn window_seconds(&self) -> u64 {
        self.window_seconds
    }

    pub fn max_requests(&self) -> u64 {
        self.max_requests
    }

    pub fn accounting_boundary(&self) -> AccountingBoundary {
        self.accounting_boundary
    }

    fn validate(&self) -> Result<(), HistorySnapshotError> {
        for (field, value) in [
            ("organization_id", self.organization_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
            ("current_intent_id", self.current_intent_id.as_str()),
            ("profile_id", self.profile_id.as_str()),
            ("profile_version", self.profile_version.as_str()),
            ("action_category", self.action_category.as_str()),
            ("action_operation", self.action_operation.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        if !(1..=MAX_HISTORY_WINDOW_SECONDS).contains(&self.window_seconds) {
            return invalid("request-frequency window_seconds is outside the supported range");
        }
        if !(1..=MAX_REQUEST_FREQUENCY_REQUESTS).contains(&self.max_requests) {
            return invalid("request-frequency max_requests is outside the supported range");
        }
        if self.accounting_boundary != AccountingBoundary::Requested {
            return invalid("request-frequency requires REQUESTED accounting");
        }
        let seconds = i64::try_from(self.window_seconds)
            .map_err(|_| HistorySnapshotError::Invalid("history window overflows i64".into()))?;
        let expected = Timestamp::from_datetime(
            self.evaluation_time.as_datetime() - Duration::seconds(seconds),
        );
        if self.window_start != expected {
            return invalid("request-frequency window_start disagrees with evaluation_time");
        }
        Ok(())
    }
}

impl RequestFrequencyHistory {
    pub fn new(
        query: RequestFrequencyQuery,
        request_count: u64,
        unresolved_scope_request_count: u64,
    ) -> Result<Self, HistorySnapshotError> {
        let history = Self {
            query,
            request_count,
            unresolved_scope_request_count,
        };
        history.validate()?;
        Ok(history)
    }

    pub fn query(&self) -> &RequestFrequencyQuery {
        &self.query
    }

    pub fn request_count(&self) -> u64 {
        self.request_count
    }

    pub fn unresolved_scope_request_count(&self) -> u64 {
        self.unresolved_scope_request_count
    }

    fn validate(&self) -> Result<(), HistorySnapshotError> {
        self.query.validate()?;
        Ok(())
    }
}

impl RiskHistorySnapshot {
    pub fn new(
        repository: RepositorySnapshot,
        duplicate_purchase: Option<DuplicatePurchaseHistory>,
    ) -> Result<Self, HistorySnapshotError> {
        Self::with_request_frequency(repository, duplicate_purchase, None, None, None)
    }

    pub fn with_daily_spend(
        repository: RepositorySnapshot,
        duplicate_purchase: Option<DuplicatePurchaseHistory>,
        daily_cumulative_spend: Option<DailySpendHistory>,
    ) -> Result<Self, HistorySnapshotError> {
        Self::with_request_frequency(
            repository,
            duplicate_purchase,
            daily_cumulative_spend,
            None,
            None,
        )
    }

    pub fn with_first_destination(
        repository: RepositorySnapshot,
        duplicate_purchase: Option<DuplicatePurchaseHistory>,
        daily_cumulative_spend: Option<DailySpendHistory>,
        first_destination: Option<FirstDestinationHistory>,
    ) -> Result<Self, HistorySnapshotError> {
        Self::with_request_frequency(
            repository,
            duplicate_purchase,
            daily_cumulative_spend,
            first_destination,
            None,
        )
    }

    pub fn with_request_frequency(
        repository: RepositorySnapshot,
        duplicate_purchase: Option<DuplicatePurchaseHistory>,
        daily_cumulative_spend: Option<DailySpendHistory>,
        first_destination: Option<FirstDestinationHistory>,
        request_frequency: Option<RequestFrequencyHistory>,
    ) -> Result<Self, HistorySnapshotError> {
        let snapshot = Self {
            repository,
            duplicate_purchase,
            daily_cumulative_spend,
            first_destination: first_destination.map(Box::new),
            request_frequency: request_frequency.map(Box::new),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn repository(&self) -> &RepositorySnapshot {
        &self.repository
    }

    pub fn duplicate_purchase(&self) -> Option<&DuplicatePurchaseHistory> {
        self.duplicate_purchase.as_ref()
    }

    pub fn daily_cumulative_spend(&self) -> Option<&DailySpendHistory> {
        self.daily_cumulative_spend.as_ref()
    }

    pub fn first_destination(&self) -> Option<&FirstDestinationHistory> {
        self.first_destination.as_deref()
    }

    pub fn request_frequency(&self) -> Option<&RequestFrequencyHistory> {
        self.request_frequency.as_deref()
    }

    pub fn validate(&self) -> Result<(), HistorySnapshotError> {
        RepositorySnapshot::new(
            self.repository.snapshot_id(),
            self.repository.through_sequence(),
            self.repository.snapshot_hash(),
        )
        .map_err(|error| HistorySnapshotError::Invalid(error.to_string()))?;
        if let Some(history) = &self.duplicate_purchase {
            history.query.validate()?;
            if let Some(result) = &history.result {
                result.validate()?;
                if result.boundary_sequence > self.repository.through_sequence() {
                    return invalid("duplicate-purchase result exceeds the repository boundary");
                }
                if result.intent_id == history.query.current_intent_id {
                    return invalid("duplicate-purchase result cannot name the current Intent");
                }
                if result.occurred_at < history.query.window_start
                    || result.occurred_at > history.query.evaluation_time
                {
                    return invalid("duplicate-purchase result is outside the query time window");
                }
            }
        }
        if let Some(history) = &self.daily_cumulative_spend {
            history.validate()?;
        }
        if let Some(history) = &self.first_destination {
            history.query.validate()?;
            if let Some(result) = &history.result {
                result.validate()?;
                if history.query.destination.value().is_none() {
                    return invalid(
                        "unavailable destination normalization cannot establish familiarity",
                    );
                }
                if result.boundary_sequence > self.repository.through_sequence() {
                    return invalid("first-destination result exceeds the repository boundary");
                }
                if result.intent_id == history.query.current_intent_id {
                    return invalid("first-destination result cannot name the current Intent");
                }
                if result.occurred_at > history.query.evaluation_time {
                    return invalid("first-destination result is after the query evaluation time");
                }
            }
        }
        if let Some(history) = &self.request_frequency {
            history.validate()?;
        }
        Ok(())
    }
}

fn validate_asset(field: &str, value: &str) -> Result<(), HistorySnapshotError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'/' | b'%')
        })
    {
        return invalid(format!(
            "{field} must be a canonical bounded asset identifier"
        ));
    }
    Ok(())
}

fn validate_destination(field: &str, value: &str) -> Result<(), HistorySnapshotError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || !value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-' | b'%')
        })
    {
        return invalid(format!(
            "{field} must be a canonical bounded destination identifier"
        ));
    }
    Ok(())
}

fn validate_identifier(field: &str, value: &str) -> Result<(), HistorySnapshotError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return invalid(format!(
            "{field} must be a canonical 1..256 byte identifier"
        ));
    }
    Ok(())
}

fn invalid<T>(reason: impl Into<String>) -> Result<T, HistorySnapshotError> {
    Err(HistorySnapshotError::Invalid(reason.into()))
}
