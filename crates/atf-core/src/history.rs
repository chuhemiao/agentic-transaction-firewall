use chrono::Duration;
use serde::{Deserialize, Serialize};

use crate::{RepositorySnapshot, Timestamp};

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_HISTORY_WINDOW_SECONDS: u64 = 31 * 24 * 60 * 60;

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

/// Repository boundary plus the exact bounded query inputs and result consumed
/// by history-dependent Risk rules. Optional query families allow later rules
/// to extend this closed snapshot without inventing an ambient database read.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RiskHistorySnapshot {
    repository: RepositorySnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    duplicate_purchase: Option<DuplicatePurchaseHistory>,
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

impl RiskHistorySnapshot {
    pub fn new(
        repository: RepositorySnapshot,
        duplicate_purchase: Option<DuplicatePurchaseHistory>,
    ) -> Result<Self, HistorySnapshotError> {
        let snapshot = Self {
            repository,
            duplicate_purchase,
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
        Ok(())
    }
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
