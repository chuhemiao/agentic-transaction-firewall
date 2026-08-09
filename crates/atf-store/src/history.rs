use atf_audit::AuditPayload;
use atf_core::{
    AccountingBoundary, Amount, DailySpendAssetTotal, DailySpendHistory, DailySpendQuery,
    DecisionKind, DestinationNormalization, DuplicatePurchaseHistory, DuplicatePurchaseMatch,
    DuplicatePurchaseQuery, FirstDestinationHistory, FirstDestinationMatch, FirstDestinationQuery,
    RepositorySnapshot, RiskHistorySnapshot, Timestamp, MAX_DAILY_SPEND_ASSET_GROUPS,
};
use atf_intent::{
    normalize_destination, normalize_destination_value, validate_profile, TransactionIntent,
};
use atf_risk::RiskRuleSet;
use sqlx::{Postgres, Transaction};
use std::str::FromStr;

use crate::audit::{verify_row_contents, AuditEventRow};
use crate::{Store, StoreError};

impl Store {
    /// Capture the current committed Audit boundary and the bounded durable
    /// inputs/result used by history-dependent Risk rules.
    pub async fn capture_risk_history(
        &self,
        intent: &TransactionIntent,
        rule_set: &RiskRuleSet,
        evaluation_time: Timestamp,
    ) -> Result<RiskHistorySnapshot, StoreError> {
        self.query_risk_history(intent, rule_set, evaluation_time, None)
            .await
    }

    /// Reconstruct the exact bounded history query named by a persisted
    /// Evaluation Context. Later Audit events are never visible to this read.
    pub async fn load_risk_history_at(
        &self,
        intent: &TransactionIntent,
        rule_set: &RiskRuleSet,
        evaluation_time: Timestamp,
        repository: &RepositorySnapshot,
    ) -> Result<RiskHistorySnapshot, StoreError> {
        self.query_risk_history(intent, rule_set, evaluation_time, Some(repository))
            .await
    }

    async fn query_risk_history(
        &self,
        intent: &TransactionIntent,
        rule_set: &RiskRuleSet,
        evaluation_time: Timestamp,
        expected: Option<&RepositorySnapshot>,
    ) -> Result<RiskHistorySnapshot, StoreError> {
        validate_scope(intent)?;
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("SET LOCAL statement_timeout = '5s'")
            .execute(&mut *transaction)
            .await?;

        let repository = match expected {
            Some(expected) => {
                verify_expected_repository(
                    &mut transaction,
                    &intent.principal.organization_id,
                    expected,
                )
                .await?;
                expected.clone()
            }
            None => {
                capture_repository_head(&mut transaction, &intent.principal.organization_id).await?
            }
        };
        let duplicate_purchase = if rule_set.duplicate_purchase_enabled() {
            Some(
                query_duplicate_purchase(
                    &mut transaction,
                    intent,
                    rule_set,
                    evaluation_time,
                    &repository,
                )
                .await?,
            )
        } else {
            None
        };
        let daily_cumulative_spend = if rule_set.daily_spend_enabled() {
            Some(
                query_daily_spend(
                    &mut transaction,
                    intent,
                    rule_set,
                    evaluation_time,
                    &repository,
                )
                .await?,
            )
        } else {
            None
        };
        let first_destination = if rule_set.first_destination_enabled() {
            Some(
                query_first_destination(
                    &mut transaction,
                    intent,
                    rule_set,
                    evaluation_time,
                    &repository,
                )
                .await?,
            )
        } else {
            None
        };
        let snapshot = RiskHistorySnapshot::with_first_destination(
            repository,
            duplicate_purchase,
            daily_cumulative_spend,
            first_destination,
        )?;
        transaction.commit().await?;
        Ok(snapshot)
    }
}

async fn query_first_destination(
    transaction: &mut Transaction<'_, Postgres>,
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    evaluation_time: Timestamp,
    repository: &RepositorySnapshot,
) -> Result<FirstDestinationHistory, StoreError> {
    let boundary = rule_set
        .first_destination_accounting_boundary()
        .ok_or_else(|| StoreError::InvalidRepositoryInput {
            reason: "enabled first-destination rule lacks an accounting boundary".into(),
        })?;
    if boundary != AccountingBoundary::Permitted {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "durable first-destination queries require PERMITTED accounting".into(),
        });
    }
    let normalizer_id = rule_set.first_destination_normalizer_id().ok_or_else(|| {
        StoreError::InvalidRepositoryInput {
            reason: "enabled first-destination rule lacks a normalizer ID".into(),
        }
    })?;
    let normalizer_version = rule_set
        .first_destination_normalizer_version()
        .ok_or_else(|| StoreError::InvalidRepositoryInput {
            reason: "enabled first-destination rule lacks a normalizer version".into(),
        })?;
    let profile = validate_profile(intent).map_err(|error| StoreError::InvalidRepositoryInput {
        reason: format!("first-destination Intent Profile is invalid: {error}"),
    })?;
    let destination = match normalize_destination(intent) {
        Ok(destination) => DestinationNormalization::available(destination.value())?,
        Err(error) => DestinationNormalization::unavailable(error.code())?,
    };
    let query = FirstDestinationQuery::new(
        &intent.principal.organization_id,
        &intent.intent_id,
        profile.id(),
        profile.version(),
        normalizer_id,
        normalizer_version,
        destination,
        evaluation_time,
        boundary,
    )?;
    let Some(normalized_destination) = query.destination().value() else {
        return FirstDestinationHistory::new(query, None).map_err(StoreError::from);
    };
    let row: Option<AuditEventRow> = sqlx::query_as(
        r#"
        SELECT
            sequence,
            event_id,
            event_type,
            schema_version,
            occurred_at,
            intent_id,
            evaluation_id,
            decision_id,
            previous_event_hash::text AS previous_event_hash,
            event_hash::text AS event_hash,
            canonical_event,
            canonical_event_bytes
        FROM audit_events
        WHERE organization_id = $1
          AND event_type = 'DecisionRecorded'
          AND sequence <= $2
          AND occurred_at <= $3
          AND intent_id <> $4
          AND canonical_event -> 'data' ->> 'decision' = 'PERMIT'
          AND canonical_event -> 'data' ->> 'organization_id' = $1
          AND canonical_event #>> '{data,binding,profile,id}' = $5
          AND canonical_event #>> '{data,binding,profile,version}' = $6
          AND lower(canonical_event #>> '{data,binding,execution_constraints,destination}') = $7
        ORDER BY occurred_at DESC, sequence DESC
        LIMIT 1
        "#,
    )
    .bind(&intent.principal.organization_id)
    .bind(i64::try_from(repository.through_sequence()).map_err(|_| {
        corrupt(
            &intent.principal.organization_id,
            "Audit sequence exceeds i64",
        )
    })?)
    .bind(query.evaluation_time().as_datetime())
    .bind(&intent.intent_id)
    .bind(query.profile_id())
    .bind(query.profile_version())
    .bind(normalized_destination)
    .fetch_optional(&mut **transaction)
    .await?;

    let result = row
        .map(|row| verify_first_destination_row(&intent.principal.organization_id, &query, row))
        .transpose()?;
    FirstDestinationHistory::new(query, result).map_err(StoreError::from)
}

fn verify_first_destination_row(
    organization_id: &str,
    query: &FirstDestinationQuery,
    row: AuditEventRow,
) -> Result<FirstDestinationMatch, StoreError> {
    let event = verify_row_contents(organization_id, &row)?;
    let payload = event.typed_payload()?;
    let AuditPayload::DecisionRecorded(recorded) = payload else {
        return Err(corrupt(
            organization_id,
            "first-destination query returned a non-Decision event",
        ));
    };
    if recorded.organization_id != organization_id || recorded.decision != DecisionKind::Permit {
        return Err(corrupt(
            organization_id,
            "first-destination query returned mismatched typed evidence",
        ));
    }
    let binding = recorded.binding.as_deref().ok_or_else(|| {
        corrupt(
            organization_id,
            "first-destination Decision lacks current binding evidence",
        )
    })?;
    let destination = binding
        .execution_constraints
        .destination
        .as_deref()
        .ok_or_else(|| {
            corrupt(
                organization_id,
                "first-destination Decision lacks destination",
            )
        })?;
    if recorded.destination.as_deref() != Some(destination)
        || binding.profile.id != query.profile_id()
        || binding.profile.version != query.profile_version()
        || !destination.starts_with(&format!("{}:", binding.execution_constraints.network))
    {
        return Err(corrupt(
            organization_id,
            "first-destination Decision binding disagrees with its typed fields",
        ));
    }
    let normalized =
        normalize_destination_value(&binding.profile.id, &binding.profile.version, destination)
            .map_err(|_| {
                corrupt(
                    organization_id,
                    "first-destination Decision cannot be normalized by its bound Profile",
                )
            })?;
    if query.destination().value() != Some(normalized.value()) {
        return Err(corrupt(
            organization_id,
            "first-destination Decision does not match the normalized query key",
        ));
    }
    let intent_id = row
        .intent_id
        .ok_or_else(|| corrupt(organization_id, "Decision history lacks intent_id"))?;
    let decision_id = row
        .decision_id
        .ok_or_else(|| corrupt(organization_id, "Decision history lacks decision_id"))?;
    FirstDestinationMatch::new(
        intent_id,
        decision_id,
        row.event_id,
        u64::try_from(row.sequence)
            .map_err(|_| corrupt(organization_id, "negative Audit sequence"))?,
        Timestamp::from_datetime(row.occurred_at),
    )
    .map_err(StoreError::from)
}

async fn query_daily_spend(
    transaction: &mut Transaction<'_, Postgres>,
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    evaluation_time: Timestamp,
    repository: &RepositorySnapshot,
) -> Result<DailySpendHistory, StoreError> {
    let boundary = rule_set.daily_spend_accounting_boundary().ok_or_else(|| {
        StoreError::InvalidRepositoryInput {
            reason: "enabled daily-spend rule lacks an accounting boundary".into(),
        }
    })?;
    if boundary != AccountingBoundary::Permitted {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "durable daily-spend queries require PERMITTED accounting".into(),
        });
    }
    let window_seconds = rule_set.daily_spend_window_seconds().ok_or_else(|| {
        StoreError::InvalidRepositoryInput {
            reason: "enabled daily-spend rule lacks a history window".into(),
        }
    })?;
    let valuation_asset = rule_set.daily_spend_valuation_asset().ok_or_else(|| {
        StoreError::InvalidRepositoryInput {
            reason: "enabled daily-spend rule lacks a valuation asset".into(),
        }
    })?;
    let query = DailySpendQuery::new(
        &intent.principal.organization_id,
        &intent.principal.agent_id,
        &intent.intent_id,
        valuation_asset,
        evaluation_time,
        window_seconds,
        boundary,
    )?;
    let rows: Vec<(Option<String>, String, i64)> = sqlx::query_as(
        r#"
        SELECT
            canonical_event #>> '{data,binding,execution_constraints,asset}' AS asset,
            SUM((canonical_event -> 'data' ->> 'amount')::numeric)::text AS total_amount,
            COUNT(*)::bigint AS decision_count
        FROM audit_events
        WHERE organization_id = $1
          AND event_type = 'DecisionRecorded'
          AND sequence <= $2
          AND occurred_at >= $3
          AND occurred_at <= $4
          AND intent_id <> $5
          AND canonical_event -> 'data' ->> 'decision' = 'PERMIT'
          AND canonical_event -> 'data' ->> 'organization_id' = $1
          AND canonical_event -> 'data' ->> 'agent_id' = $6
        GROUP BY canonical_event #>> '{data,binding,execution_constraints,asset}'
        ORDER BY asset ASC NULLS LAST
        LIMIT $7
        "#,
    )
    .bind(&intent.principal.organization_id)
    .bind(i64::try_from(repository.through_sequence()).map_err(|_| {
        corrupt(
            &intent.principal.organization_id,
            "Audit sequence exceeds i64",
        )
    })?)
    .bind(query.window_start().as_datetime())
    .bind(query.evaluation_time().as_datetime())
    .bind(&intent.intent_id)
    .bind(&intent.principal.agent_id)
    .bind(
        i64::try_from(MAX_DAILY_SPEND_ASSET_GROUPS + 1).map_err(|_| {
            corrupt(
                &intent.principal.organization_id,
                "daily-spend asset-group bound exceeds i64",
            )
        })?,
    )
    .fetch_all(&mut **transaction)
    .await?;

    if rows.len() > MAX_DAILY_SPEND_ASSET_GROUPS {
        return Err(StoreError::InvalidRepositoryInput {
            reason: format!(
                "daily-spend history exceeds {MAX_DAILY_SPEND_ASSET_GROUPS} asset groups"
            ),
        });
    }

    // Evaluation Context persistence verifies the complete Audit chain at
    // this same repository boundary before Risk can consume the aggregate.
    let mut totals = Vec::new();
    let mut unresolved_asset_decision_count = 0_u64;
    for (asset, total_amount, decision_count) in rows {
        let count = u64::try_from(decision_count).map_err(|_| {
            corrupt(
                &intent.principal.organization_id,
                "daily-spend aggregate returned an invalid decision count",
            )
        })?;
        match asset {
            Some(asset) => {
                let amount = Amount::from_str(&total_amount).map_err(|_| {
                    corrupt(
                        &intent.principal.organization_id,
                        "daily-spend aggregate is not representable as a fixed-point amount",
                    )
                })?;
                totals.push(DailySpendAssetTotal::new(asset, amount, count)?);
            }
            None => {
                unresolved_asset_decision_count = unresolved_asset_decision_count
                    .checked_add(count)
                    .ok_or_else(|| {
                        corrupt(
                            &intent.principal.organization_id,
                            "daily-spend unresolved-asset count overflowed",
                        )
                    })?;
            }
        }
    }
    DailySpendHistory::new(query, totals, unresolved_asset_decision_count).map_err(StoreError::from)
}

async fn capture_repository_head(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
) -> Result<RepositorySnapshot, StoreError> {
    let head: Option<(i64, Option<String>)> = sqlx::query_as(
        "SELECT last_sequence, last_event_hash::text FROM audit_chain_heads WHERE organization_id = $1",
    )
    .bind(organization_id)
    .fetch_optional(&mut **transaction)
    .await?;
    let Some((sequence, Some(event_hash))) = head else {
        return Err(StoreError::AuditChainCorrupt {
            organization_id: organization_id.into(),
            reason: "Risk history requires a non-empty committed Audit boundary".into(),
        });
    };
    let tail = load_event_at(transaction, organization_id, sequence).await?;
    if tail.event_hash != event_hash {
        return Err(corrupt(
            organization_id,
            "Audit head disagrees with its tail event",
        ));
    }
    RepositorySnapshot::new(
        format!("audit-chain:{organization_id}:{sequence}"),
        u64::try_from(sequence).map_err(|_| corrupt(organization_id, "negative Audit sequence"))?,
        event_hash,
    )
    .map_err(StoreError::from)
}

async fn verify_expected_repository(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    expected: &RepositorySnapshot,
) -> Result<(), StoreError> {
    let expected_id = format!(
        "audit-chain:{organization_id}:{}",
        expected.through_sequence()
    );
    if expected.snapshot_id() != expected_id {
        return Err(corrupt(
            organization_id,
            "requested Risk history snapshot has the wrong organization or sequence",
        ));
    }
    let sequence = i64::try_from(expected.through_sequence())
        .map_err(|_| corrupt(organization_id, "Audit sequence exceeds i64"))?;
    let row = load_event_at(transaction, organization_id, sequence).await?;
    if row.event_hash != expected.snapshot_hash() {
        return Err(corrupt(
            organization_id,
            "requested Risk history snapshot hash disagrees with durable Audit",
        ));
    }
    Ok(())
}

async fn query_duplicate_purchase(
    transaction: &mut Transaction<'_, Postgres>,
    intent: &TransactionIntent,
    rule_set: &RiskRuleSet,
    evaluation_time: Timestamp,
    repository: &RepositorySnapshot,
) -> Result<DuplicatePurchaseHistory, StoreError> {
    let boundary = rule_set.duplicate_purchase_accounting_boundary();
    if boundary != AccountingBoundary::Permitted {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "durable duplicate-purchase queries currently require PERMITTED accounting"
                .into(),
        });
    }
    let query = DuplicatePurchaseQuery::new(
        &intent.principal.organization_id,
        &intent.principal.agent_id,
        &intent.resource.resource_id,
        &intent.intent_id,
        evaluation_time,
        rule_set.duplicate_purchase_window_seconds(),
        boundary,
    )?;
    let row: Option<AuditEventRow> = sqlx::query_as(
        r#"
        SELECT
            sequence,
            event_id,
            event_type,
            schema_version,
            occurred_at,
            intent_id,
            evaluation_id,
            decision_id,
            previous_event_hash::text AS previous_event_hash,
            event_hash::text AS event_hash,
            canonical_event,
            canonical_event_bytes
        FROM audit_events
        WHERE organization_id = $1
          AND event_type = 'DecisionRecorded'
          AND sequence <= $2
          AND occurred_at >= $3
          AND occurred_at <= $4
          AND intent_id <> $5
          AND canonical_event -> 'data' ->> 'decision' = 'PERMIT'
          AND canonical_event -> 'data' ->> 'organization_id' = $1
          AND canonical_event -> 'data' ->> 'agent_id' = $6
          AND canonical_event -> 'data' ->> 'resource_id' = $7
        ORDER BY occurred_at DESC, sequence DESC
        LIMIT 1
        "#,
    )
    .bind(&intent.principal.organization_id)
    .bind(i64::try_from(repository.through_sequence()).map_err(|_| {
        corrupt(
            &intent.principal.organization_id,
            "Audit sequence exceeds i64",
        )
    })?)
    .bind(query.window_start().as_datetime())
    .bind(query.evaluation_time().as_datetime())
    .bind(&intent.intent_id)
    .bind(&intent.principal.agent_id)
    .bind(&intent.resource.resource_id)
    .fetch_optional(&mut **transaction)
    .await?;

    let result = row
        .map(|row| verify_duplicate_row(&intent.principal.organization_id, row))
        .transpose()?;
    DuplicatePurchaseHistory::new(query, result).map_err(StoreError::from)
}

fn verify_duplicate_row(
    organization_id: &str,
    row: AuditEventRow,
) -> Result<DuplicatePurchaseMatch, StoreError> {
    let event = verify_row_contents(organization_id, &row)?;
    let payload = event.typed_payload()?;
    let AuditPayload::DecisionRecorded(recorded) = payload else {
        return Err(corrupt(
            organization_id,
            "duplicate-purchase query returned a non-Decision event",
        ));
    };
    if recorded.organization_id != organization_id || recorded.decision != DecisionKind::Permit {
        return Err(corrupt(
            organization_id,
            "duplicate-purchase query returned mismatched typed evidence",
        ));
    }
    let intent_id = row
        .intent_id
        .ok_or_else(|| corrupt(organization_id, "Decision history lacks intent_id"))?;
    let decision_id = row
        .decision_id
        .ok_or_else(|| corrupt(organization_id, "Decision history lacks decision_id"))?;
    DuplicatePurchaseMatch::new(
        intent_id,
        decision_id,
        row.event_id,
        u64::try_from(row.sequence)
            .map_err(|_| corrupt(organization_id, "negative Audit sequence"))?,
        Timestamp::from_datetime(row.occurred_at),
    )
    .map_err(StoreError::from)
}

async fn load_event_at(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    sequence: i64,
) -> Result<AuditEventRow, StoreError> {
    let row = sqlx::query_as(
        r#"
        SELECT
            sequence,
            event_id,
            event_type,
            schema_version,
            occurred_at,
            intent_id,
            evaluation_id,
            decision_id,
            previous_event_hash::text AS previous_event_hash,
            event_hash::text AS event_hash,
            canonical_event,
            canonical_event_bytes
        FROM audit_events
        WHERE organization_id = $1 AND sequence = $2
        "#,
    )
    .bind(organization_id)
    .bind(sequence)
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or_else(|| corrupt(organization_id, "Risk history Audit boundary is missing"))?;
    verify_row_contents(organization_id, &row)?;
    Ok(row)
}

fn validate_scope(intent: &TransactionIntent) -> Result<(), StoreError> {
    for value in [
        intent.principal.organization_id.as_str(),
        intent.principal.agent_id.as_str(),
        intent.resource.resource_id.as_str(),
        intent.intent_id.as_str(),
    ] {
        if value.is_empty() || value.len() > 256 || value.trim() != value {
            return Err(StoreError::InvalidRepositoryInput {
                reason: "Risk history scope must use canonical bounded identifiers".into(),
            });
        }
    }
    Ok(())
}

fn corrupt(organization_id: &str, reason: impl Into<String>) -> StoreError {
    StoreError::AuditChainCorrupt {
        organization_id: organization_id.into(),
        reason: reason.into(),
    }
}
