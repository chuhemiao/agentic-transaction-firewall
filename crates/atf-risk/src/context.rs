use std::collections::BTreeMap;

use atf_core::{Amount, EvaluationContext, EvidenceEnvelope, EvidenceKind, EvidenceSource};
use atf_intent::TransactionIntent;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskContextIssue {
    Missing,
    Ambiguous,
    InputSourceNotAllowed,
    ValueInvalid,
    ScopeMismatch,
    ContextIntentMismatch,
}

impl RiskContextIssue {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Missing => "EVIDENCE_MISSING",
            Self::Ambiguous => "EVIDENCE_AMBIGUOUS",
            Self::InputSourceNotAllowed => "EVIDENCE_INPUT_SOURCE_NOT_ALLOWED",
            Self::ValueInvalid => "EVIDENCE_VALUE_INVALID",
            Self::ScopeMismatch => "EVIDENCE_SCOPE_MISMATCH",
            Self::ContextIntentMismatch => "EVIDENCE_CONTEXT_INTENT_MISMATCH",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RiskContext {
    intent_hash: String,
    verified: BTreeMap<EvidenceKind, Vec<EvidenceEnvelope>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoricalVendorMedianValue {
    #[serde(rename = "metric")]
    _metric: HistoricalVendorMedianMetric,
    organization_id: String,
    resource_id: String,
    asset: String,
    amount: Amount,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum HistoricalVendorMedianMetric {
    HistoricalVendorMedian,
}

impl RiskContext {
    pub(crate) fn from_evaluation_context(
        intent: &TransactionIntent,
        evaluation_context: &EvaluationContext,
    ) -> Self {
        let mut verified = BTreeMap::<EvidenceKind, Vec<EvidenceEnvelope>>::new();
        for envelope in evaluation_context.evidence_envelopes() {
            verified
                .entry(envelope.kind())
                .or_default()
                .push(envelope.clone());
        }
        Self {
            intent_hash: intent.canonical_hash(),
            verified,
        }
    }

    pub(crate) fn historical_vendor_median(
        &self,
        intent: &TransactionIntent,
    ) -> Result<Amount, RiskContextIssue> {
        if self.intent_hash != intent.canonical_hash() {
            return Err(RiskContextIssue::ContextIntentMismatch);
        }
        let mut matches = Vec::new();
        let mut candidate_issue = None;
        for evidence in self
            .verified
            .get(&EvidenceKind::Price)
            .map_or(&[][..], Vec::as_slice)
        {
            if evidence.source() != EvidenceSource::AtfEnriched {
                candidate_issue = Some(best_issue(
                    candidate_issue,
                    RiskContextIssue::InputSourceNotAllowed,
                ));
                continue;
            }
            let Ok(value) =
                serde_json::from_value::<HistoricalVendorMedianValue>(evidence.value().clone())
            else {
                candidate_issue = Some(best_issue(candidate_issue, RiskContextIssue::ValueInvalid));
                continue;
            };
            if value.organization_id != intent.principal.organization_id
                || value.resource_id != intent.resource.resource_id
                || value.asset != intent.transaction.asset
            {
                candidate_issue =
                    Some(best_issue(candidate_issue, RiskContextIssue::ScopeMismatch));
                continue;
            }
            if value.amount.as_decimal() <= rust_decimal::Decimal::ZERO {
                candidate_issue = Some(best_issue(candidate_issue, RiskContextIssue::ValueInvalid));
                continue;
            }
            matches.push(value.amount);
        }
        match matches.as_slice() {
            [amount] => Ok(*amount),
            [] => Err(candidate_issue.unwrap_or(RiskContextIssue::Missing)),
            _ => Err(RiskContextIssue::Ambiguous),
        }
    }
}
impl RiskContextIssue {
    const fn priority(self) -> u8 {
        match self {
            Self::Ambiguous => 0,
            Self::InputSourceNotAllowed => 1,
            Self::ValueInvalid => 2,
            Self::ScopeMismatch => 3,
            Self::ContextIntentMismatch => 4,
            Self::Missing => 5,
        }
    }
}

fn best_issue(current: Option<RiskContextIssue>, candidate: RiskContextIssue) -> RiskContextIssue {
    match current {
        Some(current) if current.priority() <= candidate.priority() => current,
        _ => candidate,
    }
}
