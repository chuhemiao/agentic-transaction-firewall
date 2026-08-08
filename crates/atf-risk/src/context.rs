use std::collections::{BTreeMap, BTreeSet};

use atf_core::{
    Amount, EvidenceEnvelope, EvidenceError, EvidenceKind, EvidenceSource, EvidenceTrustPolicy,
    Timestamp, VerifiedEvidence,
};
use atf_intent::TransactionIntent;
use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskContextIssue {
    Missing,
    AgentProvided,
    EvidenceInvalid,
    HashMismatch,
    UntrustedSource,
    KindNotAllowed,
    SignatureMissing,
    SignatureKeyUnknown,
    SignatureInvalid,
    NotYetValid,
    Stale,
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
            Self::AgentProvided => "AGENT_PROVIDED_PRIVILEGED_INPUT",
            Self::EvidenceInvalid => "EVIDENCE_INVALID",
            Self::HashMismatch => "EVIDENCE_HASH_MISMATCH",
            Self::UntrustedSource => "EVIDENCE_UNTRUSTED_SOURCE",
            Self::KindNotAllowed => "EVIDENCE_KIND_NOT_ALLOWED",
            Self::SignatureMissing => "EVIDENCE_SIGNATURE_MISSING",
            Self::SignatureKeyUnknown => "EVIDENCE_SIGNATURE_KEY_UNKNOWN",
            Self::SignatureInvalid => "EVIDENCE_SIGNATURE_INVALID",
            Self::NotYetValid => "EVIDENCE_NOT_YET_VALID",
            Self::Stale => "EVIDENCE_STALE",
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
    verified: BTreeMap<EvidenceKind, Vec<VerifiedEvidence>>,
    issues: BTreeMap<EvidenceKind, RiskContextIssue>,
    rejected_agent_keys: BTreeSet<String>,
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
    pub fn from_evidence<'a>(
        intent: &TransactionIntent,
        evidence: impl IntoIterator<Item = &'a EvidenceEnvelope>,
        trust_policy: &EvidenceTrustPolicy,
        evaluated_at: Timestamp,
    ) -> Self {
        let mut context = Self::agent_only(intent);
        for envelope in evidence {
            match trust_policy.verify(envelope, evaluated_at) {
                Ok(verified) => {
                    let values = context.verified.entry(verified.kind()).or_default();
                    if !values
                        .iter()
                        .any(|existing| existing.evidence_hash() == verified.evidence_hash())
                    {
                        values.push(verified);
                    }
                }
                Err(error) => {
                    context.record_issue(
                        envelope.kind(),
                        RiskContextIssue::from_evidence_error(&error),
                    );
                }
            }
        }
        context
    }

    pub fn verified(&self, kind: EvidenceKind) -> &[VerifiedEvidence] {
        self.verified.get(&kind).map_or(&[], Vec::as_slice)
    }

    pub fn rejected_agent_keys(&self) -> impl Iterator<Item = &str> {
        self.rejected_agent_keys.iter().map(String::as_str)
    }

    pub(crate) fn agent_only(intent: &TransactionIntent) -> Self {
        let rejected_agent_keys = intent
            .context
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(key, _)| privileged_kind(key).map(|_| key.clone()))
            .collect();
        Self {
            intent_hash: intent.canonical_hash(),
            verified: BTreeMap::new(),
            issues: BTreeMap::new(),
            rejected_agent_keys,
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
        let mut candidate_issue = self.issues.get(&EvidenceKind::Price).copied();
        for evidence in self.verified(EvidenceKind::Price) {
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
            [] => {
                if let Some(issue) = candidate_issue {
                    Err(issue)
                } else if self.agent_has_kind(EvidenceKind::Price) {
                    Err(RiskContextIssue::AgentProvided)
                } else {
                    Err(RiskContextIssue::Missing)
                }
            }
            _ => Err(RiskContextIssue::Ambiguous),
        }
    }

    fn agent_has_kind(&self, kind: EvidenceKind) -> bool {
        self.rejected_agent_keys
            .iter()
            .any(|key| privileged_kind(key) == Some(kind))
    }

    fn record_issue(&mut self, kind: EvidenceKind, issue: RiskContextIssue) {
        self.issues
            .entry(kind)
            .and_modify(|current| *current = best_issue(Some(*current), issue))
            .or_insert(issue);
    }
}

fn privileged_kind(key: &str) -> Option<EvidenceKind> {
    match key {
        "historical_vendor_median" | "price" | "market_price" => Some(EvidenceKind::Price),
        "balance" | "account_balance" => Some(EvidenceKind::Balance),
        "position" | "positions" => Some(EvidenceKind::Position),
        "leverage" => Some(EvidenceKind::Leverage),
        "cumulative_spend" | "daily_cumulative_spend" | "daily_spend" => {
            Some(EvidenceKind::CumulativeSpend)
        }
        "protocol_risk" => Some(EvidenceKind::ProtocolRisk),
        "address_reputation" | "reputation" => Some(EvidenceKind::AddressReputation),
        "market_data_freshness" | "staleness_ms" => Some(EvidenceKind::MarketDataFreshness),
        "simulation_result" | "simulation" => Some(EvidenceKind::SimulationResult),
        _ => None,
    }
}

impl RiskContextIssue {
    fn from_evidence_error(error: &EvidenceError) -> Self {
        match error {
            EvidenceError::HashMismatch => Self::HashMismatch,
            EvidenceError::UntrustedSource => Self::UntrustedSource,
            EvidenceError::KindNotAllowed => Self::KindNotAllowed,
            EvidenceError::MissingSignature => Self::SignatureMissing,
            EvidenceError::UnknownSignatureKey => Self::SignatureKeyUnknown,
            EvidenceError::SignatureInvalid => Self::SignatureInvalid,
            EvidenceError::NotYetValid => Self::NotYetValid,
            EvidenceError::Stale => Self::Stale,
            EvidenceError::Json(_) | EvidenceError::Invalid(_) => Self::EvidenceInvalid,
        }
    }

    const fn priority(self) -> u8 {
        match self {
            Self::Ambiguous => 0,
            Self::HashMismatch => 1,
            Self::SignatureInvalid => 2,
            Self::SignatureMissing => 3,
            Self::SignatureKeyUnknown => 4,
            Self::UntrustedSource => 5,
            Self::KindNotAllowed => 6,
            Self::NotYetValid => 7,
            Self::Stale => 8,
            Self::EvidenceInvalid => 9,
            Self::InputSourceNotAllowed => 10,
            Self::ValueInvalid => 11,
            Self::ScopeMismatch => 12,
            Self::ContextIntentMismatch => 13,
            Self::AgentProvided => 14,
            Self::Missing => 15,
        }
    }
}

fn best_issue(current: Option<RiskContextIssue>, candidate: RiskContextIssue) -> RiskContextIssue {
    match current {
        Some(current) if current.priority() <= candidate.priority() => current,
        _ => candidate,
    }
}
