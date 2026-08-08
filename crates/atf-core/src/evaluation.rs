use std::collections::BTreeSet;

use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

use crate::{sha256_hex, sort_json_keys, EvidenceEnvelope, EvidenceFreshness, Timestamp};
use crate::{EvidenceError, VerifiedEvidence};

const EVALUATION_CONTEXT_VERSION: &str = "1";
const CONTEXT_HASH_DOMAIN: &[u8] = b"ATF_EVALUATION_CONTEXT_V1\0";
const SNAPSHOT_HASH_DOMAIN: &[u8] = b"ATF_CONTEXT_SNAPSHOT_V1\0";
const AGENT_CONTEXT_HASH_DOMAIN: &[u8] = b"ATF_AGENT_CONTEXT_V1\0";
const MAX_CONTEXT_BYTES: usize = 1024 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_EVIDENCE_ITEMS: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum EvaluationContextError {
    #[error("Evaluation Context JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Evaluation Context is invalid: {0}")]
    Invalid(String),
    #[error("Evaluation Context hash does not match its canonical payload")]
    HashMismatch,
    #[error("Evaluation Context Evidence is invalid: {0}")]
    Evidence(#[from] EvidenceError),
}

/// One selected executable artifact, or an explicit fail-closed absence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum VersionedArtifactReference {
    Available {
        artifact_id: String,
        version: String,
        hash: String,
    },
    Unavailable {
        reason_code: String,
    },
}

/// Identity of the deployment-owned Evidence trust policy used to construct
/// the snapshot. An empty Evidence list may explicitly record no policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum EvidenceTrustPolicyReference {
    Configured { version: String, hash: String },
    NotConfigured { reason_code: String },
}

/// Exact repository history boundary supplied to history-dependent rules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositorySnapshot {
    snapshot_id: String,
    through_sequence: u64,
    snapshot_hash: String,
}

/// External snapshot input that is either named by immutable hash or records
/// why no such input was available.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum ExternalSnapshotReference {
    Available {
        snapshot_id: String,
        snapshot_hash: String,
    },
    Unavailable {
        reason_code: String,
    },
}

/// Simulation remains closed to `NOT_RUN` until the typed Simulator contract
/// is implemented. A later context version can add completed snapshots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "status",
    rename_all = "SCREAMING_SNAKE_CASE",
    deny_unknown_fields
)]
pub enum SimulationReference {
    NotRun { reason_code: String },
}

#[derive(Debug, Clone)]
pub struct EvaluationContextInput {
    pub evaluation_id: String,
    pub intent_id: String,
    pub intent_hash: String,
    pub evaluation_time: Timestamp,
    pub environment: String,
    pub profile_id: String,
    pub profile_version: String,
    pub policy: VersionedArtifactReference,
    pub risk: VersionedArtifactReference,
    pub context_snapshot_id: String,
    pub agent_context: Value,
    pub evidence: Vec<VerifiedEvidence>,
    pub evidence_trust_policy: EvidenceTrustPolicyReference,
    pub history: RepositorySnapshot,
    pub market_data: ExternalSnapshotReference,
    pub simulation: SimulationReference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceSnapshotRecord {
    envelope: EvidenceEnvelope,
    freshness_status: EvidenceFreshness,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvaluationContextDocument {
    evaluation_context_version: String,
    evaluation_id: String,
    intent_id: String,
    intent_hash: String,
    evaluation_time: Timestamp,
    environment: String,
    profile_id: String,
    profile_version: String,
    policy: VersionedArtifactReference,
    risk: VersionedArtifactReference,
    context_snapshot_id: String,
    agent_context_hash: String,
    evidence_trust_policy: EvidenceTrustPolicyReference,
    evidence: Vec<EvidenceSnapshotRecord>,
    context_snapshot_hash: String,
    history: RepositorySnapshot,
    market_data: ExternalSnapshotReference,
    simulation: SimulationReference,
    evaluation_context_hash: String,
}

#[derive(Serialize)]
struct ContextSnapshotHashPayload<'a> {
    context_snapshot_id: &'a str,
    agent_context_hash: &'a str,
    evidence_trust_policy: &'a EvidenceTrustPolicyReference,
    evidence: &'a [EvidenceSnapshotRecord],
}

#[derive(Serialize)]
struct EvaluationContextHashPayload<'a> {
    evaluation_context_version: &'a str,
    evaluation_id: &'a str,
    intent_id: &'a str,
    intent_hash: &'a str,
    evaluation_time: Timestamp,
    environment: &'a str,
    profile_id: &'a str,
    profile_version: &'a str,
    policy: &'a VersionedArtifactReference,
    risk: &'a VersionedArtifactReference,
    context_snapshot_id: &'a str,
    agent_context_hash: &'a str,
    evidence_trust_policy: &'a EvidenceTrustPolicyReference,
    evidence: &'a [EvidenceSnapshotRecord],
    context_snapshot_hash: &'a str,
    history: &'a RepositorySnapshot,
    market_data: &'a ExternalSnapshotReference,
    simulation: &'a SimulationReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextOrigin {
    ConstructedFromVerifiedInputs,
    LoadedFromPersistence,
}

/// Immutable, hash-verified input snapshot for one Evaluation.
///
/// Only [`EvaluationContext::new`] marks a value as persistable because that
/// constructor accepts already-verified Evidence. Values reconstructed from
/// durable bytes remain useful for verification/replay but cannot be inserted
/// as a new authoritative snapshot.
#[derive(Debug, Clone)]
pub struct EvaluationContext {
    document: EvaluationContextDocument,
    canonical_bytes: Vec<u8>,
    origin: ContextOrigin,
}

impl PartialEq for EvaluationContext {
    fn eq(&self, other: &Self) -> bool {
        self.document == other.document
    }
}

impl Eq for EvaluationContext {}

impl Serialize for EvaluationContext {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.document.serialize(serializer)
    }
}

impl VersionedArtifactReference {
    pub fn available(
        artifact_id: impl Into<String>,
        version: impl Into<String>,
        hash: impl Into<String>,
    ) -> Result<Self, EvaluationContextError> {
        let reference = Self::Available {
            artifact_id: artifact_id.into(),
            version: version.into(),
            hash: hash.into(),
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn unavailable(reason_code: impl Into<String>) -> Result<Self, EvaluationContextError> {
        let reference = Self::Unavailable {
            reason_code: reason_code.into(),
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn available_parts(&self) -> Option<(&str, &str, &str)> {
        match self {
            Self::Available {
                artifact_id,
                version,
                hash,
            } => Some((artifact_id, version, hash)),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn unavailable_reason(&self) -> Option<&str> {
        match self {
            Self::Available { .. } => None,
            Self::Unavailable { reason_code } => Some(reason_code),
        }
    }

    fn validate(&self) -> Result<(), EvaluationContextError> {
        match self {
            Self::Available {
                artifact_id,
                version,
                hash,
            } => {
                validate_identifier("artifact_id", artifact_id)?;
                validate_identifier("artifact version", version)?;
                validate_hash("artifact hash", hash)
            }
            Self::Unavailable { reason_code } => validate_identifier("reason_code", reason_code),
        }
    }
}

impl EvidenceTrustPolicyReference {
    pub fn configured(
        version: impl Into<String>,
        hash: impl Into<String>,
    ) -> Result<Self, EvaluationContextError> {
        let reference = Self::Configured {
            version: version.into(),
            hash: hash.into(),
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn not_configured(reason_code: impl Into<String>) -> Result<Self, EvaluationContextError> {
        let reference = Self::NotConfigured {
            reason_code: reason_code.into(),
        };
        reference.validate()?;
        Ok(reference)
    }

    fn validate(&self) -> Result<(), EvaluationContextError> {
        match self {
            Self::Configured { version, hash } => {
                validate_identifier("trust policy version", version)?;
                validate_hash("trust policy hash", hash)
            }
            Self::NotConfigured { reason_code } => {
                validate_identifier("trust policy reason_code", reason_code)
            }
        }
    }
}

impl RepositorySnapshot {
    pub fn new(
        snapshot_id: impl Into<String>,
        through_sequence: u64,
        snapshot_hash: impl Into<String>,
    ) -> Result<Self, EvaluationContextError> {
        let snapshot = Self {
            snapshot_id: snapshot_id.into(),
            through_sequence,
            snapshot_hash: snapshot_hash.into(),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    pub fn through_sequence(&self) -> u64 {
        self.through_sequence
    }

    pub fn snapshot_hash(&self) -> &str {
        &self.snapshot_hash
    }

    fn validate(&self) -> Result<(), EvaluationContextError> {
        validate_identifier("history.snapshot_id", &self.snapshot_id)?;
        if self.through_sequence == 0 {
            return invalid("history.through_sequence must be positive");
        }
        validate_hash("history.snapshot_hash", &self.snapshot_hash)
    }
}

impl ExternalSnapshotReference {
    pub fn available(
        snapshot_id: impl Into<String>,
        snapshot_hash: impl Into<String>,
    ) -> Result<Self, EvaluationContextError> {
        let reference = Self::Available {
            snapshot_id: snapshot_id.into(),
            snapshot_hash: snapshot_hash.into(),
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn unavailable(reason_code: impl Into<String>) -> Result<Self, EvaluationContextError> {
        let reference = Self::Unavailable {
            reason_code: reason_code.into(),
        };
        reference.validate()?;
        Ok(reference)
    }

    fn validate(&self) -> Result<(), EvaluationContextError> {
        match self {
            Self::Available {
                snapshot_id,
                snapshot_hash,
            } => {
                validate_identifier("external snapshot_id", snapshot_id)?;
                validate_hash("external snapshot_hash", snapshot_hash)
            }
            Self::Unavailable { reason_code } => {
                validate_identifier("external reason_code", reason_code)
            }
        }
    }
}

impl SimulationReference {
    pub fn not_run(reason_code: impl Into<String>) -> Result<Self, EvaluationContextError> {
        let reference = Self::NotRun {
            reason_code: reason_code.into(),
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn reason_code(&self) -> &str {
        match self {
            Self::NotRun { reason_code } => reason_code,
        }
    }

    fn validate(&self) -> Result<(), EvaluationContextError> {
        match self {
            Self::NotRun { reason_code } => {
                validate_identifier("simulation reason_code", reason_code)
            }
        }
    }
}

impl EvaluationContext {
    pub fn new(input: EvaluationContextInput) -> Result<Self, EvaluationContextError> {
        if !input.agent_context.is_object() {
            return invalid("agent_context must be an object");
        }
        if !input.evidence.is_empty() {
            let EvidenceTrustPolicyReference::Configured { hash, .. } =
                &input.evidence_trust_policy
            else {
                return invalid("Evidence requires a configured trust-policy identity");
            };
            if input
                .evidence
                .iter()
                .any(|verified| verified.trust_policy_hash() != hash)
            {
                return invalid("Evidence trust-policy hash does not match its verifier");
            }
        }
        let agent_context_hash = domain_hash(AGENT_CONTEXT_HASH_DOMAIN, &input.agent_context)?;
        let mut evidence = input
            .evidence
            .into_iter()
            .map(|verified| EvidenceSnapshotRecord {
                envelope: verified.envelope().clone(),
                freshness_status: verified.freshness_status(),
            })
            .collect::<Vec<_>>();
        evidence.sort_by(|left, right| {
            left.envelope
                .evidence_hash()
                .cmp(right.envelope.evidence_hash())
        });
        evidence.dedup_by(|left, right| {
            left.envelope.evidence_hash() == right.envelope.evidence_hash()
        });
        if evidence.len() > MAX_EVIDENCE_ITEMS {
            return invalid("Evidence snapshot exceeds 64 items");
        }

        let context_snapshot_hash = expected_snapshot_hash(
            &input.context_snapshot_id,
            &agent_context_hash,
            &input.evidence_trust_policy,
            &evidence,
        )?;
        let mut context = Self {
            document: EvaluationContextDocument {
                evaluation_context_version: EVALUATION_CONTEXT_VERSION.into(),
                evaluation_id: input.evaluation_id,
                intent_id: input.intent_id,
                intent_hash: input.intent_hash,
                evaluation_time: input.evaluation_time,
                environment: input.environment,
                profile_id: input.profile_id,
                profile_version: input.profile_version,
                policy: input.policy,
                risk: input.risk,
                context_snapshot_id: input.context_snapshot_id,
                agent_context_hash,
                evidence_trust_policy: input.evidence_trust_policy,
                evidence,
                context_snapshot_hash,
                history: input.history,
                market_data: input.market_data,
                simulation: input.simulation,
                evaluation_context_hash: "0".repeat(64),
            },
            canonical_bytes: Vec::new(),
            origin: ContextOrigin::ConstructedFromVerifiedInputs,
        };
        context.validate_document()?;
        context.document.evaluation_context_hash = context.expected_hash()?;
        context.validate_size()?;
        context.canonical_bytes = context.document_canonical_bytes();
        Ok(context)
    }

    /// Reconstruct and verify a durable document. This does not mark the
    /// result as a new persistable authority boundary.
    pub fn from_persisted(
        bytes: &[u8],
        expected_hash: &str,
    ) -> Result<Self, EvaluationContextError> {
        if bytes.len() > MAX_CONTEXT_BYTES {
            return invalid("document exceeds 1048576 bytes");
        }
        validate_hash("expected Evaluation Context hash", expected_hash)?;
        let document: EvaluationContextDocument = serde_json::from_slice(bytes)?;
        let mut context = Self {
            document,
            canonical_bytes: Vec::new(),
            origin: ContextOrigin::LoadedFromPersistence,
        };
        context.validate_document()?;
        context.verify_hash(expected_hash)?;
        context.canonical_bytes = context.document_canonical_bytes();
        Ok(context)
    }

    pub fn verify_hash(&self, expected_hash: &str) -> Result<(), EvaluationContextError> {
        let expected_snapshot = expected_snapshot_hash(
            &self.document.context_snapshot_id,
            &self.document.agent_context_hash,
            &self.document.evidence_trust_policy,
            &self.document.evidence,
        )?;
        if self.document.context_snapshot_hash != expected_snapshot
            || self.document.evaluation_context_hash != self.expected_hash()?
            || self.document.evaluation_context_hash != expected_hash
        {
            return Err(EvaluationContextError::HashMismatch);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }

    fn document_canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&sort_json_keys(
            serde_json::to_value(&self.document)
                .expect("Evaluation Context serialization cannot fail"),
        ))
        .expect("canonical Evaluation Context serialization cannot fail")
    }

    pub fn is_newly_constructed(&self) -> bool {
        self.origin == ContextOrigin::ConstructedFromVerifiedInputs
    }

    pub fn evaluation_id(&self) -> &str {
        &self.document.evaluation_id
    }

    pub fn intent_id(&self) -> &str {
        &self.document.intent_id
    }

    pub fn intent_hash(&self) -> &str {
        &self.document.intent_hash
    }

    pub fn evaluation_time(&self) -> Timestamp {
        self.document.evaluation_time
    }

    pub fn environment(&self) -> &str {
        &self.document.environment
    }

    pub fn profile_id(&self) -> &str {
        &self.document.profile_id
    }

    pub fn profile_version(&self) -> &str {
        &self.document.profile_version
    }

    pub fn policy(&self) -> &VersionedArtifactReference {
        &self.document.policy
    }

    pub fn risk(&self) -> &VersionedArtifactReference {
        &self.document.risk
    }

    pub fn context_snapshot_id(&self) -> &str {
        &self.document.context_snapshot_id
    }

    pub fn context_snapshot_hash(&self) -> &str {
        &self.document.context_snapshot_hash
    }

    pub fn agent_context_hash(&self) -> &str {
        &self.document.agent_context_hash
    }

    pub fn evidence_trust_policy(&self) -> &EvidenceTrustPolicyReference {
        &self.document.evidence_trust_policy
    }

    /// Verify that the Agent-provided context retained by the immutable Intent
    /// is the exact value represented by this snapshot.
    pub fn verify_agent_context(
        &self,
        agent_context: &Value,
    ) -> Result<(), EvaluationContextError> {
        if !agent_context.is_object() {
            return invalid("agent_context must be an object");
        }
        if domain_hash(AGENT_CONTEXT_HASH_DOMAIN, agent_context)?
            != self.document.agent_context_hash
        {
            return Err(EvaluationContextError::HashMismatch);
        }
        Ok(())
    }

    pub fn history(&self) -> &RepositorySnapshot {
        &self.document.history
    }

    pub fn market_data(&self) -> &ExternalSnapshotReference {
        &self.document.market_data
    }

    pub fn simulation(&self) -> &SimulationReference {
        &self.document.simulation
    }

    pub fn evaluation_context_hash(&self) -> &str {
        &self.document.evaluation_context_hash
    }

    pub fn evidence_envelopes(&self) -> impl Iterator<Item = &EvidenceEnvelope> {
        self.document.evidence.iter().map(|record| &record.envelope)
    }

    pub fn evidence_source_ids(&self) -> Vec<String> {
        self.document
            .evidence
            .iter()
            .map(|record| record.envelope.source_id().to_owned())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    pub fn context_source_ids(&self) -> Vec<String> {
        let mut sources = BTreeSet::from(["agent-intent-context".to_owned()]);
        sources.extend(self.evidence_source_ids());
        sources.into_iter().collect()
    }

    fn validate_document(&self) -> Result<(), EvaluationContextError> {
        let document = &self.document;
        if document.evaluation_context_version != EVALUATION_CONTEXT_VERSION {
            return invalid("unsupported evaluation_context_version");
        }
        for (field, value) in [
            ("evaluation_id", document.evaluation_id.as_str()),
            ("intent_id", document.intent_id.as_str()),
            ("environment", document.environment.as_str()),
            ("profile_id", document.profile_id.as_str()),
            ("profile_version", document.profile_version.as_str()),
            ("context_snapshot_id", document.context_snapshot_id.as_str()),
        ] {
            validate_identifier(field, value)?;
        }
        validate_hash("intent_hash", &document.intent_hash)?;
        validate_hash("agent_context_hash", &document.agent_context_hash)?;
        validate_hash("context_snapshot_hash", &document.context_snapshot_hash)?;
        validate_hash("evaluation_context_hash", &document.evaluation_context_hash)?;
        if document
            .evaluation_time
            .as_datetime()
            .timestamp_subsec_nanos()
            % 1_000_000
            != 0
        {
            return invalid("evaluation_time must use millisecond precision");
        }
        document.policy.validate()?;
        document.risk.validate()?;
        document.evidence_trust_policy.validate()?;
        document.history.validate()?;
        document.market_data.validate()?;
        document.simulation.validate()?;
        if document.evidence.len() > MAX_EVIDENCE_ITEMS {
            return invalid("Evidence snapshot exceeds 64 items");
        }
        if !document.evidence.is_empty()
            && matches!(
                document.evidence_trust_policy,
                EvidenceTrustPolicyReference::NotConfigured { .. }
            )
        {
            return invalid("Evidence requires a configured trust-policy identity");
        }
        let mut previous_hash: Option<&str> = None;
        for record in &document.evidence {
            record.envelope.verify_hash()?;
            if record.freshness_status != EvidenceFreshness::Fresh
                || record.envelope.freshness_at(document.evaluation_time)
                    != EvidenceFreshness::Fresh
            {
                return invalid("all persisted Evidence must be fresh at evaluation_time");
            }
            let hash = record.envelope.evidence_hash();
            if previous_hash.is_some_and(|previous| previous >= hash) {
                return invalid("Evidence must be sorted by unique evidence_hash");
            }
            previous_hash = Some(hash);
        }
        self.validate_size()
    }

    fn validate_size(&self) -> Result<(), EvaluationContextError> {
        if self.document_canonical_bytes().len() > MAX_CONTEXT_BYTES {
            return invalid("document exceeds 1048576 bytes");
        }
        Ok(())
    }

    fn expected_hash(&self) -> Result<String, EvaluationContextError> {
        let document = &self.document;
        domain_hash(
            CONTEXT_HASH_DOMAIN,
            &EvaluationContextHashPayload {
                evaluation_context_version: &document.evaluation_context_version,
                evaluation_id: &document.evaluation_id,
                intent_id: &document.intent_id,
                intent_hash: &document.intent_hash,
                evaluation_time: document.evaluation_time,
                environment: &document.environment,
                profile_id: &document.profile_id,
                profile_version: &document.profile_version,
                policy: &document.policy,
                risk: &document.risk,
                context_snapshot_id: &document.context_snapshot_id,
                agent_context_hash: &document.agent_context_hash,
                evidence_trust_policy: &document.evidence_trust_policy,
                evidence: &document.evidence,
                context_snapshot_hash: &document.context_snapshot_hash,
                history: &document.history,
                market_data: &document.market_data,
                simulation: &document.simulation,
            },
        )
    }
}

fn expected_snapshot_hash(
    context_snapshot_id: &str,
    agent_context_hash: &str,
    evidence_trust_policy: &EvidenceTrustPolicyReference,
    evidence: &[EvidenceSnapshotRecord],
) -> Result<String, EvaluationContextError> {
    domain_hash(
        SNAPSHOT_HASH_DOMAIN,
        &ContextSnapshotHashPayload {
            context_snapshot_id,
            agent_context_hash,
            evidence_trust_policy,
            evidence,
        },
    )
}

fn domain_hash<T: Serialize>(domain: &[u8], value: &T) -> Result<String, EvaluationContextError> {
    let canonical = sort_json_keys(serde_json::to_value(value)?);
    let canonical_bytes = serde_json::to_vec(&canonical)?;
    let mut input = Vec::with_capacity(domain.len() + canonical_bytes.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(&canonical_bytes);
    Ok(sha256_hex(&input))
}

fn validate_identifier(field: &str, value: &str) -> Result<(), EvaluationContextError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value.trim() != value
        || value.bytes().any(|byte| {
            byte.is_ascii_control()
                || !(byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
        })
    {
        return invalid(format!("{field} is not a canonical identifier"));
    }
    Ok(())
}

fn validate_hash(field: &str, value: &str) -> Result<(), EvaluationContextError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return invalid(format!("{field} must be lowercase SHA-256 hexadecimal"));
    }
    Ok(())
}

fn invalid<T>(reason: impl Into<String>) -> Result<T, EvaluationContextError> {
    Err(EvaluationContextError::Invalid(reason.into()))
}
