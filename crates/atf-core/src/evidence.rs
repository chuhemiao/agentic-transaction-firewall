use std::collections::{BTreeMap, BTreeSet};

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::{sha256_hex, sort_json_keys, Timestamp};

const EVIDENCE_VERSION: &str = "1";
const HASH_DOMAIN: &[u8] = b"ATF_EVIDENCE_V1\0";
const SIGNATURE_DOMAIN: &[u8] = b"ATF_EVIDENCE_SIGNATURE_V1\0";
const TRUST_POLICY_HASH_DOMAIN: &[u8] = b"ATF_EVIDENCE_TRUST_POLICY_V1\0";
const MAX_EVIDENCE_BYTES: usize = 64 * 1024;
const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_CONFIDENCE_BPS: u16 = 10_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceSource {
    AgentProvided,
    AtfEnriched,
    OracleProvided,
    AdapterProvided,
    AdminProvided,
    SignedExternalEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceKind {
    Price,
    Balance,
    Position,
    Leverage,
    CumulativeSpend,
    ProtocolRisk,
    AddressReputation,
    MarketDataFreshness,
    SimulationResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceFreshness {
    NotYetValid,
    Fresh,
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSignature {
    signature_version: String,
    algorithm: String,
    key_id: String,
    signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceEnvelope {
    evidence_version: String,
    kind: EvidenceKind,
    source: EvidenceSource,
    source_id: String,
    observed_at: Timestamp,
    expires_at: Timestamp,
    value: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence_bps: Option<u16>,
    evidence_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<EvidenceSignature>,
}

/// Deployment-owned authorization for one exact external evidence producer.
#[derive(Debug, Clone)]
pub struct TrustedEvidenceSource {
    source: EvidenceSource,
    source_id: String,
    allowed_kinds: BTreeSet<EvidenceKind>,
    require_signature: bool,
    ed25519_keys: BTreeMap<String, [u8; 32]>,
}

/// Closed allowlist used to turn untrusted envelopes into verified evidence.
#[derive(Debug, Clone, Default)]
pub struct EvidenceTrustPolicy {
    sources: BTreeMap<(EvidenceSource, String), TrustedEvidenceSource>,
}

/// Evidence whose integrity, authority, signature policy and freshness have
/// all been checked at one explicit evaluation time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedEvidence {
    envelope: EvidenceEnvelope,
    freshness_status: EvidenceFreshness,
    #[serde(skip_serializing)]
    trust_policy_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceEnvelopeDocument {
    evidence_version: String,
    kind: EvidenceKind,
    source: EvidenceSource,
    source_id: String,
    observed_at: Timestamp,
    expires_at: Timestamp,
    value: Value,
    confidence_bps: Option<u16>,
    evidence_hash: String,
    signature: Option<EvidenceSignatureDocument>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceSignatureDocument {
    signature_version: String,
    algorithm: String,
    key_id: String,
    signature: String,
}

#[derive(Serialize)]
struct EvidenceHashPayload<'a> {
    evidence_version: &'a str,
    kind: EvidenceKind,
    source: EvidenceSource,
    source_id: &'a str,
    observed_at: Timestamp,
    expires_at: Timestamp,
    value: &'a Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    confidence_bps: Option<u16>,
}

#[derive(Serialize)]
struct EvidenceTrustPolicyHashPayload<'a> {
    sources: Vec<TrustedEvidenceSourceHashPayload<'a>>,
}

#[derive(Serialize)]
struct TrustedEvidenceSourceHashPayload<'a> {
    source: EvidenceSource,
    source_id: &'a str,
    allowed_kinds: Vec<EvidenceKind>,
    require_signature: bool,
    ed25519_keys: Vec<TrustedEvidenceKeyHashPayload<'a>>,
}

#[derive(Serialize)]
struct TrustedEvidenceKeyHashPayload<'a> {
    key_id: &'a str,
    public_key: String,
}

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("evidence JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("evidence is invalid: {0}")]
    Invalid(String),
    #[error("evidence hash does not match its canonical payload")]
    HashMismatch,
    #[error("evidence source is not trusted")]
    UntrustedSource,
    #[error("evidence kind is not allowed for this source")]
    KindNotAllowed,
    #[error("evidence requires a signature")]
    MissingSignature,
    #[error("evidence signature key is not trusted")]
    UnknownSignatureKey,
    #[error("evidence signature verification failed")]
    SignatureInvalid,
    #[error("evidence is not yet valid")]
    NotYetValid,
    #[error("evidence is stale")]
    Stale,
}

impl EvidenceSignature {
    pub fn ed25519(key_id: impl Into<String>, signature: [u8; 64]) -> Result<Self, EvidenceError> {
        let value = Self {
            signature_version: "1".into(),
            algorithm: "Ed25519".into(),
            key_id: key_id.into(),
            signature: hex::encode(signature),
        };
        validate_identifier("signature.key_id", &value.key_id)?;
        Ok(value)
    }
}

impl EvidenceError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Json(_) | Self::Invalid(_) => "EVIDENCE_INVALID",
            Self::HashMismatch => "EVIDENCE_HASH_MISMATCH",
            Self::UntrustedSource => "EVIDENCE_UNTRUSTED_SOURCE",
            Self::KindNotAllowed => "EVIDENCE_KIND_NOT_ALLOWED",
            Self::MissingSignature => "EVIDENCE_SIGNATURE_MISSING",
            Self::UnknownSignatureKey => "EVIDENCE_SIGNATURE_KEY_UNKNOWN",
            Self::SignatureInvalid => "EVIDENCE_SIGNATURE_INVALID",
            Self::NotYetValid => "EVIDENCE_NOT_YET_VALID",
            Self::Stale => "EVIDENCE_STALE",
        }
    }
}

impl EvidenceEnvelope {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: EvidenceKind,
        source: EvidenceSource,
        source_id: impl Into<String>,
        observed_at: Timestamp,
        expires_at: Timestamp,
        value: Value,
        confidence_bps: Option<u16>,
    ) -> Result<Self, EvidenceError> {
        let mut envelope = Self {
            evidence_version: EVIDENCE_VERSION.into(),
            kind,
            source,
            source_id: source_id.into(),
            observed_at,
            expires_at,
            value,
            confidence_bps,
            evidence_hash: "0".repeat(64),
            signature: None,
        };
        envelope.validate_shape()?;
        envelope.evidence_hash = envelope.expected_hash()?;
        Ok(envelope)
    }

    /// Parses one untrusted evidence document and validates only its structural
    /// contract. The returned envelope is not authoritative until it has been
    /// passed through [`EvidenceTrustPolicy::verify`].
    pub fn from_json(raw: &str) -> Result<Self, EvidenceError> {
        if raw.len() > MAX_EVIDENCE_BYTES {
            return invalid("document exceeds 65536 bytes");
        }
        let value: Value = serde_json::from_str(raw)?;
        Self::from_value(value)
    }

    fn from_value(value: Value) -> Result<Self, EvidenceError> {
        let object = value
            .as_object()
            .ok_or_else(|| EvidenceError::Invalid("evidence must be an object".into()))?;
        for field in ["confidence_bps", "signature"] {
            if object.get(field).is_some_and(Value::is_null) {
                return invalid(format!("{field} must be omitted instead of null"));
            }
        }
        let document: EvidenceEnvelopeDocument = serde_json::from_value(value)?;
        let envelope = Self {
            evidence_version: document.evidence_version,
            kind: document.kind,
            source: document.source,
            source_id: document.source_id,
            observed_at: document.observed_at,
            expires_at: document.expires_at,
            value: document.value,
            confidence_bps: document.confidence_bps,
            evidence_hash: document.evidence_hash,
            signature: document.signature.map(|signature| EvidenceSignature {
                signature_version: signature.signature_version,
                algorithm: signature.algorithm,
                key_id: signature.key_id,
                signature: signature.signature,
            }),
        };
        envelope.validate_shape()?;
        Ok(envelope)
    }

    pub fn verify_hash(&self) -> Result<(), EvidenceError> {
        if self.evidence_hash != self.expected_hash()? {
            return Err(EvidenceError::HashMismatch);
        }
        Ok(())
    }

    pub fn freshness_at(&self, evaluated_at: Timestamp) -> EvidenceFreshness {
        if evaluated_at < self.observed_at {
            EvidenceFreshness::NotYetValid
        } else if evaluated_at >= self.expires_at {
            EvidenceFreshness::Stale
        } else {
            EvidenceFreshness::Fresh
        }
    }

    pub fn signature_message(&self, key_id: &str) -> Result<Vec<u8>, EvidenceError> {
        validate_identifier("signature.key_id", key_id)?;
        let hash = decode_lower_hex::<32>("evidence_hash", &self.evidence_hash)?;
        let key_id_len = u32::try_from(key_id.len())
            .map_err(|_| EvidenceError::Invalid("signature.key_id is too long".into()))?;
        let mut message =
            Vec::with_capacity(SIGNATURE_DOMAIN.len() + 4 + key_id.len() + hash.len());
        message.extend_from_slice(SIGNATURE_DOMAIN);
        message.extend_from_slice(&key_id_len.to_be_bytes());
        message.extend_from_slice(key_id.as_bytes());
        message.extend_from_slice(&hash);
        Ok(message)
    }

    pub fn with_signature(mut self, signature: EvidenceSignature) -> Result<Self, EvidenceError> {
        self.signature = Some(signature);
        self.validate_shape()?;
        Ok(self)
    }

    pub fn evidence_hash(&self) -> &str {
        &self.evidence_hash
    }

    pub fn kind(&self) -> EvidenceKind {
        self.kind
    }

    pub fn source(&self) -> EvidenceSource {
        self.source
    }

    pub fn source_id(&self) -> &str {
        &self.source_id
    }

    pub fn observed_at(&self) -> Timestamp {
        self.observed_at
    }

    pub fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn confidence_bps(&self) -> Option<u16> {
        self.confidence_bps
    }

    fn validate_shape(&self) -> Result<(), EvidenceError> {
        if self.evidence_version != EVIDENCE_VERSION {
            return invalid("unsupported evidence_version");
        }
        validate_identifier("source_id", &self.source_id)?;
        if self.observed_at >= self.expires_at {
            return invalid("expires_at must be later than observed_at");
        }
        for (name, timestamp) in [
            ("observed_at", self.observed_at),
            ("expires_at", self.expires_at),
        ] {
            if timestamp.as_datetime().timestamp_subsec_nanos() % 1_000_000 != 0 {
                return invalid(format!("{name} must use millisecond precision"));
            }
        }
        if self
            .confidence_bps
            .is_some_and(|value| value > MAX_CONFIDENCE_BPS)
        {
            return invalid("confidence_bps must be within 0..=10000");
        }
        if self.value.is_null() || contains_json_number(&self.value) {
            return invalid("value must be non-null and contain no JSON numbers");
        }
        if serde_json::to_vec(&self.value)?.len() > MAX_EVIDENCE_BYTES {
            return invalid("value exceeds 65536 bytes");
        }
        validate_lower_hex("evidence_hash", &self.evidence_hash, 64)?;
        if let Some(signature) = &self.signature {
            if signature.signature_version != "1" || signature.algorithm != "Ed25519" {
                return invalid("unsupported signature version or algorithm");
            }
            validate_identifier("signature.key_id", &signature.key_id)?;
            validate_lower_hex("signature.signature", &signature.signature, 128)?;
        }
        if serde_json::to_vec(self)?.len() > MAX_EVIDENCE_BYTES {
            return invalid("document exceeds 65536 bytes");
        }
        Ok(())
    }

    fn expected_hash(&self) -> Result<String, EvidenceError> {
        let payload = EvidenceHashPayload {
            evidence_version: &self.evidence_version,
            kind: self.kind,
            source: self.source,
            source_id: &self.source_id,
            observed_at: self.observed_at,
            expires_at: self.expires_at,
            value: &self.value,
            confidence_bps: self.confidence_bps,
        };
        let canonical = sort_json_keys(serde_json::to_value(payload)?);
        let canonical_bytes = serde_json::to_vec(&canonical)?;
        let mut input = Vec::with_capacity(HASH_DOMAIN.len() + canonical_bytes.len());
        input.extend_from_slice(HASH_DOMAIN);
        input.extend_from_slice(&canonical_bytes);
        Ok(sha256_hex(&input))
    }
}

impl TrustedEvidenceSource {
    pub fn unsigned(
        source: EvidenceSource,
        source_id: impl Into<String>,
        allowed_kinds: impl IntoIterator<Item = EvidenceKind>,
    ) -> Result<Self, EvidenceError> {
        if matches!(
            source,
            EvidenceSource::AgentProvided | EvidenceSource::SignedExternalEvidence
        ) {
            return invalid("this evidence source cannot be trusted without a signature");
        }
        Self::new(source, source_id, allowed_kinds, false, BTreeMap::new())
    }

    pub fn signed_ed25519(
        source: EvidenceSource,
        source_id: impl Into<String>,
        allowed_kinds: impl IntoIterator<Item = EvidenceKind>,
        key_id: impl Into<String>,
        public_key: [u8; 32],
    ) -> Result<Self, EvidenceError> {
        if source == EvidenceSource::AgentProvided {
            return invalid("AGENT_PROVIDED evidence can never be trusted");
        }
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| EvidenceError::Invalid("Ed25519 public key is invalid".into()))?;
        let key_id = key_id.into();
        validate_identifier("trusted key_id", &key_id)?;
        Self::new(
            source,
            source_id,
            allowed_kinds,
            true,
            BTreeMap::from([(key_id, public_key)]),
        )
    }

    fn new(
        source: EvidenceSource,
        source_id: impl Into<String>,
        allowed_kinds: impl IntoIterator<Item = EvidenceKind>,
        require_signature: bool,
        ed25519_keys: BTreeMap<String, [u8; 32]>,
    ) -> Result<Self, EvidenceError> {
        let source_id = source_id.into();
        validate_identifier("trusted source_id", &source_id)?;
        let allowed_kinds = allowed_kinds.into_iter().collect::<BTreeSet<_>>();
        if allowed_kinds.is_empty() {
            return invalid("trusted source must allow at least one evidence kind");
        }
        Ok(Self {
            source,
            source_id,
            allowed_kinds,
            require_signature,
            ed25519_keys,
        })
    }
}

impl EvidenceTrustPolicy {
    pub fn new(
        sources: impl IntoIterator<Item = TrustedEvidenceSource>,
    ) -> Result<Self, EvidenceError> {
        let mut result = BTreeMap::new();
        for source in sources {
            let key = (source.source, source.source_id.clone());
            if result.insert(key, source).is_some() {
                return invalid("duplicate trusted evidence source");
            }
        }
        Ok(Self { sources: result })
    }

    /// Domain-separated identity of every exact source/kind/signature
    /// authorization in this policy.
    pub fn policy_hash(&self) -> Result<String, EvidenceError> {
        let sources = self
            .sources
            .values()
            .map(|source| TrustedEvidenceSourceHashPayload {
                source: source.source,
                source_id: &source.source_id,
                allowed_kinds: source.allowed_kinds.iter().copied().collect(),
                require_signature: source.require_signature,
                ed25519_keys: source
                    .ed25519_keys
                    .iter()
                    .map(|(key_id, public_key)| TrustedEvidenceKeyHashPayload {
                        key_id,
                        public_key: hex::encode(public_key),
                    })
                    .collect(),
            })
            .collect();
        let canonical = sort_json_keys(serde_json::to_value(EvidenceTrustPolicyHashPayload {
            sources,
        })?);
        let canonical_bytes = serde_json::to_vec(&canonical)?;
        let mut input = Vec::with_capacity(TRUST_POLICY_HASH_DOMAIN.len() + canonical_bytes.len());
        input.extend_from_slice(TRUST_POLICY_HASH_DOMAIN);
        input.extend_from_slice(&canonical_bytes);
        Ok(sha256_hex(&input))
    }

    pub fn verify(
        &self,
        evidence: &EvidenceEnvelope,
        evaluated_at: Timestamp,
    ) -> Result<VerifiedEvidence, EvidenceError> {
        evidence.verify_hash()?;
        let trusted = self
            .sources
            .get(&(evidence.source, evidence.source_id.clone()))
            .ok_or(EvidenceError::UntrustedSource)?;
        if !trusted.allowed_kinds.contains(&evidence.kind) {
            return Err(EvidenceError::KindNotAllowed);
        }
        match &evidence.signature {
            None if trusted.require_signature => return Err(EvidenceError::MissingSignature),
            None => {}
            Some(proof) => {
                let public_key = trusted
                    .ed25519_keys
                    .get(&proof.key_id)
                    .ok_or(EvidenceError::UnknownSignatureKey)?;
                let key = VerifyingKey::from_bytes(public_key)
                    .map_err(|_| EvidenceError::SignatureInvalid)?;
                let signature = decode_lower_hex::<64>("signature.signature", &proof.signature)?;
                key.verify_strict(
                    &evidence.signature_message(&proof.key_id)?,
                    &Signature::from_bytes(&signature),
                )
                .map_err(|_| EvidenceError::SignatureInvalid)?;
            }
        }
        let freshness_status = evidence.freshness_at(evaluated_at);
        match freshness_status {
            EvidenceFreshness::NotYetValid => return Err(EvidenceError::NotYetValid),
            EvidenceFreshness::Stale => return Err(EvidenceError::Stale),
            EvidenceFreshness::Fresh => {}
        }
        Ok(VerifiedEvidence {
            envelope: evidence.clone(),
            freshness_status,
            trust_policy_hash: self.policy_hash()?,
        })
    }
}

impl VerifiedEvidence {
    pub fn envelope(&self) -> &EvidenceEnvelope {
        &self.envelope
    }

    pub fn kind(&self) -> EvidenceKind {
        self.envelope.kind()
    }

    pub fn source(&self) -> EvidenceSource {
        self.envelope.source()
    }

    pub fn source_id(&self) -> &str {
        self.envelope.source_id()
    }

    pub fn evidence_hash(&self) -> &str {
        self.envelope.evidence_hash()
    }

    pub fn value(&self) -> &Value {
        self.envelope.value()
    }

    pub fn observed_at(&self) -> Timestamp {
        self.envelope.observed_at()
    }

    pub fn expires_at(&self) -> Timestamp {
        self.envelope.expires_at()
    }

    pub fn confidence_bps(&self) -> Option<u16> {
        self.envelope.confidence_bps()
    }

    pub fn freshness_status(&self) -> EvidenceFreshness {
        self.freshness_status
    }

    pub fn trust_policy_hash(&self) -> &str {
        &self.trust_policy_hash
    }
}

impl<'de> Deserialize<'de> for EvidenceEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        Self::from_value(value).map_err(D::Error::custom)
    }
}

fn validate_identifier(field: &str, value: &str) -> Result<(), EvidenceError> {
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

fn validate_lower_hex(field: &str, value: &str, expected_len: usize) -> Result<(), EvidenceError> {
    if value.len() != expected_len
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return invalid(format!("{field} must be lowercase hexadecimal"));
    }
    Ok(())
}

fn decode_lower_hex<const N: usize>(field: &str, value: &str) -> Result<[u8; N], EvidenceError> {
    validate_lower_hex(field, value, N * 2)?;
    let mut decoded = [0_u8; N];
    hex::decode_to_slice(value, &mut decoded)
        .map_err(|_| EvidenceError::Invalid(format!("{field} is invalid hexadecimal")))?;
    Ok(decoded)
}

fn contains_json_number(value: &Value) -> bool {
    match value {
        Value::Number(_) => true,
        Value::Array(values) => values.iter().any(contains_json_number),
        Value::Object(values) => values.values().any(contains_json_number),
        _ => false,
    }
}

fn invalid<T>(reason: impl Into<String>) -> Result<T, EvidenceError> {
    Err(EvidenceError::Invalid(reason.into()))
}
