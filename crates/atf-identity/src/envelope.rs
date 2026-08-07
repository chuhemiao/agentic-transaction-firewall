use atf_core::Timestamp;
use atf_intent::TransactionIntent;
use serde::{Deserialize, Serialize};

use crate::IdentityError;

pub const IDENTITY_ENVELOPE_DOMAIN: &str = "ATF_INTENT_V1";
const MAX_ENVELOPE_LIFETIME_NANOS: i64 = 5 * 60 * 1_000_000_000;
const MAX_IDENTIFIER_BYTES: usize = 128;
const MIN_NONCE_BYTES: usize = 16;

/// Trusted request context supplied by the verifier. Keeping time explicit
/// makes identity verification deterministic and replay-testable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeVerificationContext<'a> {
    pub audience: &'a str,
    pub environment: &'a str,
    pub verification_time: Timestamp,
}

/// Version-1 Agent identity assertion signed before an Intent enters the
/// durable Gateway pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityEnvelope {
    pub domain: String,
    pub organization_id: String,
    pub agent_id: String,
    pub key_id: String,
    pub intent_hash: String,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub nonce: String,
    pub audience: String,
    pub environment: String,
}

impl IdentityEnvelope {
    /// Compact UTF-8 JSON with recursively sorted keys. These are the exact
    /// bytes SDKs sign and verifiers authenticate.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let value = serde_json::to_value(self).expect("IdentityEnvelope always serializes to JSON");
        serde_json::to_vec(&atf_core::sort_json_keys(value))
            .expect("canonical IdentityEnvelope always serializes")
    }

    /// Validate the envelope's canonical field encodings, bounded lifetime,
    /// Intent binding and trusted deployment context before key lookup.
    pub fn validate(
        &self,
        intent: &TransactionIntent,
        context: &EnvelopeVerificationContext<'_>,
    ) -> Result<(), IdentityError> {
        if self.domain != IDENTITY_ENVELOPE_DOMAIN {
            return Err(IdentityError::DomainMismatch);
        }
        for (field, value) in [
            ("organization_id", self.organization_id.as_str()),
            ("agent_id", self.agent_id.as_str()),
            ("key_id", self.key_id.as_str()),
            ("audience", self.audience.as_str()),
            ("environment", self.environment.as_str()),
        ] {
            if !is_canonical_identifier(value, 1) {
                return Err(IdentityError::InvalidEnvelopeField { field });
            }
        }
        if !is_canonical_identifier(&self.nonce, MIN_NONCE_BYTES) {
            return Err(IdentityError::InvalidEnvelopeField { field: "nonce" });
        }
        if self.intent_hash.len() != 64
            || !self
                .intent_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(IdentityError::InvalidEnvelopeField {
                field: "intent_hash",
            });
        }
        for (field, timestamp) in [
            ("issued_at", self.issued_at),
            ("expires_at", self.expires_at),
        ] {
            if timestamp.as_datetime().timestamp_subsec_nanos() % 1_000_000 != 0 {
                return Err(IdentityError::InvalidEnvelopeField { field });
            }
        }

        if self.issued_at >= self.expires_at {
            return Err(IdentityError::EnvelopeTimeRangeInvalid);
        }
        let lifetime_nanos = self
            .expires_at
            .as_datetime()
            .signed_duration_since(self.issued_at.as_datetime())
            .num_nanoseconds()
            .ok_or(IdentityError::EnvelopeLifetimeExceeded)?;
        if lifetime_nanos > MAX_ENVELOPE_LIFETIME_NANOS {
            return Err(IdentityError::EnvelopeLifetimeExceeded);
        }
        if self.issued_at > context.verification_time {
            return Err(IdentityError::EnvelopeNotYetValid);
        }
        if self.expires_at <= context.verification_time {
            return Err(IdentityError::EnvelopeExpired);
        }
        if self.issued_at < intent.created_at || self.expires_at > intent.expires_at {
            return Err(IdentityError::EnvelopeOutsideIntentLifetime);
        }

        if self.organization_id != intent.principal.organization_id {
            return Err(IdentityError::OrganizationMismatch);
        }
        if self.agent_id != intent.principal.agent_id {
            return Err(IdentityError::AgentMismatch);
        }
        if self.intent_hash != intent.canonical_hash() {
            return Err(IdentityError::IntentHashMismatch);
        }
        if self.audience != context.audience {
            return Err(IdentityError::AudienceMismatch);
        }
        if self.environment != context.environment {
            return Err(IdentityError::EnvironmentMismatch);
        }
        Ok(())
    }
}

pub(crate) fn is_canonical_identifier(value: &str, minimum_bytes: usize) -> bool {
    (minimum_bytes..=MAX_IDENTIFIER_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

pub(crate) fn is_canonical_key_id(value: &str) -> bool {
    is_canonical_identifier(value, 1)
}
