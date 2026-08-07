use atf_identity::IdentityEnvelope;
use axum::http::{HeaderMap, HeaderName, HeaderValue};
use std::fmt;

pub(crate) const IDENTITY_ENVELOPE_HEADER: HeaderName =
    HeaderName::from_static("x-atf-identity-envelope");
pub(crate) const IDENTITY_SIGNATURE_HEADER: HeaderName =
    HeaderName::from_static("x-atf-identity-signature");

const MAX_ENVELOPE_HEADER_BYTES: usize = 4_096;
const SIGNATURE_HEX_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityGatewayConfig {
    audience: String,
    environment: String,
}

impl IdentityGatewayConfig {
    pub fn new(
        audience: impl Into<String>,
        environment: impl Into<String>,
    ) -> Result<Self, IdentityGatewayConfigError> {
        let audience = audience.into();
        let environment = environment.into();
        if !is_canonical_identifier(&audience) {
            return Err(IdentityGatewayConfigError { field: "audience" });
        }
        if !is_canonical_identifier(&environment) {
            return Err(IdentityGatewayConfigError {
                field: "environment",
            });
        }
        Ok(Self {
            audience,
            environment,
        })
    }

    pub fn audience(&self) -> &str {
        &self.audience
    }

    pub fn environment(&self) -> &str {
        &self.environment
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdentityGatewayConfigError {
    field: &'static str,
}

impl fmt::Display for IdentityGatewayConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "identity Gateway {} must be 1..128 canonical ASCII bytes",
            self.field
        )
    }
}

impl std::error::Error for IdentityGatewayConfigError {}

#[derive(Debug)]
pub(crate) struct IdentityAssertion {
    pub envelope: IdentityEnvelope,
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IdentityHeaderError {
    Required,
    Duplicate,
    EnvelopeInvalid,
    SignatureInvalid,
}

impl IdentityHeaderError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Required => "IDENTITY_HEADERS_REQUIRED",
            Self::Duplicate => "IDENTITY_HEADERS_DUPLICATE",
            Self::EnvelopeInvalid => "IDENTITY_ENVELOPE_HEADER_INVALID",
            Self::SignatureInvalid => "IDENTITY_SIGNATURE_HEADER_INVALID",
        }
    }
}

pub(crate) fn parse_identity_assertion(
    headers: &HeaderMap,
) -> Result<IdentityAssertion, IdentityHeaderError> {
    let envelope_header = exactly_one(headers, &IDENTITY_ENVELOPE_HEADER)?;
    let signature_header = exactly_one(headers, &IDENTITY_SIGNATURE_HEADER)?;

    let encoded_envelope = envelope_header.as_bytes();
    if encoded_envelope.is_empty()
        || encoded_envelope.len() > MAX_ENVELOPE_HEADER_BYTES
        || encoded_envelope.len() % 2 != 0
        || !is_lowercase_hex(encoded_envelope)
    {
        return Err(IdentityHeaderError::EnvelopeInvalid);
    }
    let envelope_bytes =
        hex::decode(encoded_envelope).map_err(|_| IdentityHeaderError::EnvelopeInvalid)?;
    let envelope: IdentityEnvelope = serde_json::from_slice(&envelope_bytes)
        .map_err(|_| IdentityHeaderError::EnvelopeInvalid)?;
    if envelope.canonical_bytes() != envelope_bytes {
        return Err(IdentityHeaderError::EnvelopeInvalid);
    }

    let encoded_signature = signature_header.as_bytes();
    if encoded_signature.len() != SIGNATURE_HEX_BYTES || !is_lowercase_hex(encoded_signature) {
        return Err(IdentityHeaderError::SignatureInvalid);
    }
    let signature = hex::decode(encoded_signature)
        .map_err(|_| IdentityHeaderError::SignatureInvalid)?
        .try_into()
        .map_err(|_| IdentityHeaderError::SignatureInvalid)?;

    Ok(IdentityAssertion {
        envelope,
        signature,
    })
}

fn exactly_one<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<&'a HeaderValue, IdentityHeaderError> {
    let mut values = headers.get_all(name).iter();
    let first = values.next().ok_or(IdentityHeaderError::Required)?;
    if values.next().is_some() {
        return Err(IdentityHeaderError::Duplicate);
    }
    Ok(first)
}

fn is_lowercase_hex(value: &[u8]) -> bool {
    value
        .iter()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn is_canonical_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use atf_core::Timestamp;

    fn envelope() -> IdentityEnvelope {
        IdentityEnvelope {
            domain: "ATF_INTENT_V1".into(),
            organization_id: "alpha-lab".into(),
            agent_id: "agent-1".into(),
            key_id: "key-1".into(),
            intent_hash: "a".repeat(64),
            issued_at: timestamp("2026-08-08T01:00:00.000Z"),
            expires_at: timestamp("2026-08-08T01:05:00.000Z"),
            nonce: "nonce-0123456789abcdef".into(),
            audience: "atf-gateway".into(),
            environment: "test".into(),
        }
    }

    #[test]
    fn accepts_exact_canonical_hex_headers() {
        let envelope = envelope();
        let mut headers = HeaderMap::new();
        headers.insert(
            IDENTITY_ENVELOPE_HEADER,
            hex::encode(envelope.canonical_bytes()).parse().unwrap(),
        );
        headers.insert(IDENTITY_SIGNATURE_HEADER, "00".repeat(64).parse().unwrap());

        let parsed = parse_identity_assertion(&headers).unwrap();
        assert_eq!(parsed.envelope, envelope);
        assert_eq!(parsed.signature, [0; 64]);
    }

    #[test]
    fn rejects_missing_duplicate_noncanonical_and_invalid_signature_headers() {
        let envelope = envelope();
        let canonical_hex = hex::encode(envelope.canonical_bytes());

        assert_eq!(
            parse_identity_assertion(&HeaderMap::new()).unwrap_err(),
            IdentityHeaderError::Required
        );

        let mut duplicate = HeaderMap::new();
        duplicate.append(
            IDENTITY_ENVELOPE_HEADER.clone(),
            canonical_hex.parse().unwrap(),
        );
        duplicate.append(IDENTITY_ENVELOPE_HEADER, canonical_hex.parse().unwrap());
        duplicate.insert(IDENTITY_SIGNATURE_HEADER, "00".repeat(64).parse().unwrap());
        assert_eq!(
            parse_identity_assertion(&duplicate).unwrap_err(),
            IdentityHeaderError::Duplicate
        );

        let noncanonical = serde_json::to_vec_pretty(&envelope).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            IDENTITY_ENVELOPE_HEADER.clone(),
            hex::encode(noncanonical).parse().unwrap(),
        );
        headers.insert(
            IDENTITY_SIGNATURE_HEADER.clone(),
            "00".repeat(64).parse().unwrap(),
        );
        assert_eq!(
            parse_identity_assertion(&headers).unwrap_err(),
            IdentityHeaderError::EnvelopeInvalid
        );

        headers.insert(IDENTITY_ENVELOPE_HEADER, canonical_hex.parse().unwrap());
        headers.insert(IDENTITY_SIGNATURE_HEADER, "AA".repeat(64).parse().unwrap());
        assert_eq!(
            parse_identity_assertion(&headers).unwrap_err(),
            IdentityHeaderError::SignatureInvalid
        );
    }

    #[test]
    fn rejects_odd_oversized_unknown_field_and_wrong_length_headers() {
        let envelope = envelope();
        let mut headers = HeaderMap::new();
        headers.insert(IDENTITY_ENVELOPE_HEADER, "a".parse().unwrap());
        headers.insert(
            IDENTITY_SIGNATURE_HEADER.clone(),
            "00".repeat(64).parse().unwrap(),
        );
        assert_eq!(
            parse_identity_assertion(&headers).unwrap_err(),
            IdentityHeaderError::EnvelopeInvalid
        );

        headers.insert(
            IDENTITY_ENVELOPE_HEADER.clone(),
            "a".repeat(MAX_ENVELOPE_HEADER_BYTES + 2).parse().unwrap(),
        );
        assert_eq!(
            parse_identity_assertion(&headers).unwrap_err(),
            IdentityHeaderError::EnvelopeInvalid
        );

        let mut unknown = serde_json::to_value(&envelope).unwrap();
        unknown["private_hint"] = serde_json::json!("must not be accepted");
        let unknown = serde_json::to_vec(&atf_core::sort_json_keys(unknown)).unwrap();
        headers.insert(
            IDENTITY_ENVELOPE_HEADER.clone(),
            hex::encode(unknown).parse().unwrap(),
        );
        assert_eq!(
            parse_identity_assertion(&headers).unwrap_err(),
            IdentityHeaderError::EnvelopeInvalid
        );

        headers.insert(
            IDENTITY_ENVELOPE_HEADER,
            hex::encode(envelope.canonical_bytes()).parse().unwrap(),
        );
        headers.insert(IDENTITY_SIGNATURE_HEADER, "00".repeat(63).parse().unwrap());
        assert_eq!(
            parse_identity_assertion(&headers).unwrap_err(),
            IdentityHeaderError::SignatureInvalid
        );
    }

    #[test]
    fn trusted_identity_context_rejects_empty_whitespace_and_oversized_values() {
        for (audience, environment) in [
            ("", "test"),
            ("atf gateway", "test"),
            ("atf-gateway", ""),
            ("atf-gateway", "x y"),
        ] {
            assert!(IdentityGatewayConfig::new(audience, environment).is_err());
        }
        assert!(IdentityGatewayConfig::new("a".repeat(129), "test").is_err());
    }

    fn timestamp(value: &str) -> Timestamp {
        value.parse().unwrap()
    }
}
