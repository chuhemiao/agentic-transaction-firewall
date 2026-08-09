use sha3::{Digest, Keccak256};

use crate::{
    validate_profile, TransactionIntent, AGENT_COMMERCE_PAYMENT_PROFILE_ID,
    AGENT_COMMERCE_PAYMENT_PROFILE_VERSION,
};

pub const PAYMENT_DESTINATION_NORMALIZER_ID: &str = "atf.agent-commerce.payment.destination.eip155";
pub const PAYMENT_DESTINATION_NORMALIZER_VERSION: &str = "1";

/// A destination key derived for history comparison without changing the
/// canonical Intent bytes that the caller signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileNormalizedDestination {
    value: String,
}

impl ProfileNormalizedDestination {
    pub fn profile_id(&self) -> &'static str {
        AGENT_COMMERCE_PAYMENT_PROFILE_ID
    }

    pub fn profile_version(&self) -> &'static str {
        AGENT_COMMERCE_PAYMENT_PROFILE_VERSION
    }

    pub fn normalizer_id(&self) -> &'static str {
        PAYMENT_DESTINATION_NORMALIZER_ID
    }

    pub fn normalizer_version(&self) -> &'static str {
        PAYMENT_DESTINATION_NORMALIZER_VERSION
    }

    pub fn value(&self) -> &str {
        &self.value
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DestinationNormalizationError {
    #[error("destination profile is not supported by this normalizer")]
    ProfileUnsupported,
    #[error("destination namespace is not supported by this normalizer")]
    NamespaceUnsupported,
    #[error("destination cannot be normalized safely")]
    Invalid,
}

impl DestinationNormalizationError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::ProfileUnsupported => "DESTINATION_NORMALIZATION_PROFILE_UNSUPPORTED",
            Self::NamespaceUnsupported => "DESTINATION_NORMALIZATION_NAMESPACE_UNSUPPORTED",
            Self::Invalid => "DESTINATION_NORMALIZATION_INVALID",
        }
    }
}

/// Derive the Payment Profile's versioned EIP-155 history key.
///
/// CAIP-10 is case-sensitive and delegates canonicalization to namespace
/// profiles, so ATF never rewrites the signed Intent. The EIP-155 namespace
/// accepts legacy lowercase or checksum-case addresses; EIP-55 defines the
/// checksum over lowercase ASCII hexadecimal bytes.
///
/// Sources:
/// - https://standards.chainagnostic.org/CAIPs/caip-10#canonicalization
/// - https://namespaces.chainagnostic.org/eip155/caip10#syntax
/// - https://eips.ethereum.org/EIPS/eip-55#specification
pub fn normalize_destination(
    intent: &TransactionIntent,
) -> Result<ProfileNormalizedDestination, DestinationNormalizationError> {
    let profile =
        validate_profile(intent).map_err(|_| DestinationNormalizationError::ProfileUnsupported)?;
    if profile.id() != AGENT_COMMERCE_PAYMENT_PROFILE_ID
        || profile.version() != AGENT_COMMERCE_PAYMENT_PROFILE_VERSION
    {
        return Err(DestinationNormalizationError::ProfileUnsupported);
    }
    let destination = intent
        .transaction
        .destination
        .as_deref()
        .ok_or(DestinationNormalizationError::Invalid)?;
    normalize_destination_value(profile.id(), profile.version(), destination)
}

/// Normalize a destination from already verified Profile-bound durable
/// evidence. Store uses this to recheck a prior Decision row selected by the
/// destination-history index.
pub fn normalize_destination_value(
    profile_id: &str,
    profile_version: &str,
    destination: &str,
) -> Result<ProfileNormalizedDestination, DestinationNormalizationError> {
    if profile_id != AGENT_COMMERCE_PAYMENT_PROFILE_ID
        || profile_version != AGENT_COMMERCE_PAYMENT_PROFILE_VERSION
    {
        return Err(DestinationNormalizationError::ProfileUnsupported);
    }
    let mut segments = destination.split(':');
    let namespace = segments
        .next()
        .ok_or(DestinationNormalizationError::Invalid)?;
    let chain_reference = segments
        .next()
        .ok_or(DestinationNormalizationError::Invalid)?;
    let address = segments
        .next()
        .ok_or(DestinationNormalizationError::Invalid)?;
    if segments.next().is_some() {
        return Err(DestinationNormalizationError::Invalid);
    }
    if namespace != "eip155" {
        return Err(DestinationNormalizationError::NamespaceUnsupported);
    }
    if chain_reference.is_empty()
        || !chain_reference.bytes().all(|byte| byte.is_ascii_digit())
        || (chain_reference.len() > 1 && chain_reference.starts_with('0'))
    {
        return Err(DestinationNormalizationError::Invalid);
    }
    let hexadecimal = address
        .strip_prefix("0x")
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .ok_or(DestinationNormalizationError::Invalid)?;
    let lowercase = hexadecimal.to_ascii_lowercase();
    if hexadecimal.bytes().any(|byte| byte.is_ascii_uppercase())
        && checksum_address(&lowercase) != address
    {
        return Err(DestinationNormalizationError::Invalid);
    }
    Ok(ProfileNormalizedDestination {
        value: format!("eip155:{chain_reference}:0x{lowercase}"),
    })
}

fn checksum_address(lowercase: &str) -> String {
    debug_assert_eq!(lowercase.len(), 40);
    let digest = Keccak256::digest(lowercase.as_bytes());
    let mut checksum = String::with_capacity(42);
    checksum.push_str("0x");
    for (index, character) in lowercase.bytes().enumerate() {
        if character.is_ascii_digit() {
            checksum.push(char::from(character));
            continue;
        }
        let hash_nibble = if index % 2 == 0 {
            digest[index / 2] >> 4
        } else {
            digest[index / 2] & 0x0f
        };
        checksum.push(char::from(if hash_nibble >= 8 {
            character.to_ascii_uppercase()
        } else {
            character
        }));
    }
    checksum
}
