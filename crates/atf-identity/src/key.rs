use atf_core::Timestamp;
use ed25519_dalek::VerifyingKey;

use crate::{envelope::is_canonical_key_id, IdentityError};

/// One explicitly addressed Ed25519 identity key and its validity window.
/// Private key material is deliberately absent from this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityKeyRecord {
    pub agent_id: String,
    pub key_id: String,
    pub verifying_key: VerifyingKey,
    pub activates_at: Timestamp,
    pub expires_at: Option<Timestamp>,
    pub revoked_at: Option<Timestamp>,
}

impl IdentityKeyRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn from_public_key_bytes(
        agent_id: String,
        key_id: String,
        public_key: &[u8],
        activates_at: Timestamp,
        expires_at: Option<Timestamp>,
        revoked_at: Option<Timestamp>,
    ) -> Result<Self, IdentityError> {
        let public_key: [u8; 32] =
            public_key
                .try_into()
                .map_err(|_| IdentityError::InvalidKeyField {
                    field: "public_key",
                })?;
        let verifying_key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| IdentityError::InvalidKeyField {
                field: "public_key",
            })?;
        let record = Self {
            agent_id,
            key_id,
            verifying_key,
            activates_at,
            expires_at,
            revoked_at,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), IdentityError> {
        if !is_canonical_key_id(&self.agent_id) {
            return Err(IdentityError::InvalidKeyField { field: "agent_id" });
        }
        if !is_canonical_key_id(&self.key_id) {
            return Err(IdentityError::InvalidKeyField { field: "key_id" });
        }
        if !millisecond_aligned(self.activates_at) {
            return Err(IdentityError::InvalidKeyField {
                field: "activates_at",
            });
        }
        if let Some(expires_at) = self.expires_at {
            if !millisecond_aligned(expires_at) || expires_at <= self.activates_at {
                return Err(IdentityError::InvalidKeyField {
                    field: "expires_at",
                });
            }
        }
        if self
            .revoked_at
            .is_some_and(|value| !millisecond_aligned(value))
        {
            return Err(IdentityError::InvalidKeyField {
                field: "revoked_at",
            });
        }
        Ok(())
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn public_key_fingerprint(&self) -> String {
        atf_core::sha256_hex(&self.public_key_bytes())
    }
}

fn millisecond_aligned(timestamp: Timestamp) -> bool {
    timestamp.as_datetime().timestamp_subsec_nanos() % 1_000_000 == 0
}
