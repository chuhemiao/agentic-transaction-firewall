use std::collections::HashMap;

use atf_core::Timestamp;
use atf_intent::TransactionIntent;
use ed25519_dalek::Signature;

use crate::{
    AgentRecord, EnvelopeVerificationContext, IdentityEnvelope, IdentityError, IdentityKeyRecord,
};

/// Identity facts authenticated by one exact registered key. This proves
/// provenance only; Policy/Risk still decide whether the Intent is allowed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub organization_id: String,
    pub agent_id: String,
    pub key_id: String,
    pub nonce: String,
    pub envelope_expires_at: Timestamp,
}

/// In-memory identity-domain registry. Durable Agent/key lifecycle is DS-015;
/// Gateway verification and atomic nonce consumption are DS-016.
#[derive(Default)]
pub struct IdentityRegistry {
    agents: HashMap<String, AgentRecord>,
    keys: HashMap<(String, String), IdentityKeyRecord>,
}

impl IdentityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_agent(&mut self, record: AgentRecord) -> Result<(), IdentityError> {
        record.validate()?;
        if self.agents.contains_key(&record.agent_id) {
            return Err(IdentityError::DuplicateAgentId {
                agent_id: record.agent_id,
            });
        }
        self.agents.insert(record.agent_id.clone(), record);
        Ok(())
    }

    /// Register one explicitly addressed Agent key and its mandatory lifecycle
    /// metadata. Reusing a key ID fails; key material is never replaced.
    pub fn register_key(&mut self, record: IdentityKeyRecord) -> Result<(), IdentityError> {
        record.validate()?;
        if !self.agents.contains_key(&record.agent_id) {
            return Err(IdentityError::UnknownAgent(record.agent_id));
        }
        let address = (record.agent_id.clone(), record.key_id.clone());
        if self.keys.contains_key(&address) {
            return Err(IdentityError::DuplicateKeyId {
                agent_id: record.agent_id,
                key_id: record.key_id,
            });
        }
        self.keys.insert(address, record);
        Ok(())
    }

    pub fn agent(&self, agent_id: &str) -> Option<&AgentRecord> {
        self.agents.get(agent_id)
    }

    /// Validate and strictly verify one domain-separated envelope with only
    /// its declared `(agent_id, key_id)` public key.
    pub fn verify_envelope(
        &self,
        intent: &TransactionIntent,
        envelope: &IdentityEnvelope,
        signature_bytes: &[u8; 64],
        context: &EnvelopeVerificationContext<'_>,
    ) -> Result<VerifiedIdentity, IdentityError> {
        envelope.validate(intent, context)?;

        let record = self
            .agents
            .get(&envelope.agent_id)
            .ok_or_else(|| IdentityError::UnknownAgent(envelope.agent_id.clone()))?;
        if !record.status.may_submit_requests() {
            return Err(IdentityError::AgentNotActive {
                agent_id: envelope.agent_id.clone(),
                status: record.status,
            });
        }
        if record.organization_id != envelope.organization_id {
            return Err(IdentityError::AgentOrganizationMismatch {
                agent_id: envelope.agent_id.clone(),
            });
        }
        if record.deployment_environment != envelope.environment {
            return Err(IdentityError::AgentEnvironmentMismatch {
                agent_id: envelope.agent_id.clone(),
            });
        }
        if record.created_at > envelope.issued_at {
            return Err(IdentityError::AgentNotYetActive {
                agent_id: envelope.agent_id.clone(),
            });
        }
        if let Some(expires_at) = record.expires_at {
            if expires_at <= context.verification_time {
                return Err(IdentityError::AgentExpired {
                    agent_id: envelope.agent_id.clone(),
                });
            }
            if envelope.expires_at > expires_at {
                return Err(IdentityError::EnvelopeExceedsAgentLifetime {
                    agent_id: envelope.agent_id.clone(),
                });
            }
        }

        let address = (envelope.agent_id.clone(), envelope.key_id.clone());
        let key = self
            .keys
            .get(&address)
            .ok_or_else(|| IdentityError::UnknownKey {
                agent_id: envelope.agent_id.clone(),
                key_id: envelope.key_id.clone(),
            })?;
        if key.activates_at > envelope.issued_at {
            return Err(IdentityError::KeyNotYetActive {
                agent_id: envelope.agent_id.clone(),
                key_id: envelope.key_id.clone(),
            });
        }
        if key
            .revoked_at
            .is_some_and(|revoked_at| revoked_at <= context.verification_time)
        {
            return Err(IdentityError::KeyRevoked {
                agent_id: envelope.agent_id.clone(),
                key_id: envelope.key_id.clone(),
            });
        }
        if let Some(expires_at) = key.expires_at {
            if expires_at <= context.verification_time {
                return Err(IdentityError::KeyExpired {
                    agent_id: envelope.agent_id.clone(),
                    key_id: envelope.key_id.clone(),
                });
            }
            if envelope.expires_at > expires_at {
                return Err(IdentityError::EnvelopeExceedsKeyLifetime {
                    agent_id: envelope.agent_id.clone(),
                    key_id: envelope.key_id.clone(),
                });
            }
        }
        let signature = Signature::from_bytes(signature_bytes);
        key.verifying_key
            .verify_strict(&envelope.canonical_bytes(), &signature)
            .map_err(|_| IdentityError::InvalidSignature {
                agent_id: envelope.agent_id.clone(),
                key_id: envelope.key_id.clone(),
            })?;

        Ok(VerifiedIdentity {
            organization_id: envelope.organization_id.clone(),
            agent_id: envelope.agent_id.clone(),
            key_id: envelope.key_id.clone(),
            nonce: envelope.nonce.clone(),
            envelope_expires_at: envelope.expires_at,
        })
    }
}
