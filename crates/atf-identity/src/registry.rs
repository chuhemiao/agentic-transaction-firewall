use std::collections::HashMap;

use atf_intent::TransactionIntent;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::error::IdentityError;
use crate::record::AgentRecord;

/// In-memory Agent identity registry (PRD §17). Persistence is a Phase 2
/// concern (`atf-audit`/a real store behind `atf-gateway`) — this type is
/// the domain logic a persistent implementation would wrap.
#[derive(Default)]
pub struct IdentityRegistry {
    agents: HashMap<String, AgentRecord>,
    /// Multiple keys per agent support a rotation window (PRD §17.2.4):
    /// both the old and new key verify successfully during the overlap
    /// period, and nothing here ever removes a key on its own — that's an
    /// explicit `revoke_key` operation, not implemented yet since there is
    /// no admin API to drive it (PRD §17.3).
    keys: HashMap<String, Vec<VerifyingKey>>,
}

impl IdentityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_agent(&mut self, record: AgentRecord) {
        self.agents.insert(record.agent_id.clone(), record);
    }

    pub fn register_key(&mut self, agent_id: &str, key: VerifyingKey) {
        self.keys.entry(agent_id.to_string()).or_default().push(key);
    }

    pub fn agent(&self, agent_id: &str) -> Option<&AgentRecord> {
        self.agents.get(agent_id)
    }

    /// Verify that `signature_bytes` (a raw 64-byte Ed25519 signature) over
    /// `intent.canonical_hash()` was produced by one of
    /// `intent.principal.agent_id`'s currently-registered keys, and that the
    /// Agent's status allows it to submit requests at all (PRD §17.2.2-3,
    /// §17.2.5). This only proves "this request came from this Agent" — it
    /// says nothing about whether the request itself should be permitted;
    /// that is still Policy's and Risk's job.
    pub fn verify_intent_signature(
        &self,
        intent: &TransactionIntent,
        signature_bytes: &[u8; 64],
    ) -> Result<(), IdentityError> {
        let agent_id = &intent.principal.agent_id;

        let record = self
            .agents
            .get(agent_id)
            .ok_or_else(|| IdentityError::UnknownAgent(agent_id.clone()))?;

        if !record.status.may_submit_requests() {
            return Err(IdentityError::AgentNotActive {
                agent_id: agent_id.clone(),
                status: record.status,
            });
        }

        let keys = self
            .keys
            .get(agent_id)
            .filter(|keys| !keys.is_empty())
            .ok_or_else(|| IdentityError::NoRegisteredKey(agent_id.clone()))?;

        let message = intent.canonical_hash();
        let signature = Signature::from_bytes(signature_bytes);

        let verified = keys
            .iter()
            .any(|key| key.verify(message.as_bytes(), &signature).is_ok());

        if verified {
            Ok(())
        } else {
            Err(IdentityError::InvalidSignature(agent_id.clone()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::record::AgentStatus;
    use atf_core::{Amount, Timestamp};
    use atf_intent::{Action, Mandate, Principal, Resource, Transaction};
    use ed25519_dalek::{Signer, SigningKey};
    use std::str::FromStr;

    fn signing_key(seed_byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed_byte; 32])
    }

    fn sample_intent(agent_id: &str) -> TransactionIntent {
        TransactionIntent {
            spec_version: "1.0".into(),
            intent_id: "01J00000000000000000000000".into(),
            idempotency_key: "idem-1".into(),
            created_at: Timestamp::from_str("2026-07-18T08:00:00Z").unwrap(),
            expires_at: Timestamp::from_str("2099-01-01T00:00:00Z").unwrap(),
            principal: Principal {
                organization_id: "alpha-lab".into(),
                user_id: None,
                agent_id: agent_id.to_string(),
                agent_version: None,
                strategy_id: None,
            },
            mandate: Mandate {
                mandate_id: "mandate-001".into(),
                task_id: None,
                purpose: "test".into(),
                budget_id: None,
                human_authorized: true,
            },
            action: Action {
                category: "payment".into(),
                operation: "purchase_api_resource".into(),
            },
            resource: Resource {
                protocol: "x402".into(),
                venue: None,
                resource_id: "btc-orderbook-2026-07-01".into(),
                resource_type: None,
            },
            transaction: Transaction {
                network: "base".into(),
                asset: "eip155:8453/erc20:0x0".into(),
                amount: Amount::from_str("12.50").unwrap(),
                destination: None,
                contract: None,
                calldata_hash: None,
                max_fee: None,
                slippage_bps: None,
                leverage: None,
            },
            context: serde_json::json!({}),
            metadata: serde_json::json!({}),
        }
    }

    fn sample_record(agent_id: &str, status: AgentStatus) -> AgentRecord {
        AgentRecord {
            agent_id: agent_id.to_string(),
            organization_id: "alpha-lab".to_string(),
            owner_user_id: "user-001".to_string(),
            agent_type: "trading".to_string(),
            model_provider: "anthropic".to_string(),
            model_name: "claude".to_string(),
            agent_version: "1.4.2".to_string(),
            code_hash: "deadbeef".to_string(),
            deployment_environment: "production".to_string(),
            allowed_tools: vec![],
            allowed_adapters: vec![],
            default_budget: None,
            risk_tier: "standard".to_string(),
            status,
            created_at: Timestamp::now(),
            expires_at: None,
        }
    }

    fn sign(key: &SigningKey, intent: &TransactionIntent) -> [u8; 64] {
        key.sign(intent.canonical_hash().as_bytes()).to_bytes()
    }

    #[test]
    fn verifies_a_correctly_signed_intent() {
        let mut registry = IdentityRegistry::new();
        let key = signing_key(1);
        registry.register_agent(sample_record("agent-1", AgentStatus::Active));
        registry.register_key("agent-1", key.verifying_key());

        let intent = sample_intent("agent-1");
        let signature = sign(&key, &intent);

        assert!(registry
            .verify_intent_signature(&intent, &signature)
            .is_ok());
    }

    #[test]
    fn rejects_a_tampered_intent() {
        let mut registry = IdentityRegistry::new();
        let key = signing_key(1);
        registry.register_agent(sample_record("agent-1", AgentStatus::Active));
        registry.register_key("agent-1", key.verifying_key());

        let intent = sample_intent("agent-1");
        let signature = sign(&key, &intent);

        let mut tampered = intent.clone();
        tampered.transaction.amount = Amount::from_str("999.00").unwrap();

        assert_eq!(
            registry.verify_intent_signature(&tampered, &signature),
            Err(IdentityError::InvalidSignature("agent-1".to_string()))
        );
    }

    #[test]
    fn rejects_a_signature_from_an_unregistered_key() {
        let mut registry = IdentityRegistry::new();
        let registered_key = signing_key(1);
        let attacker_key = signing_key(2);
        registry.register_agent(sample_record("agent-1", AgentStatus::Active));
        registry.register_key("agent-1", registered_key.verifying_key());

        let intent = sample_intent("agent-1");
        let signature = sign(&attacker_key, &intent);

        assert_eq!(
            registry.verify_intent_signature(&intent, &signature),
            Err(IdentityError::InvalidSignature("agent-1".to_string()))
        );
    }

    #[test]
    fn rejects_an_unknown_agent() {
        let registry = IdentityRegistry::new();
        let key = signing_key(1);
        let intent = sample_intent("ghost-agent");
        let signature = sign(&key, &intent);

        assert_eq!(
            registry.verify_intent_signature(&intent, &signature),
            Err(IdentityError::UnknownAgent("ghost-agent".to_string()))
        );
    }

    #[test]
    fn rejects_a_paused_agent_even_with_a_valid_signature() {
        let mut registry = IdentityRegistry::new();
        let key = signing_key(1);
        registry.register_agent(sample_record("agent-1", AgentStatus::Paused));
        registry.register_key("agent-1", key.verifying_key());

        let intent = sample_intent("agent-1");
        let signature = sign(&key, &intent);

        assert_eq!(
            registry.verify_intent_signature(&intent, &signature),
            Err(IdentityError::AgentNotActive {
                agent_id: "agent-1".to_string(),
                status: AgentStatus::Paused,
            })
        );
    }

    #[test]
    fn shadow_only_agents_may_still_submit_for_verification() {
        let mut registry = IdentityRegistry::new();
        let key = signing_key(1);
        registry.register_agent(sample_record("agent-1", AgentStatus::ShadowOnly));
        registry.register_key("agent-1", key.verifying_key());

        let intent = sample_intent("agent-1");
        let signature = sign(&key, &intent);

        assert!(registry
            .verify_intent_signature(&intent, &signature)
            .is_ok());
    }

    #[test]
    fn a_rotated_second_key_verifies_alongside_the_first() {
        let mut registry = IdentityRegistry::new();
        let old_key = signing_key(1);
        let new_key = signing_key(2);
        registry.register_agent(sample_record("agent-1", AgentStatus::Active));
        registry.register_key("agent-1", old_key.verifying_key());
        registry.register_key("agent-1", new_key.verifying_key());

        let intent = sample_intent("agent-1");

        assert!(registry
            .verify_intent_signature(&intent, &sign(&old_key, &intent))
            .is_ok());
        assert!(registry
            .verify_intent_signature(&intent, &sign(&new_key, &intent))
            .is_ok());
    }

    #[test]
    fn rejects_when_no_key_is_registered_at_all() {
        let mut registry = IdentityRegistry::new();
        let key = signing_key(1);
        registry.register_agent(sample_record("agent-1", AgentStatus::Active));

        let intent = sample_intent("agent-1");
        let signature = sign(&key, &intent);

        assert_eq!(
            registry.verify_intent_signature(&intent, &signature),
            Err(IdentityError::NoRegisteredKey("agent-1".to_string()))
        );
    }
}
