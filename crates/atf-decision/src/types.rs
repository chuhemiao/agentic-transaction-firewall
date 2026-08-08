use atf_core::{
    sha256_hex, sort_json_keys, DecisionObligation, EvaluationContext, ExecutionConstraints,
    ProfileBinding, RequiredApproval, SimulationReference, Timestamp, VersionedArtifactReference,
};
use atf_intent::TransactionIntent;
use serde::{Deserialize, Serialize};

use crate::DecisionError;

const DECISION_VERSION: &str = "1";
const DECISION_HASH_DOMAIN: &[u8] = b"ATF_DECISION_V1\0";

/// PRD §10.2. `Review` is produced when the Risk Engine returns a `High`
/// finding; the future Simulator branch can also produce it.
pub use atf_core::DecisionKind;

/// A single contributing reason for a Decision (PRD §10 `reasons`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Reason {
    pub code: String,
    pub severity: String,
    pub message: String,
}

fn constraints_for_intent(intent: &TransactionIntent) -> ExecutionConstraints {
    ExecutionConstraints {
        action_category: intent.action.category.clone(),
        action_operation: intent.action.operation.clone(),
        resource_id: intent.resource.resource_id.clone(),
        resource_protocol: intent.resource.protocol.clone(),
        network: intent.transaction.network.clone(),
        asset: intent.transaction.asset.clone(),
        max_amount: intent.transaction.amount,
        destination: intent.transaction.destination.clone(),
        adapter_id: None,
    }
}

/// Version-1 strongly bound Decision envelope.
///
/// `decision_hash` is SHA-256 over the domain-separated canonical form of
/// every field except `decision_hash` itself. The full persisted/API document
/// remains canonical JSON including the resulting hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub decision_version: String,
    pub decision_id: String,
    pub intent_id: String,
    pub intent_hash: String,
    pub evaluation_id: String,
    pub profile: ProfileBinding,
    pub policy: VersionedArtifactReference,
    pub risk: VersionedArtifactReference,
    pub evaluation_context_hash: String,
    pub context_snapshot_hash: String,
    pub simulation: SimulationReference,
    pub evaluation_time: Timestamp,
    pub expires_at: Timestamp,
    pub decision: DecisionKind,
    pub reasons: Vec<Reason>,
    pub required_approvals: Vec<RequiredApproval>,
    pub obligations: Vec<DecisionObligation>,
    pub execution_constraints: ExecutionConstraints,
    pub decision_hash: String,
}

impl Decision {
    pub(crate) fn seal(
        decision_id: String,
        intent: &TransactionIntent,
        context: &EvaluationContext,
        decision: DecisionKind,
        reasons: Vec<Reason>,
    ) -> Result<Self, DecisionError> {
        let mut value = Self {
            decision_version: DECISION_VERSION.into(),
            decision_id,
            intent_id: intent.intent_id.clone(),
            intent_hash: intent.canonical_hash(),
            evaluation_id: context.evaluation_id().into(),
            profile: ProfileBinding {
                id: context.profile_id().into(),
                version: context.profile_version().into(),
            },
            policy: context.policy().clone(),
            risk: context.risk().clone(),
            evaluation_context_hash: context.evaluation_context_hash().into(),
            context_snapshot_hash: context.context_snapshot_hash().into(),
            simulation: context.simulation().clone(),
            evaluation_time: context.evaluation_time(),
            expires_at: intent.expires_at,
            decision,
            reasons,
            required_approvals: Vec::new(),
            obligations: Vec::new(),
            execution_constraints: constraints_for_intent(intent),
            decision_hash: "0".repeat(64),
        };
        value.validate_shape()?;
        value.verify_derived_binding(intent, context)?;
        value.decision_hash = value.expected_hash();
        Ok(value)
    }

    /// Canonical bytes of the complete Decision document, including its
    /// embedded `decision_hash`.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&sort_json_keys(
            serde_json::to_value(self).expect("Decision serialization cannot fail"),
        ))
        .expect("canonical Decision serialization cannot fail")
    }

    /// Verify only the domain-separated canonical hash. Store/replay callers
    /// must additionally call `verify_binding` against the authoritative
    /// Intent and Evaluation Context.
    pub fn verify_hash(&self) -> Result<(), DecisionError> {
        self.validate_shape()?;
        if self.decision_hash != self.expected_hash() {
            return Err(DecisionError::HashMismatch);
        }
        Ok(())
    }

    /// Verify every Context/Intent-derived binding and the Decision hash.
    pub fn verify_binding(
        &self,
        intent: &TransactionIntent,
        context: &EvaluationContext,
    ) -> Result<(), DecisionError> {
        self.validate_shape()?;
        self.verify_derived_binding(intent, context)?;
        self.verify_hash()
    }

    fn verify_derived_binding(
        &self,
        intent: &TransactionIntent,
        context: &EvaluationContext,
    ) -> Result<(), DecisionError> {
        if context.intent_id() != intent.intent_id
            || context.intent_hash() != intent.canonical_hash()
            || context.verify_agent_context(&intent.context).is_err()
        {
            return Err(DecisionError::IntentBindingMismatch);
        }
        let binding_matches = self.intent_id == intent.intent_id
            && self.intent_hash == intent.canonical_hash()
            && self.evaluation_id == context.evaluation_id()
            && self.profile.id == context.profile_id()
            && self.profile.version == context.profile_version()
            && self.policy == *context.policy()
            && self.risk == *context.risk()
            && self.evaluation_context_hash == context.evaluation_context_hash()
            && self.context_snapshot_hash == context.context_snapshot_hash()
            && self.simulation == *context.simulation()
            && self.evaluation_time == context.evaluation_time()
            && self.expires_at == intent.expires_at
            && self.execution_constraints == constraints_for_intent(intent)
            && self.required_approvals.is_empty()
            && self.obligations.is_empty();
        if !binding_matches {
            return Err(DecisionError::ContextBindingMismatch);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), DecisionError> {
        if self.decision_version != DECISION_VERSION {
            return Err(DecisionError::UnsupportedVersion);
        }
        for value in [
            self.decision_id.as_str(),
            self.intent_id.as_str(),
            self.evaluation_id.as_str(),
            self.profile.id.as_str(),
            self.profile.version.as_str(),
        ] {
            if value.is_empty() || value.trim() != value || value.len() > 256 {
                return Err(DecisionError::InvalidShape);
            }
        }
        for hash in [
            self.intent_hash.as_str(),
            self.evaluation_context_hash.as_str(),
            self.context_snapshot_hash.as_str(),
            self.decision_hash.as_str(),
        ] {
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err(DecisionError::InvalidShape);
            }
        }
        if self.reasons.iter().any(|reason| {
            reason.code.is_empty()
                || reason.severity.is_empty()
                || reason.message.is_empty()
                || reason.code.len() > 256
                || reason.severity.len() > 32
                || reason.message.len() > 1024
        }) {
            return Err(DecisionError::InvalidShape);
        }
        Ok(())
    }

    fn expected_hash(&self) -> String {
        let mut value = serde_json::to_value(self).expect("Decision serialization cannot fail");
        value
            .as_object_mut()
            .expect("Decision serializes as an object")
            .remove("decision_hash");
        let canonical = sort_json_keys(value);
        let canonical_bytes =
            serde_json::to_vec(&canonical).expect("canonical Decision serialization cannot fail");
        let mut input = Vec::with_capacity(DECISION_HASH_DOMAIN.len() + canonical_bytes.len());
        input.extend_from_slice(DECISION_HASH_DOMAIN);
        input.extend_from_slice(&canonical_bytes);
        sha256_hex(&input)
    }
}
