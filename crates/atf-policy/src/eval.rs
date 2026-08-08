use atf_core::EvaluationContext;
use atf_intent::{validate_profile, TransactionIntent};
use cedar_policy::{Authorizer, Decision as CedarDecision, Entities};
use serde::{Deserialize, Serialize};

use crate::bundle::PolicyBundle;
use crate::error::PolicyError;
use crate::mapping::build_request;

/// Cedar's own Allow/Deny, renamed to the vocabulary PRD §11 uses for the
/// Policy Kernel specifically (as opposed to ATF's overall PERMIT/DENY/
/// REVIEW/ERROR Decision in `atf-decision`, PRD §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyDecision {
    Permit,
    Forbid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyOutcome {
    pub decision: PolicyDecision,
    /// Ids of the policies that contributed to the decision (PRD §10 `reasons`).
    pub policy_ids: Vec<String>,
    pub bundle_id: String,
    pub policy_version: String,
    pub bundle_hash: String,
}

impl PolicyBundle {
    /// Evaluate one Intent using only inputs bound by an immutable Evaluation
    /// Context. The executable Bundle remains a separate in-memory value, but
    /// its exact identity, scope and active time must match the Context before
    /// Cedar is invoked.
    pub fn evaluate(
        &self,
        intent: &TransactionIntent,
        context: &EvaluationContext,
    ) -> Result<PolicyOutcome, PolicyError> {
        validate_context_binding(self, intent, context)?;
        let request = build_request(intent, &self.schema)?;
        let entities = Entities::empty();
        let authorizer = Authorizer::new();
        let response = authorizer.is_authorized(&request, &self.policies, &entities);
        let authorization_errors = response
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if !authorization_errors.is_empty() {
            return Err(PolicyError::Authorization(authorization_errors.join("; ")));
        }

        let decision = match response.decision() {
            CedarDecision::Allow => PolicyDecision::Permit,
            CedarDecision::Deny => PolicyDecision::Forbid,
        };
        let policy_ids = response
            .diagnostics()
            .reason()
            .map(|id| id.to_string())
            .collect();

        Ok(PolicyOutcome {
            decision,
            policy_ids,
            bundle_id: self.bundle_id().to_owned(),
            policy_version: self.policy_version().to_owned(),
            bundle_hash: self.bundle_hash().to_owned(),
        })
    }
}

fn validate_context_binding(
    bundle: &PolicyBundle,
    intent: &TransactionIntent,
    context: &EvaluationContext,
) -> Result<(), PolicyError> {
    if context.intent_id() != intent.intent_id || context.intent_hash() != intent.canonical_hash() {
        return Err(PolicyError::EvaluationContext(
            "Intent ID/hash binding does not match".into(),
        ));
    }
    context
        .verify_agent_context(&intent.context)
        .map_err(|_| PolicyError::EvaluationContext("Agent context hash does not match".into()))?;
    let profile = validate_profile(intent).map_err(|error| {
        PolicyError::EvaluationContext(format!("Intent Profile is invalid: {error}"))
    })?;
    if context.profile_id() != profile.id() || context.profile_version() != profile.version() {
        return Err(PolicyError::EvaluationContext(
            "Intent Profile binding does not match".into(),
        ));
    }
    if context.environment() != bundle.environment()
        || intent.principal.organization_id != bundle.organization_id()
    {
        return Err(PolicyError::ScopeMismatch {
            expected_organization_id: bundle.organization_id().into(),
            expected_environment: bundle.environment().into(),
        });
    }
    let expected = (
        bundle.bundle_id(),
        bundle.policy_version(),
        bundle.bundle_hash(),
    );
    if context.policy().available_parts() != Some(expected) {
        return Err(PolicyError::EvaluationContext(
            "Policy Bundle identity does not match".into(),
        ));
    }
    bundle.validate_evaluation_scope(&intent.principal.organization_id, context.evaluation_time())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atf_core::{
        Amount, EvaluationContextInput, EvidenceTrustPolicyReference, ExternalSnapshotReference,
        RepositorySnapshot, SimulationReference, Timestamp, VersionedArtifactReference,
    };
    use atf_intent::{Action, Mandate, Principal, Resource, Transaction};
    use std::path::Path;
    use std::str::FromStr;

    fn sample_intent(amount: &str, human_authorized: bool) -> TransactionIntent {
        TransactionIntent {
            spec_version: "1.0".into(),
            intent_id: "01J00000000000000000000000".into(),
            idempotency_key: "idem-1".into(),
            created_at: Timestamp::from_str("2026-07-18T08:00:00Z").unwrap(),
            expires_at: Timestamp::from_str("2026-07-18T08:05:00Z").unwrap(),
            principal: Principal {
                organization_id: "alpha-lab".into(),
                user_id: None,
                agent_id: "research-agent-01".into(),
                agent_version: None,
                strategy_id: None,
            },
            mandate: Mandate {
                mandate_id: "mandate-001".into(),
                task_id: None,
                purpose: "purchase historical order-book data".into(),
                budget_id: None,
                human_authorized,
            },
            action: Action {
                category: "payment".into(),
                operation: "purchase_api_resource".into(),
            },
            resource: Resource {
                protocol: "x402".into(),
                venue: None,
                resource_id: "btc-orderbook-2026-07-01".into(),
                resource_type: Some("dataset".into()),
            },
            transaction: Transaction {
                network: "eip155:8453".into(),
                asset: "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913".into(),
                amount: Amount::from_str(amount).unwrap(),
                destination: Some("eip155:8453:0x1111111111111111111111111111111111111111".into()),
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

    #[test]
    fn permits_within_budget() {
        let bundle = example_bundle();
        let intent = sample_intent("12.50", true);
        let context = evaluation_context(&bundle, &intent);
        let outcome = bundle.evaluate(&intent, &context).unwrap();
        assert_eq!(outcome.decision, PolicyDecision::Permit);
        assert!(!outcome.policy_ids.is_empty());
    }

    #[test]
    fn denies_over_budget_by_default() {
        let bundle = example_bundle();
        let intent = sample_intent("50.00", true);
        let context = evaluation_context(&bundle, &intent);
        // No permit matches (amount exceeds 20), and no forbid matches either
        // (human_authorized is true) — Cedar's default-deny applies.
        let outcome = bundle.evaluate(&intent, &context).unwrap();
        assert_eq!(outcome.decision, PolicyDecision::Forbid);
    }

    #[test]
    fn forbid_overrides_permit() {
        let bundle = example_bundle();
        let intent = sample_intent("12.50", false);
        let context = evaluation_context(&bundle, &intent);
        // Within budget, but not human-authorized -> explicit forbid wins.
        let outcome = bundle.evaluate(&intent, &context).unwrap();
        assert_eq!(outcome.decision, PolicyDecision::Forbid);
    }

    #[test]
    fn repeated_evaluation_of_one_snapshot_is_byte_equivalent() {
        let bundle = example_bundle();
        let intent = sample_intent("12.50", true);
        let context = evaluation_context(&bundle, &intent);

        let first = bundle.evaluate(&intent, &context).unwrap();
        let second = bundle.evaluate(&intent, &context).unwrap();

        assert_eq!(
            serde_json::to_vec(&first).unwrap(),
            serde_json::to_vec(&second).unwrap()
        );
    }

    fn example_bundle() -> PolicyBundle {
        let context = crate::PolicyBundleLoadContext {
            organization_id: "alpha-lab".into(),
            environment: "development".into(),
            evaluated_at: evaluation_time(),
        };
        PolicyBundle::from_dir(
            &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../policies/examples"),
            &context,
        )
        .unwrap()
    }

    fn evaluation_time() -> Timestamp {
        Timestamp::from_str("2026-08-08T12:00:00Z").unwrap()
    }

    fn evaluation_context(bundle: &PolicyBundle, intent: &TransactionIntent) -> EvaluationContext {
        let profile = validate_profile(intent).unwrap();
        EvaluationContext::new(EvaluationContextInput {
            evaluation_id: "01J0000000000000000000EVAL".into(),
            intent_id: intent.intent_id.clone(),
            intent_hash: intent.canonical_hash(),
            evaluation_time: evaluation_time(),
            environment: bundle.environment().into(),
            profile_id: profile.id().into(),
            profile_version: profile.version().into(),
            policy: VersionedArtifactReference::available(
                bundle.bundle_id(),
                bundle.policy_version(),
                bundle.bundle_hash(),
            )
            .unwrap(),
            risk: VersionedArtifactReference::unavailable("RISK_NOT_USED").unwrap(),
            context_snapshot_id: "01J0000000000000000000SNAP".into(),
            agent_context: intent.context.clone(),
            evidence: Vec::new(),
            evidence_trust_policy: EvidenceTrustPolicyReference::not_configured(
                "TRUST_POLICY_NOT_CONFIGURED",
            )
            .unwrap(),
            history: RepositorySnapshot::new("audit-chain:alpha-lab:1", 1, "0".repeat(64)).unwrap(),
            market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_UNAVAILABLE").unwrap(),
            simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED").unwrap(),
        })
        .unwrap()
    }
}
