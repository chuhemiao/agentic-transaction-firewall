use std::fs;
use std::path::Path;
use std::str::FromStr;

use atf_intent::TransactionIntent;
use cedar_policy::{Authorizer, Decision as CedarDecision, Entities, PolicySet};

use crate::error::PolicyError;
use crate::mapping::build_request;

/// Cedar's own Allow/Deny, renamed to the vocabulary PRD §11 uses for the
/// Policy Kernel specifically (as opposed to ATF's overall PERMIT/DENY/
/// REVIEW/ERROR Decision in `atf-decision`, PRD §10.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    Permit,
    Forbid,
}

#[derive(Debug, Clone)]
pub struct PolicyOutcome {
    pub decision: PolicyDecision,
    /// Ids of the policies that contributed to the decision (PRD §10 `reasons`).
    pub policy_ids: Vec<String>,
}

/// A loaded, parsed set of Cedar policies ready to evaluate Transaction
/// Intents against. Does not yet implement Policy Bundle versioning or
/// multi-bundle conflict resolution (PRD §11.3) — that is future work once
/// there is more than one bundle source to reconcile.
pub struct PolicyBundle {
    policies: PolicySet,
}

impl FromStr for PolicyBundle {
    type Err = PolicyError;

    fn from_str(src: &str) -> Result<Self, PolicyError> {
        let policies = src
            .parse::<PolicySet>()
            .map_err(|e| PolicyError::Parse(e.to_string()))?;
        Ok(Self { policies })
    }
}

impl PolicyBundle {
    /// Load every `*.cedar` file directly inside `dir` (not recursive),
    /// concatenated in filename order, as a single policy set.
    pub fn from_dir(dir: &Path) -> Result<Self, PolicyError> {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .map_err(|e| PolicyError::Io(format!("{}: {e}", dir.display())))?
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "cedar"))
            .map(|entry| entry.path())
            .collect();
        entries.sort();

        let mut combined = String::new();
        for path in entries {
            let content = fs::read_to_string(&path)
                .map_err(|e| PolicyError::Io(format!("{}: {e}", path.display())))?;
            combined.push_str(&content);
            combined.push('\n');
        }
        Self::from_str(&combined)
    }

    pub fn evaluate(&self, intent: &TransactionIntent) -> Result<PolicyOutcome, PolicyError> {
        let request = build_request(intent)?;
        let entities = Entities::empty();
        let authorizer = Authorizer::new();
        let response = authorizer.is_authorized(&request, &self.policies, &entities);

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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use atf_core::{Amount, Timestamp};
    use atf_intent::{Action, Mandate, Principal, Resource, Transaction};

    fn sample_intent(amount: &str, human_authorized: bool) -> TransactionIntent {
        TransactionIntent {
            spec_version: "1.0".into(),
            intent_id: "01J000000000000000000000".into(),
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
                resource_type: None,
            },
            transaction: Transaction {
                network: "base".into(),
                asset: "eip155:8453/erc20:0x0".into(),
                amount: Amount::from_str(amount).unwrap(),
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

    const POLICY: &str = r#"
        permit (
            principal,
            action == Action::"payment/purchase_api_resource",
            resource
        )
        when {
            context.organization_id == "alpha-lab" &&
            context.amount.lessThanOrEqual(decimal("20.0000"))
        };

        forbid (
            principal,
            action,
            resource
        )
        when {
            context.human_authorized == false
        };
    "#;

    #[test]
    fn permits_within_budget() {
        let bundle = PolicyBundle::from_str(POLICY).unwrap();
        let outcome = bundle.evaluate(&sample_intent("12.50", true)).unwrap();
        assert_eq!(outcome.decision, PolicyDecision::Permit);
        assert!(!outcome.policy_ids.is_empty());
    }

    #[test]
    fn denies_over_budget_by_default() {
        let bundle = PolicyBundle::from_str(POLICY).unwrap();
        // No permit matches (amount exceeds 20), and no forbid matches either
        // (human_authorized is true) — Cedar's default-deny applies.
        let outcome = bundle.evaluate(&sample_intent("50.00", true)).unwrap();
        assert_eq!(outcome.decision, PolicyDecision::Forbid);
    }

    #[test]
    fn forbid_overrides_permit() {
        let bundle = PolicyBundle::from_str(POLICY).unwrap();
        // Within budget, but not human-authorized -> explicit forbid wins.
        let outcome = bundle.evaluate(&sample_intent("12.50", false)).unwrap();
        assert_eq!(outcome.decision, PolicyDecision::Forbid);
    }

    #[test]
    fn rejects_malformed_policy_text() {
        assert!(PolicyBundle::from_str("not a policy").is_err());
    }

    #[test]
    fn loads_and_combines_a_directory_of_cedar_files() {
        let dir = std::env::temp_dir().join(format!("atf-policy-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("a.cedar"), POLICY).unwrap();

        let bundle = PolicyBundle::from_dir(&dir).unwrap();
        let outcome = bundle.evaluate(&sample_intent("12.50", true)).unwrap();
        assert_eq!(outcome.decision, PolicyDecision::Permit);

        fs::remove_dir_all(&dir).unwrap();
    }
}
