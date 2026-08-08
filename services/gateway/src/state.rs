use std::sync::Arc;

use atf_core::Timestamp;
use atf_intent::TransactionIntent;
use atf_policy::{PolicyBundle, PolicyError, PolicyOutcome};
use atf_risk::RiskConfig;
use atf_store::Store;

use crate::{IdentityGatewayConfig, OperatorAuthenticator};

/// Everything a request handler needs, shared across connections.
///
/// PostgreSQL is the sole authority for admitted Intents, Decisions, Audit,
/// and the durable active Policy pointer.
#[derive(Clone)]
pub struct AppState {
    policy_source: PolicySource,
    pub risk_config: Arc<RiskConfig>,
    pub store: Store,
    pub identity: Arc<IdentityGatewayConfig>,
    pub operator_auth: Arc<OperatorAuthenticator>,
}

#[derive(Clone)]
enum PolicySource {
    Static(Arc<PolicyBundle>),
    Durable {
        organization_id: Arc<str>,
        environment: Arc<str>,
        bundle_id: Arc<str>,
    },
}

impl AppState {
    pub fn new(
        policy_bundle: PolicyBundle,
        risk_config: RiskConfig,
        store: Store,
        identity: IdentityGatewayConfig,
        operator_auth: OperatorAuthenticator,
    ) -> Self {
        Self {
            policy_source: PolicySource::Static(Arc::new(policy_bundle)),
            risk_config: Arc::new(risk_config),
            store,
            identity: Arc::new(identity),
            operator_auth: Arc::new(operator_auth),
        }
    }

    pub fn new_durable(
        organization_id: String,
        environment: String,
        bundle_id: String,
        risk_config: RiskConfig,
        store: Store,
        identity: IdentityGatewayConfig,
        operator_auth: OperatorAuthenticator,
    ) -> Self {
        Self {
            policy_source: PolicySource::Durable {
                organization_id: organization_id.into(),
                environment: environment.into(),
                bundle_id: bundle_id.into(),
            },
            risk_config: Arc::new(risk_config),
            store,
            identity: Arc::new(identity),
            operator_auth: Arc::new(operator_auth),
        }
    }

    pub(crate) async fn evaluate_policy(
        &self,
        intent: &TransactionIntent,
        evaluated_at: Timestamp,
    ) -> Result<PolicyOutcome, PolicyError> {
        match &self.policy_source {
            PolicySource::Static(bundle) => bundle.evaluate_at(intent, evaluated_at),
            PolicySource::Durable {
                organization_id,
                environment,
                bundle_id,
            } => {
                if intent.principal.organization_id != organization_id.as_ref() {
                    return Err(PolicyError::ScopeMismatch {
                        expected_organization_id: organization_id.to_string(),
                        expected_environment: environment.to_string(),
                    });
                }
                let active = self
                    .store
                    .load_active_policy_bundle(
                        organization_id,
                        environment,
                        bundle_id,
                        evaluated_at,
                    )
                    .await
                    .map_err(|_| PolicyError::Unavailable)?;
                active.bundle.evaluate_at(intent, evaluated_at)
            }
        }
    }
}
