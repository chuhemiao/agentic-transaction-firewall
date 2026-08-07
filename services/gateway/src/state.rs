use std::sync::Arc;

use atf_policy::PolicyBundle;
use atf_risk::RiskConfig;
use atf_store::Store;

use crate::IdentityGatewayConfig;

/// Everything a request handler needs, shared across connections.
///
/// PostgreSQL is the sole authority for admitted Intents, Decisions, and
/// Audit. Policy and Risk configuration remain immutable process state.
#[derive(Clone)]
pub struct AppState {
    pub policy_bundle: Arc<PolicyBundle>,
    pub risk_config: Arc<RiskConfig>,
    pub store: Store,
    pub identity: Arc<IdentityGatewayConfig>,
}

impl AppState {
    pub fn new(
        policy_bundle: PolicyBundle,
        risk_config: RiskConfig,
        store: Store,
        identity: IdentityGatewayConfig,
    ) -> Self {
        Self {
            policy_bundle: Arc::new(policy_bundle),
            risk_config: Arc::new(risk_config),
            store,
            identity: Arc::new(identity),
        }
    }
}
