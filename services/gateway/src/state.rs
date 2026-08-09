use std::sync::Arc;

use atf_core::{EvaluationContext, Timestamp};
use atf_intent::TransactionIntent;
use atf_policy::{PolicyBundle, PolicyError, PolicyOutcome};
use atf_risk::RiskRuleSet;
use atf_store::Store;

use crate::middleware::{GatewayHttpConfig, HttpRuntime};
use crate::telemetry::GatewayTelemetry;
use crate::{IdentityGatewayConfig, OperatorAuthenticator};

/// Everything a request handler needs, shared across connections.
///
/// PostgreSQL is the sole authority for admitted Intents, Decisions, Audit,
/// and the durable active Policy pointer.
#[derive(Clone)]
pub struct AppState {
    policy_source: PolicySource,
    pub risk_rule_set: Arc<RiskRuleSet>,
    pub store: Store,
    pub identity: Arc<IdentityGatewayConfig>,
    pub operator_auth: Arc<OperatorAuthenticator>,
    pub(crate) telemetry: GatewayTelemetry,
    pub(crate) http: HttpRuntime,
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

pub(crate) enum ResolvedPolicyBundle {
    Static(Arc<PolicyBundle>),
    Durable(Arc<PolicyBundle>),
}

impl ResolvedPolicyBundle {
    pub(crate) fn bundle(&self) -> &PolicyBundle {
        match self {
            Self::Static(bundle) => bundle,
            Self::Durable(bundle) => bundle,
        }
    }

    pub(crate) fn evaluate(
        &self,
        intent: &TransactionIntent,
        context: &EvaluationContext,
    ) -> Result<PolicyOutcome, PolicyError> {
        self.bundle().evaluate(intent, context)
    }
}

impl AppState {
    pub fn new(
        policy_bundle: PolicyBundle,
        risk_rule_set: RiskRuleSet,
        store: Store,
        identity: IdentityGatewayConfig,
        operator_auth: OperatorAuthenticator,
    ) -> Self {
        let telemetry = GatewayTelemetry::default();
        Self {
            policy_source: PolicySource::Static(Arc::new(policy_bundle)),
            risk_rule_set: Arc::new(risk_rule_set),
            store,
            identity: Arc::new(identity),
            operator_auth: Arc::new(operator_auth),
            http: HttpRuntime::new(GatewayHttpConfig::default(), telemetry.clone()),
            telemetry,
        }
    }

    pub fn new_durable(
        organization_id: String,
        environment: String,
        bundle_id: String,
        risk_rule_set: RiskRuleSet,
        store: Store,
        identity: IdentityGatewayConfig,
        operator_auth: OperatorAuthenticator,
    ) -> Self {
        let telemetry = GatewayTelemetry::default();
        Self {
            policy_source: PolicySource::Durable {
                organization_id: organization_id.into(),
                environment: environment.into(),
                bundle_id: bundle_id.into(),
            },
            risk_rule_set: Arc::new(risk_rule_set),
            store,
            identity: Arc::new(identity),
            operator_auth: Arc::new(operator_auth),
            http: HttpRuntime::new(GatewayHttpConfig::default(), telemetry.clone()),
            telemetry,
        }
    }

    pub(crate) fn configure_http(&mut self, config: GatewayHttpConfig) {
        self.http = HttpRuntime::new(config, self.telemetry.clone());
    }

    pub(crate) async fn resolve_policy(
        &self,
        intent: &TransactionIntent,
        evaluated_at: Timestamp,
    ) -> Result<ResolvedPolicyBundle, PolicyError> {
        match &self.policy_source {
            PolicySource::Static(bundle) => Ok(ResolvedPolicyBundle::Static(bundle.clone())),
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
                Ok(ResolvedPolicyBundle::Durable(Arc::new(active.bundle)))
            }
        }
    }
}
