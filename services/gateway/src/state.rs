use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use atf_audit::AuditLedger;
use atf_decision::Decision;
use atf_policy::PolicyBundle;
use atf_risk::RiskConfig;

/// Everything a request handler needs, shared across connections.
///
/// Everything here is in-memory: the decision store and the audit ledger
/// both disappear on restart. That is an explicit, temporary limitation —
/// see `docs/architecture.md` — not an oversight; persistence is Phase 2
/// follow-up work once this wiring itself is proven out.
#[derive(Clone)]
pub struct AppState {
    pub policy_bundle: Arc<PolicyBundle>,
    pub risk_config: Arc<RiskConfig>,
    pub audit_ledger: Arc<Mutex<AuditLedger>>,
    /// Keyed by `intent_id`, so `GET /v1/intents/{id}/decision` has
    /// something to look up (PRD §22.2). A real deployment would read this
    /// back out of the audit ledger's `PolicyEvaluated`/`RiskEvaluated`
    /// events instead of keeping a separate map, once there is a
    /// persistent, queryable ledger to read from.
    pub decisions: Arc<Mutex<HashMap<String, Decision>>>,
}

impl AppState {
    pub fn new(policy_bundle: PolicyBundle, risk_config: RiskConfig) -> Self {
        Self {
            policy_bundle: Arc::new(policy_bundle),
            risk_config: Arc::new(risk_config),
            audit_ledger: Arc::new(Mutex::new(AuditLedger::new())),
            decisions: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
