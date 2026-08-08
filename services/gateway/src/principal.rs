use atf_store::{AdmissionGrant, OperatorPrincipal};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AgentPrincipal {
    pub organization_id: String,
    pub agent_id: String,
    pub key_id: String,
    pub intent_hash: String,
    pub envelope_hash: String,
}

impl AgentPrincipal {
    pub(crate) fn from_admission(admission: &AdmissionGrant) -> Self {
        Self {
            organization_id: admission.admitted.identity.organization_id.clone(),
            agent_id: admission.admitted.identity.agent_id.clone(),
            key_id: admission.admitted.identity.key_id.clone(),
            intent_hash: admission.admitted.intent_hash.clone(),
            envelope_hash: admission.admitted.identity.envelope_hash.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RequestPrincipal {
    Agent(AgentPrincipal),
    Operator(OperatorPrincipal),
}

impl RequestPrincipal {
    pub(crate) fn into_agent(self) -> Option<AgentPrincipal> {
        match self {
            Self::Agent(principal) => Some(principal),
            Self::Operator(_) => None,
        }
    }

    pub(crate) fn into_operator(self) -> Option<OperatorPrincipal> {
        match self {
            Self::Operator(principal) => Some(principal),
            Self::Agent(_) => None,
        }
    }
}
