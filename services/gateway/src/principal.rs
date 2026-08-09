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
    Operations(OperationsPrincipal),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperationsCapability {
    MetricsRead,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OperationsPrincipal {
    credential_fingerprint: String,
    capability: OperationsCapability,
}

impl OperationsPrincipal {
    pub(crate) fn from_spki(spki: &[u8]) -> Self {
        let mut fingerprint_input = b"ATF_OPERATIONS_MTLS_V1\0".to_vec();
        fingerprint_input.extend_from_slice(spki);
        Self {
            credential_fingerprint: atf_core::sha256_hex(&fingerprint_input),
            capability: OperationsCapability::MetricsRead,
        }
    }

    pub(crate) fn credential_fingerprint(&self) -> &str {
        &self.credential_fingerprint
    }

    pub(crate) fn can_read_metrics(&self) -> bool {
        self.capability == OperationsCapability::MetricsRead
    }
}

impl RequestPrincipal {
    pub(crate) fn into_agent(self) -> Option<AgentPrincipal> {
        match self {
            Self::Agent(principal) => Some(principal),
            Self::Operator(_) | Self::Operations(_) => None,
        }
    }

    pub(crate) fn into_operator(self) -> Option<OperatorPrincipal> {
        match self {
            Self::Operator(principal) => Some(principal),
            Self::Agent(_) | Self::Operations(_) => None,
        }
    }

    pub(crate) fn into_operations(self) -> Option<OperationsPrincipal> {
        match self {
            Self::Operations(principal) => Some(principal),
            Self::Agent(_) | Self::Operator(_) => None,
        }
    }
}
