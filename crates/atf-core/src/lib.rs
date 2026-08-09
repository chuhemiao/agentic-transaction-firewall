//! Shared domain primitives used across all ATF crates.
//!
//! Nothing in this crate is transport-, storage-, or protocol-specific. It
//! exists so that "no floating point for money" and "timestamps are always
//! RFC 3339" (PRD §9.1, §35.8) are enforced in one place instead of being
//! re-implemented per crate.

mod amount;
mod canonical;
mod decision;
mod decision_binding;
mod error;
mod evaluation;
mod evidence;
mod history;
mod id;
mod lifecycle;
mod time;

pub use amount::Amount;
pub use canonical::{sha256_hex, sort_json_keys};
pub use decision::DecisionKind;
pub use decision_binding::{
    DecisionObligation, ExecutionConstraints, ProfileBinding, RequiredApproval,
};
pub use error::CoreError;
pub use evaluation::{
    EvaluationContext, EvaluationContextError, EvaluationContextInput,
    EvidenceTrustPolicyReference, ExternalSnapshotReference, RepositorySnapshot,
    SimulationReference, VersionedArtifactReference,
};
pub use evidence::{
    EvidenceEnvelope, EvidenceError, EvidenceFreshness, EvidenceKind, EvidenceSignature,
    EvidenceSource, EvidenceTrustPolicy, TrustedEvidenceSource, VerifiedEvidence,
};
pub use history::{
    AccountingBoundary, DuplicatePurchaseHistory, DuplicatePurchaseMatch, DuplicatePurchaseQuery,
    HistorySnapshotError, RiskHistorySnapshot,
};
pub use id::new_ulid;
pub use lifecycle::{
    validate_lifecycle_transition, IntentLifecycleState, LifecycleTransitionError,
};
pub use time::Timestamp;
