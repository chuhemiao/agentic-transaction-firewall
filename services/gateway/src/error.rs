use atf_intent::IntentError;
use atf_store::StoreError;
use axum::http::StatusCode;
use axum::http::{header::WWW_AUTHENTICATE, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Serialize;

use crate::request_id::RequestId;

#[derive(Debug, Serialize)]
struct ApiErrorBody {
    code: &'static str,
    message: &'static str,
    request_id: String,
    details: Vec<ApiErrorDetail>,
}

#[derive(Debug, Serialize)]
struct ApiErrorDetail {
    code: &'static str,
    field: &'static str,
}

pub(crate) struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
    details: Vec<ApiErrorDetail>,
    bearer_challenge: bool,
}

impl ApiError {
    pub(crate) fn invalid_utf8() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "INVALID_UTF8",
            "Request body must be valid UTF-8.",
        )
    }

    pub(crate) fn body_rejection(status: StatusCode) -> Self {
        if status == StatusCode::PAYLOAD_TOO_LARGE {
            Self::new(
                StatusCode::PAYLOAD_TOO_LARGE,
                "REQUEST_BODY_TOO_LARGE",
                "Request body exceeds the configured limit.",
            )
        } else {
            Self::new(
                StatusCode::BAD_REQUEST,
                "REQUEST_BODY_INVALID",
                "Request body could not be read safely.",
            )
        }
    }

    pub(crate) fn from_intent(error: IntentError) -> Self {
        match error {
            IntentError::InvalidJson(_) => Self::new(
                StatusCode::BAD_REQUEST,
                "INVALID_JSON",
                "Request body must be valid JSON.",
            ),
            IntentError::SchemaViolation(_) => Self::new(
                StatusCode::BAD_REQUEST,
                "INTENT_SCHEMA_INVALID",
                "Intent does not match the supported schema.",
            ),
            IntentError::Malformed(_) => Self::new(
                StatusCode::BAD_REQUEST,
                "INTENT_SHAPE_INVALID",
                "Intent could not be parsed safely.",
            ),
            IntentError::Semantic(errors) => Self {
                status: StatusCode::BAD_REQUEST,
                code: "INTENT_SEMANTIC_INVALID",
                message: "Intent violates one or more semantic rules.",
                details: errors
                    .violations()
                    .iter()
                    .map(|violation| ApiErrorDetail {
                        code: violation.code.as_str(),
                        field: violation.field,
                    })
                    .collect(),
                bearer_challenge: false,
            },
        }
    }

    pub(crate) fn organization_header_invalid() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "ORGANIZATION_HEADER_INVALID",
            "X-ATF-Organization-ID must be a non-empty trimmed value no longer than 128 bytes.",
        )
    }

    pub(crate) fn identity_rejected(code: &'static str) -> Self {
        let status = if matches!(
            code,
            "IDENTITY_AGENT_NOT_ACTIVE"
                | "IDENTITY_AGENT_ENVIRONMENT_MISMATCH"
                | "IDENTITY_AGENT_NOT_YET_ACTIVE"
                | "IDENTITY_AGENT_EXPIRED"
                | "IDENTITY_ENVELOPE_EXCEEDS_AGENT_LIFETIME"
                | "IDENTITY_KEY_NOT_YET_ACTIVE"
                | "IDENTITY_KEY_EXPIRED"
                | "IDENTITY_KEY_REVOKED"
                | "IDENTITY_ENVELOPE_EXCEEDS_KEY_LIFETIME"
        ) {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::UNAUTHORIZED
        };
        Self::new(status, code, "The request identity assertion was rejected.")
    }

    pub(crate) fn decision_not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "DECISION_NOT_FOUND",
            "No decision was found.",
        )
    }

    pub(crate) fn authentication_required() -> Self {
        let mut error = Self::new(
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
            "A valid route-appropriate credential is required.",
        );
        error.bearer_challenge = true;
        error
    }

    pub(crate) fn route_not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "ROUTE_NOT_FOUND",
            "No route was found.",
        )
    }

    pub(crate) fn method_not_allowed() -> Self {
        Self::new(
            StatusCode::METHOD_NOT_ALLOWED,
            "METHOD_NOT_ALLOWED",
            "The HTTP method is not allowed for this route.",
        )
    }

    pub(crate) fn from_store(error: StoreError) -> Self {
        match error {
            StoreError::OrganizationNotFound { .. } => Self::new(
                StatusCode::BAD_REQUEST,
                "ORGANIZATION_NOT_FOUND",
                "The Intent organization is not available.",
            ),
            StoreError::IdempotencyConflict { .. } => Self::new(
                StatusCode::CONFLICT,
                "IDEMPOTENCY_CONFLICT",
                "The idempotency key is already bound to different request content.",
            ),
            StoreError::IdempotencyInProgress { .. } => Self::new(
                StatusCode::CONFLICT,
                "IDEMPOTENCY_IN_PROGRESS",
                "The idempotent request is in progress or awaiting recovery.",
            ),
            StoreError::IdentityRejected { reason_code } => Self::identity_rejected(reason_code),
            StoreError::NonceReplay { .. } => Self::new(
                StatusCode::CONFLICT,
                "IDENTITY_NONCE_REPLAY",
                "The signed identity Nonce is already bound to another request.",
            ),
            StoreError::IntentConflict { .. }
            | StoreError::AgentConflict { .. }
            | StoreError::IdentityKeyConflict { .. }
            | StoreError::OperatorConflict { .. }
            | StoreError::OperatorRoleConflict { .. }
            | StoreError::IntentHashMismatch { .. }
            | StoreError::LifecycleConflict { .. }
            | StoreError::DecisionConflict { .. }
            | StoreError::FinalizationConflict { .. }
            | StoreError::IdempotencyCompleted { .. }
            | StoreError::EvaluatorLeaseLost { .. } => Self::new(
                StatusCode::CONFLICT,
                "DURABLE_STATE_CONFLICT",
                "The request conflicts with existing durable state.",
            ),
            StoreError::DurableStateCorrupt { .. }
            | StoreError::IdentityStateCorrupt { .. }
            | StoreError::OperatorStateCorrupt { .. }
            | StoreError::NonceStateCorrupt { .. }
            | StoreError::IncompleteAdmissionEvidence { .. }
            | StoreError::IncompleteDecisionEvidence { .. }
            | StoreError::AuditChainCorrupt { .. } => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DURABLE_STATE_INTEGRITY_ERROR",
                "Durable state failed an integrity check.",
            ),
            StoreError::AuditPayload(_)
            | StoreError::IdentityDomain(_)
            | StoreError::InvalidAuditEvent { .. }
            | StoreError::InvalidRepositoryInput { .. }
            | StoreError::AgentNotFound { .. }
            | StoreError::IdentityKeyNotFound { .. }
            | StoreError::OperatorNotFound { .. }
            | StoreError::OperatorRoleNotFound { .. }
            | StoreError::IdempotencyNotFound { .. }
            | StoreError::RecoveredWorkMustFailClosed { .. }
            | StoreError::IntentNotFound { .. }
            | StoreError::DecisionBindingMismatch { .. }
            | StoreError::Json(_) => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "The request could not be completed safely.",
            ),
            StoreError::Database(_)
            | StoreError::Migration(_)
            | StoreError::MissingSchemaMetadata
            | StoreError::IncompatibleSchema { .. } => Self::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "DURABLE_STATE_UNAVAILABLE",
                "Durable state is unavailable.",
            ),
        }
    }

    pub(crate) fn into_response(self, request_id: &RequestId) -> Response {
        let mut response = (
            self.status,
            Json(ApiErrorBody {
                code: self.code,
                message: self.message,
                request_id: request_id.as_str().to_owned(),
                details: self.details,
            }),
        )
            .into_response();
        if self.bearer_challenge {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }

    pub(crate) fn code(&self) -> &'static str {
        self.code
    }

    fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
            details: Vec::new(),
            bearer_challenge: false,
        }
    }
}
