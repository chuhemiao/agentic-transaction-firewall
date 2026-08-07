use atf_intent::IntentError;
use atf_store::StoreError;
use axum::http::StatusCode;
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

    pub(crate) fn decision_not_found() -> Self {
        Self::new(
            StatusCode::NOT_FOUND,
            "DECISION_NOT_FOUND",
            "No decision was found.",
        )
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
            StoreError::IntentConflict { .. }
            | StoreError::IntentHashMismatch { .. }
            | StoreError::LifecycleConflict { .. }
            | StoreError::DecisionConflict { .. }
            | StoreError::FinalizationConflict { .. } => Self::new(
                StatusCode::CONFLICT,
                "DURABLE_STATE_CONFLICT",
                "The request conflicts with existing durable state.",
            ),
            StoreError::DurableStateCorrupt { .. }
            | StoreError::IncompleteAdmissionEvidence { .. }
            | StoreError::IncompleteDecisionEvidence { .. }
            | StoreError::AuditChainCorrupt { .. } => Self::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "DURABLE_STATE_INTEGRITY_ERROR",
                "Durable state failed an integrity check.",
            ),
            StoreError::AuditPayload(_)
            | StoreError::InvalidAuditEvent { .. }
            | StoreError::InvalidRepositoryInput { .. }
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
        (
            self.status,
            Json(ApiErrorBody {
                code: self.code,
                message: self.message,
                request_id: request_id.as_str().to_owned(),
                details: self.details,
            }),
        )
            .into_response()
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
        }
    }
}
