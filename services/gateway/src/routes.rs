use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;

use atf_core::Timestamp;
use atf_decision::Decision;
use atf_policy::PolicyDecision;
use atf_store::{AdmissionInput, EvaluationInput, FinalizationInput, StoreError};

use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/intents", post(create_intent))
        .route("/v1/intents/{intent_id}/decision", get(get_decision))
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<AppState>) -> Response {
    match state.store.check_ready().await {
        Ok(()) => (StatusCode::OK, "ready").into_response(),
        Err(error) => {
            tracing::warn!(error = %error, "Gateway readiness check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
        }
    }
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

fn error_response(status: StatusCode, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            error: message.into(),
        }),
    )
        .into_response()
}

/// `POST /v1/intents` (PRD §22.1): validate, evaluate, and record a
/// Transaction Intent, then return the resulting Decision. This never
/// executes anything — there is no execution path in this repo at all yet
/// (PRD §22, last line: execution is off by default and this gateway
/// doesn't even have the flag to turn it on).
async fn create_intent(State(state): State<AppState>, body: Bytes) -> Response {
    let raw = match std::str::from_utf8(&body) {
        Ok(raw) => raw,
        Err(_) => {
            return error_response(StatusCode::BAD_REQUEST, "request body is not valid UTF-8")
        }
    };

    let intent = match atf_intent::validate(raw) {
        Ok(intent) => intent,
        Err(err) => return error_response(StatusCode::BAD_REQUEST, err.to_string()),
    };

    let admitted = match state
        .store
        .admit_intent(AdmissionInput {
            intent: intent.clone(),
            received_at: Timestamp::now(),
        })
        .await
    {
        Ok(admitted) => admitted,
        Err(error) => return store_error_response("admit Intent", error),
    };

    let policy_result = state.policy_bundle.evaluate(&intent);
    let policy_evidence = match &policy_result {
        Ok(outcome) => serde_json::json!({
            "status": "SUCCEEDED",
            "decision": format!("{:?}", outcome.decision).to_uppercase(),
            "policy_ids": outcome.policy_ids,
        }),
        Err(error) => serde_json::json!({
            "status": "ERROR",
            "error": error.to_string(),
        }),
    };

    // PRD §10.1.2: a forbidden/errored request never reaches Risk scoring.
    let (risk_findings, risk_status) = match &policy_result {
        Ok(outcome) if outcome.decision == PolicyDecision::Permit => {
            let chain = match state
                .store
                .load_verified_audit_chain(&intent.principal.organization_id)
                .await
            {
                Ok(chain) => chain,
                Err(error) => return store_error_response("load Risk history", error),
            };
            (
                atf_risk::evaluate_with_events(
                    &intent,
                    &state.risk_config,
                    chain.iter().map(|stored| &stored.event),
                ),
                "SUCCEEDED",
            )
        }
        _ => (Vec::new(), "NOT_RUN"),
    };
    let risk_evidence = serde_json::json!({
        "status": risk_status,
        "findings": &risk_findings,
    });

    let decision = atf_decision::decide(&intent, policy_result, &risk_findings);
    let evaluated_at = Timestamp::now();
    let finalized = match state
        .store
        .finalize_decision(FinalizationInput {
            organization_id: intent.principal.organization_id.clone(),
            intent_id: intent.intent_id.clone(),
            expected_intent_hash: admitted.intent_hash,
            evaluation: EvaluationInput {
                evaluation_id: atf_core::new_ulid(),
                evaluated_at,
                evidence: serde_json::json!({
                    "policy": policy_evidence,
                    "risk": risk_evidence,
                }),
            },
            decision,
            decided_at: Timestamp::now(),
        })
        .await
    {
        Ok(finalized) => finalized,
        Err(error) => return store_error_response("finalize Decision", error),
    };

    Json(finalized.decision).into_response()
}

/// `GET /v1/intents/{intent_id}/decision` (PRD §22.2).
async fn get_decision(
    State(state): State<AppState>,
    Path(intent_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Decision>, Response> {
    let organization_id = organization_header(&headers).ok_or_else(|| {
        error_response(
            StatusCode::BAD_REQUEST,
            "x-atf-organization-id must be a non-empty trimmed header",
        )
    })?;
    match state
        .store
        .load_finalized_decision(organization_id, &intent_id)
        .await
    {
        Ok(Some(finalized)) => Ok(Json(finalized.decision)),
        Ok(None) => Err(error_response(
            StatusCode::NOT_FOUND,
            format!("no decision recorded for intent `{intent_id}`"),
        )),
        Err(error) => Err(store_error_response("load Decision", error)),
    }
}

fn organization_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-atf-organization-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.trim() == *value && value.len() <= 128)
}

fn store_error_response(operation: &'static str, error: StoreError) -> Response {
    tracing::warn!(operation, error = %error, "durable Gateway operation failed");
    match error {
        StoreError::OrganizationNotFound { .. } => error_response(
            StatusCode::BAD_REQUEST,
            "the Intent organization is not provisioned",
        ),
        StoreError::IntentConflict { .. }
        | StoreError::IntentHashMismatch { .. }
        | StoreError::DecisionConflict { .. }
        | StoreError::FinalizationConflict { .. } => error_response(
            StatusCode::CONFLICT,
            "the request conflicts with existing durable state",
        ),
        StoreError::InvalidRepositoryInput { .. }
        | StoreError::DecisionBindingMismatch { .. }
        | StoreError::Json(_) => error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "the request could not be recorded safely",
        ),
        _ => error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "durable state is unavailable",
        ),
    }
}
