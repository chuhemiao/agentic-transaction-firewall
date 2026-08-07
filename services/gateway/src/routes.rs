use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::{Extension, Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use atf_audit::{
    OptionalModuleOutcome, PolicyEvaluatedPayload, PolicyOutcome, RequiredModuleOutcome,
    RiskEvaluatedPayload, RiskFindingEvidence, RiskSeverity, SimulationCompletedPayload,
};
use atf_core::Timestamp;
use atf_decision::Decision;
use atf_policy::PolicyDecision;
use atf_store::{AdmissionInput, EvaluationInput, FinalizationInput, StoreError};
use std::time::Duration;

use crate::error::ApiError;
use crate::request_id::RequestId;
use crate::state::AppState;

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/intents", post(create_intent))
        .route("/v1/intents/{intent_id}/decision", get(get_decision))
        .fallback(route_not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
        .layer(middleware::from_fn(crate::request_id::assign))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
) -> Response {
    match state.store.check_ready().await {
        Ok(()) => (StatusCode::OK, "ready").into_response(),
        Err(_) => {
            tracing::warn!(
                request_id = request_id.as_str(),
                error_code = "DURABLE_STATE_UNAVAILABLE",
                "Gateway readiness check failed"
            );
            (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
        }
    }
}

/// `POST /v1/intents` (PRD §22.1): validate, evaluate, and record a
/// Transaction Intent, then return the resulting Decision. This never
/// executes anything — there is no execution path in this repo at all yet
/// (PRD §22, last line: execution is off by default and this gateway
/// doesn't even have the flag to turn it on).
async fn create_intent(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(rejection) => {
            return ApiError::body_rejection(rejection.status()).into_response(&request_id)
        }
    };
    let raw = match std::str::from_utf8(&body) {
        Ok(raw) => raw,
        Err(_) => return ApiError::invalid_utf8().into_response(&request_id),
    };

    let intent = match atf_intent::validate(raw) {
        Ok(intent) => intent,
        Err(error) => return ApiError::from_intent(error).into_response(&request_id),
    };

    let admitted = match state
        .store
        .admit_intent(AdmissionInput {
            intent: intent.clone(),
            received_at: Timestamp::now(),
            lease_duration: Duration::from_secs(30),
        })
        .await
    {
        Ok(admitted) => admitted,
        Err(error) => return store_error_response(&request_id, "admit Intent", error),
    };

    let policy_result = state.policy_bundle.evaluate(&intent);
    let policy_evidence = match &policy_result {
        Ok(outcome) => PolicyEvaluatedPayload {
            outcome: RequiredModuleOutcome::Succeeded {
                result: match outcome.decision {
                    PolicyDecision::Permit => PolicyOutcome::Permit,
                    PolicyDecision::Forbid => PolicyOutcome::Forbid,
                },
            },
            policy_ids: outcome.policy_ids.clone(),
        },
        Err(_) => {
            tracing::warn!(
                request_id = request_id.as_str(),
                error_code = "POLICY_EVALUATION_ERROR",
                "Policy evaluation failed closed"
            );
            PolicyEvaluatedPayload {
                outcome: RequiredModuleOutcome::Error {
                    error_code: "POLICY_EVALUATION_ERROR".into(),
                },
                policy_ids: Vec::new(),
            }
        }
    };

    // PRD §10.1.2: a forbidden/errored request never reaches Risk scoring.
    let (risk_findings, risk_evidence) = match &policy_result {
        Ok(outcome) if outcome.decision == PolicyDecision::Permit => {
            let chain = match state
                .store
                .load_verified_audit_chain(&intent.principal.organization_id)
                .await
            {
                Ok(chain) => chain,
                Err(error) => return store_error_response(&request_id, "load Risk history", error),
            };
            let findings = atf_risk::evaluate_with_events(
                &intent,
                &state.risk_config,
                chain.iter().map(|stored| &stored.event),
            );
            let evidence = findings
                .iter()
                .map(|finding| RiskFindingEvidence {
                    code: finding.code.clone(),
                    severity: match finding.severity {
                        atf_risk::Severity::Info => RiskSeverity::Info,
                        atf_risk::Severity::Medium => RiskSeverity::Medium,
                        atf_risk::Severity::High => RiskSeverity::High,
                        atf_risk::Severity::Critical => RiskSeverity::Critical,
                    },
                })
                .collect();
            (
                findings,
                RiskEvaluatedPayload {
                    outcome: OptionalModuleOutcome::Succeeded { result: evidence },
                },
            )
        }
        Ok(_) => (
            Vec::new(),
            RiskEvaluatedPayload {
                outcome: OptionalModuleOutcome::NotRun {
                    reason_code: "POLICY_FORBID".into(),
                },
            },
        ),
        Err(_) => (
            Vec::new(),
            RiskEvaluatedPayload {
                outcome: OptionalModuleOutcome::NotRun {
                    reason_code: "POLICY_ERROR".into(),
                },
            },
        ),
    };

    let decision = atf_decision::decide(&intent, policy_result, &risk_findings);
    let evaluated_at = Timestamp::now();
    let finalized = match state
        .store
        .finalize_decision(FinalizationInput {
            organization_id: intent.principal.organization_id.clone(),
            intent_id: intent.intent_id.clone(),
            evaluator_lease: admitted.evaluator_lease.clone(),
            expected_intent_hash: admitted.admitted.intent_hash.clone(),
            expected_lifecycle_version: admitted.admitted.lifecycle.version,
            evaluation: EvaluationInput {
                evaluation_id: atf_core::new_ulid(),
                evaluated_at,
                policy: policy_evidence,
                risk: risk_evidence,
                simulation: SimulationCompletedPayload {
                    outcome: OptionalModuleOutcome::NotRun {
                        reason_code: "SIMULATOR_NOT_IMPLEMENTED".into(),
                    },
                },
            },
            decision,
            decided_at: Timestamp::now(),
        })
        .await
    {
        Ok(finalized) => finalized,
        Err(error) => return store_error_response(&request_id, "finalize Decision", error),
    };

    Json(finalized.decision).into_response()
}

/// `GET /v1/intents/{intent_id}/decision` (PRD §22.2).
async fn get_decision(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(intent_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Decision>, Response> {
    let organization_id = organization_header(&headers)
        .ok_or_else(|| ApiError::organization_header_invalid().into_response(&request_id))?;
    match state
        .store
        .load_finalized_decision(organization_id, &intent_id)
        .await
    {
        Ok(Some(finalized)) => Ok(Json(finalized.decision)),
        Ok(None) => Err(ApiError::decision_not_found().into_response(&request_id)),
        Err(error) => Err(store_error_response(&request_id, "load Decision", error)),
    }
}

fn organization_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-atf-organization-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.trim() == *value && value.len() <= 128)
}

fn store_error_response(
    request_id: &RequestId,
    operation: &'static str,
    error: StoreError,
) -> Response {
    let api_error = ApiError::from_store(error);
    tracing::warn!(
        request_id = request_id.as_str(),
        operation,
        error_code = api_error.code(),
        "durable Gateway operation failed"
    );
    api_error.into_response(request_id)
}

async fn route_not_found(Extension(request_id): Extension<RequestId>) -> Response {
    ApiError::route_not_found().into_response(&request_id)
}

async fn method_not_allowed(Extension(request_id): Extension<RequestId>) -> Response {
    ApiError::method_not_allowed().into_response(&request_id)
}
