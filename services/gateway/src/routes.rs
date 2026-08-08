use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::rejection::JsonRejection;
use axum::extract::{Extension, Path, State};
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use atf_audit::{
    OptionalModuleOutcome, PolicyEvaluatedPayload, PolicyOutcome, RequiredModuleOutcome,
    RiskEvaluatedPayload, RiskFindingEvidence, RiskSeverity, SimulationCompletedPayload,
};
use atf_core::Timestamp;
use atf_decision::{Decision, DecisionKind, Reason};
use atf_intent::TransactionIntent;
use atf_policy::PolicyDecision;
use atf_store::{
    AdmissionGrant, AdmittedIntent, AuthenticatedAdmissionInput, EvaluationInput, EvaluatorLease,
    FinalizationInput, OperatorPrincipal, Store, StoreError,
};
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::auth::{has_identity_headers, parse_identity_assertion};
use crate::error::ApiError;
use crate::principal::{AgentPrincipal, RequestPrincipal};
use crate::request_id::RequestId;
use crate::state::AppState;

const EVALUATOR_LEASE_DURATION: Duration = Duration::from_secs(30);

enum AdmissionOutcome {
    Evaluate(Box<AdmissionGrant>),
    Completed(Decision),
}

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/intents", post(create_intent))
        .route("/v1/intents/{intent_id}/decision", get(get_decision))
        .route(
            "/v1/policy-bundles/{bundle_id}/activate",
            post(activate_policy_bundle),
        )
        .route(
            "/v1/policy-bundles/{bundle_id}/rollback",
            post(rollback_policy_bundle),
        )
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
    let (store_ready, auth_ready) =
        tokio::join!(state.store.check_ready(), state.operator_auth.check_ready());
    match (store_ready, auth_ready) {
        (Ok(()), Ok(())) => (StatusCode::OK, "ready").into_response(),
        _ => {
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
    headers: HeaderMap,
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

    if headers.contains_key(AUTHORIZATION) {
        let reason_code = "IDENTITY_PRINCIPAL_TYPE_MISMATCH";
        if let Err(store_error) = state
            .store
            .record_identity_rejection(&intent, reason_code, Timestamp::now_millis())
            .await
        {
            return store_error_response(&request_id, "record identity rejection", store_error);
        }
        return ApiError::authentication_required().into_response(&request_id);
    }

    let identity_assertion = match parse_identity_assertion(&headers) {
        Ok(assertion) => assertion,
        Err(error) => {
            let reason_code = error.code();
            if let Err(store_error) = state
                .store
                .record_identity_rejection(&intent, reason_code, Timestamp::now_millis())
                .await
            {
                return store_error_response(&request_id, "record identity rejection", store_error);
            }
            return ApiError::identity_rejected(reason_code).into_response(&request_id);
        }
    };

    let admitted = match admit_or_recover(
        &state.store,
        intent.clone(),
        identity_assertion,
        state.identity.audience(),
        state.identity.environment(),
    )
    .await
    {
        Ok(AdmissionOutcome::Evaluate(admitted)) => *admitted,
        Ok(AdmissionOutcome::Completed(decision)) => {
            return Json(decision).into_response();
        }
        Err(error) => return store_error_response(&request_id, "admit or recover Intent", error),
    };
    let principal = RequestPrincipal::Agent(AgentPrincipal::from_admission(&admitted));
    let agent_principal = principal
        .into_agent()
        .expect("Agent admission constructs only an Agent Principal");
    debug_assert_eq!(
        agent_principal.organization_id,
        intent.principal.organization_id
    );
    debug_assert_eq!(agent_principal.agent_id, intent.principal.agent_id);
    debug_assert_eq!(agent_principal.intent_hash, admitted.admitted.intent_hash);
    debug_assert_eq!(agent_principal.key_id, admitted.admitted.identity.key_id);
    debug_assert_eq!(
        agent_principal.envelope_hash,
        admitted.admitted.identity.envelope_hash
    );

    let evaluated_at = Timestamp::now_millis();
    let policy_result = state.evaluate_policy(&intent, evaluated_at).await;
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
    let mut evaluator_lease = match state
        .store
        .renew_evaluator_lease(&admitted.evaluator_lease, EVALUATOR_LEASE_DURATION)
        .await
    {
        Ok(evaluator_lease) => evaluator_lease,
        Err(error) => {
            return store_error_response(&request_id, "renew evaluator lease after Policy", error)
        }
    };

    // PRD §10.1.2: a forbidden/errored request never reaches Risk scoring.
    let (risk_findings, risk_evidence) = match &policy_result {
        Ok(outcome) if outcome.decision == PolicyDecision::Permit => {
            let chain = match state
                .store
                .load_verified_audit_chain(&agent_principal.organization_id)
                .await
            {
                Ok(chain) => chain,
                Err(error) => return store_error_response(&request_id, "load Risk history", error),
            };
            let result = atf_risk::evaluate_with_events_at(
                &intent,
                &state.risk_rule_set,
                chain.iter().map(|stored| &stored.event),
                evaluated_at,
            );
            let evidence = result
                .findings
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
                result.findings,
                RiskEvaluatedPayload {
                    risk_rule_set_version: Some(result.rule_set_version),
                    risk_rule_set_hash: Some(result.rule_set_hash),
                    outcome: OptionalModuleOutcome::Succeeded { result: evidence },
                },
            )
        }
        Ok(_) => (
            Vec::new(),
            RiskEvaluatedPayload {
                risk_rule_set_version: Some(state.risk_rule_set.version().into()),
                risk_rule_set_hash: Some(state.risk_rule_set.rule_set_hash().into()),
                outcome: OptionalModuleOutcome::NotRun {
                    reason_code: "POLICY_FORBID".into(),
                },
            },
        ),
        Err(_) => (
            Vec::new(),
            RiskEvaluatedPayload {
                risk_rule_set_version: Some(state.risk_rule_set.version().into()),
                risk_rule_set_hash: Some(state.risk_rule_set.rule_set_hash().into()),
                outcome: OptionalModuleOutcome::NotRun {
                    reason_code: "POLICY_ERROR".into(),
                },
            },
        ),
    };
    evaluator_lease = match state
        .store
        .renew_evaluator_lease(&evaluator_lease, EVALUATOR_LEASE_DURATION)
        .await
    {
        Ok(evaluator_lease) => evaluator_lease,
        Err(error) => {
            return store_error_response(&request_id, "renew evaluator lease after Risk", error)
        }
    };

    let decision = atf_decision::decide(&intent, policy_result, &risk_findings);
    let finalized = match state
        .store
        .finalize_decision(FinalizationInput {
            organization_id: intent.principal.organization_id.clone(),
            intent_id: intent.intent_id.clone(),
            evaluator_lease,
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
            decided_at: Timestamp::now_millis(),
        })
        .await
    {
        Ok(finalized) => finalized,
        Err(error) => return store_error_response(&request_id, "finalize Decision", error),
    };

    Json(finalized.decision).into_response()
}

async fn admit_or_recover(
    store: &Store,
    intent: TransactionIntent,
    identity: crate::auth::IdentityAssertion,
    audience: &str,
    environment: &str,
) -> Result<AdmissionOutcome, StoreError> {
    match store
        .authenticate_and_admit(AuthenticatedAdmissionInput {
            intent: intent.clone(),
            envelope: identity.envelope,
            signature: identity.signature,
            audience: audience.to_owned(),
            environment: environment.to_owned(),
            received_at: Timestamp::now_millis(),
            lease_duration: EVALUATOR_LEASE_DURATION,
        })
        .await
    {
        Ok(admitted) => Ok(AdmissionOutcome::Evaluate(Box::new(admitted))),
        Err(StoreError::IdempotencyCompleted {
            organization_id,
            intent_id,
            decision_id,
            ..
        }) => load_completed_decision(store, &organization_id, &intent_id, &decision_id).await,
        Err(StoreError::IdempotencyInProgress { .. }) => {
            recover_expired_intent(store, &intent).await
        }
        Err(error) => Err(error),
    }
}

async fn recover_expired_intent(
    store: &Store,
    intent: &TransactionIntent,
) -> Result<AdmissionOutcome, StoreError> {
    let organization_id = &intent.principal.organization_id;
    let intent_hash = intent.canonical_hash();
    let evaluator_lease = match store
        .reclaim_expired_idempotency(
            organization_id,
            &intent.idempotency_key,
            &intent_hash,
            EVALUATOR_LEASE_DURATION,
        )
        .await
    {
        Ok(evaluator_lease) => evaluator_lease,
        Err(StoreError::IdempotencyCompleted {
            intent_id,
            decision_id,
            ..
        }) => {
            return load_completed_decision(store, organization_id, &intent_id, &decision_id).await;
        }
        Err(error) => return Err(error),
    };
    let admitted = store
        .load_admitted_intent(organization_id, &intent.intent_id)
        .await?
        .ok_or_else(|| StoreError::IncompleteAdmissionEvidence {
            organization_id: organization_id.clone(),
            intent_id: intent.intent_id.clone(),
        })?;
    if admitted.intent_hash != intent_hash {
        return Err(StoreError::IntentHashMismatch {
            organization_id: organization_id.clone(),
            intent_id: intent.intent_id.clone(),
            expected: intent_hash,
            stored: admitted.intent_hash,
        });
    }
    let evaluator_lease = store
        .renew_evaluator_lease(&evaluator_lease, EVALUATOR_LEASE_DURATION)
        .await?;
    let finalized = store
        .finalize_decision(recovery_finalization(admitted, evaluator_lease))
        .await?;
    Ok(AdmissionOutcome::Completed(finalized.decision))
}

async fn load_completed_decision(
    store: &Store,
    organization_id: &str,
    intent_id: &str,
    decision_id: &str,
) -> Result<AdmissionOutcome, StoreError> {
    match store
        .load_finalized_decision(organization_id, intent_id)
        .await?
    {
        Some(finalized) if finalized.decision.decision_id == decision_id => {
            Ok(AdmissionOutcome::Completed(finalized.decision))
        }
        _ => Err(StoreError::IncompleteDecisionEvidence {
            organization_id: organization_id.to_owned(),
            intent_id: intent_id.to_owned(),
        }),
    }
}

fn recovery_finalization(
    admitted: AdmittedIntent,
    evaluator_lease: EvaluatorLease,
) -> FinalizationInput {
    let evaluated_at = Timestamp::now_millis();
    FinalizationInput {
        organization_id: admitted.organization_id,
        intent_id: admitted.intent.intent_id.clone(),
        expected_intent_hash: admitted.intent_hash,
        expected_lifecycle_version: admitted.lifecycle.version,
        evaluator_lease,
        evaluation: EvaluationInput {
            evaluation_id: atf_core::new_ulid(),
            evaluated_at,
            policy: PolicyEvaluatedPayload {
                outcome: RequiredModuleOutcome::Error {
                    error_code: "RECOVERY_CONTEXT_UNAVAILABLE".into(),
                },
                policy_ids: Vec::new(),
            },
            risk: RiskEvaluatedPayload {
                risk_rule_set_version: None,
                risk_rule_set_hash: None,
                outcome: OptionalModuleOutcome::NotRun {
                    reason_code: "POLICY_ERROR".into(),
                },
            },
            simulation: SimulationCompletedPayload {
                outcome: OptionalModuleOutcome::NotRun {
                    reason_code: "RECOVERY_CONTEXT_UNAVAILABLE".into(),
                },
            },
        },
        decision: Decision {
            decision_id: atf_core::new_ulid(),
            intent_id: admitted.intent.intent_id,
            decision: DecisionKind::Error,
            reasons: vec![Reason {
                code: "RECOVERY_CONTEXT_UNAVAILABLE".into(),
                severity: "critical".into(),
                message: "Recovery failed closed because pinned evaluation context is unavailable."
                    .into(),
            }],
        },
        decided_at: Timestamp::now_millis(),
    }
}

/// `GET /v1/intents/{intent_id}/decision` (PRD §22.2).
async fn get_decision(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(intent_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Decision>, Response> {
    let principal = authenticate_operator(&state, &headers, &request_id).await?;
    if !principal.roles.iter().any(|role| role.can_read_decisions()) {
        return Err(ApiError::decision_not_found().into_response(&request_id));
    }
    match state
        .store
        .load_finalized_decision(&principal.organization_id, &intent_id)
        .await
    {
        Ok(Some(finalized)) => Ok(Json(finalized.decision)),
        Ok(None) => Err(ApiError::decision_not_found().into_response(&request_id)),
        Err(error) => Err(store_error_response(&request_id, "load Decision", error)),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivatePolicyRequest {
    environment: String,
    policy_version: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackPolicyRequest {
    environment: String,
}

#[derive(Debug, Serialize)]
struct PolicyMutationResponse {
    bundle_id: String,
    policy_version: String,
    bundle_hash: String,
    lifecycle_version: i64,
    audit_event_id: String,
}

async fn activate_policy_bundle(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(bundle_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<ActivatePolicyRequest>, JsonRejection>,
) -> Result<Json<PolicyMutationResponse>, Response> {
    let principal = authenticate_policy_operator(&state, &headers, &request_id).await?;
    let Json(body) = body.map_err(|_| ApiError::invalid_json().into_response(&request_id))?;
    let active = state
        .store
        .activate_policy_bundle(
            &principal.organization_id,
            &body.environment,
            &bundle_id,
            &body.policy_version,
            &principal.operator_id,
            Timestamp::now_millis(),
        )
        .await
        .map_err(|error| policy_mutation_error(&request_id, error))?;
    Ok(Json(policy_mutation_response(active)))
}

async fn rollback_policy_bundle(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(bundle_id): Path<String>,
    headers: HeaderMap,
    body: Result<Json<RollbackPolicyRequest>, JsonRejection>,
) -> Result<Json<PolicyMutationResponse>, Response> {
    let principal = authenticate_policy_operator(&state, &headers, &request_id).await?;
    let Json(body) = body.map_err(|_| ApiError::invalid_json().into_response(&request_id))?;
    let active = state
        .store
        .rollback_policy_bundle(
            &principal.organization_id,
            &body.environment,
            &bundle_id,
            &principal.operator_id,
            Timestamp::now_millis(),
        )
        .await
        .map_err(|error| policy_mutation_error(&request_id, error))?;
    Ok(Json(policy_mutation_response(active)))
}

async fn authenticate_policy_operator(
    state: &AppState,
    headers: &HeaderMap,
    request_id: &RequestId,
) -> Result<OperatorPrincipal, Response> {
    let principal = authenticate_operator(state, headers, request_id).await?;
    if principal.roles.iter().any(|role| role.can_change_policy()) {
        Ok(principal)
    } else {
        Err(ApiError::policy_bundle_not_found().into_response(request_id))
    }
}

async fn authenticate_operator(
    state: &AppState,
    headers: &HeaderMap,
    request_id: &RequestId,
) -> Result<OperatorPrincipal, Response> {
    if has_identity_headers(headers) {
        return Err(ApiError::authentication_required().into_response(request_id));
    }
    let verified = state
        .operator_auth
        .verify(headers)
        .await
        .map_err(|_| ApiError::authentication_required().into_response(request_id))?;
    let organization_id = organization_header(headers)
        .ok_or_else(|| ApiError::organization_header_invalid().into_response(request_id))?;
    let principal = state
        .store
        .resolve_operator_principal(
            &verified.issuer_id,
            &verified.subject_fingerprint,
            organization_id,
        )
        .await
        .map_err(|error| store_error_response(request_id, "resolve Operator", error))?
        .ok_or_else(|| ApiError::authentication_required().into_response(request_id))?;
    let principal = RequestPrincipal::Operator(principal)
        .into_operator()
        .expect("Operator authentication constructs only an Operator Principal");
    if principal.organization_id != organization_id {
        return Err(ApiError::authentication_required().into_response(request_id));
    }
    Ok(principal)
}

fn policy_mutation_response(active: atf_store::ActivePolicyBundle) -> PolicyMutationResponse {
    PolicyMutationResponse {
        bundle_id: active.bundle.bundle_id().into(),
        policy_version: active.bundle.policy_version().into(),
        bundle_hash: active.bundle.bundle_hash().into(),
        lifecycle_version: active.lifecycle_version,
        audit_event_id: active.last_event_id,
    }
}

fn policy_mutation_error(request_id: &RequestId, error: StoreError) -> Response {
    if matches!(error, StoreError::InvalidRepositoryInput { .. }) {
        return ApiError::invalid_json().into_response(request_id);
    }
    if matches!(
        error,
        StoreError::PolicyAuthorizationDenied { .. }
            | StoreError::PolicyBundleNotFound { .. }
            | StoreError::ActivePolicyBundleNotFound { .. }
            | StoreError::PolicyRollbackUnavailable { .. }
    ) {
        ApiError::policy_bundle_not_found().into_response(request_id)
    } else {
        store_error_response(request_id, "change active Policy Bundle", error)
    }
}

fn organization_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("x-atf-organization-id")
        .and_then(|value| value.to_str().ok())
        .filter(|value| {
            (1..=128).contains(&value.len())
                && value.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-')
                })
        })
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
