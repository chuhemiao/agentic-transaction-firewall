use axum::body::Bytes;
use axum::extract::rejection::BytesRejection;
use axum::extract::rejection::JsonRejection;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, Path, Query, State};
use axum::http::{header::AUTHORIZATION, HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use atf_audit::{
    AuditEvent, EventType, OptionalModuleOutcome, PolicyEvaluatedPayload, PolicyOutcome,
    RequiredModuleOutcome, RiskEvaluatedPayload, RiskFindingEvidence, RiskSeverity,
    SimulationCompletedPayload,
};
use atf_core::{
    EvaluationContext, EvaluationContextInput, EvidenceTrustPolicyReference,
    ExternalSnapshotReference, RepositorySnapshot, SimulationReference, Timestamp,
    VersionedArtifactReference,
};
use atf_decision::Decision;
use atf_intent::{validate_profile, TransactionIntent};
use atf_policy::PolicyDecision;
use atf_store::{
    AdmissionGrant, AdmittedIntent, AuditQuery, AuditQueryPage, AuthenticatedAdmissionInput,
    EvaluationContextPersistence, EvaluationInput, EvaluatorLease, FinalizationInput,
    FinalizedDecision, OperatorPrincipal, Store, StoreError, DEFAULT_AUDIT_QUERY_PAGE_SIZE,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use std::time::Instant;

use crate::auth::{has_identity_headers, parse_identity_assertion};
use crate::error::ApiError;
use crate::principal::{AgentPrincipal, RequestPrincipal};
use crate::request_id::RequestId;
use crate::state::AppState;
use crate::telemetry::{
    AuditOperation, IdempotencyOutcome, PolicyOutcomeLabel, RiskOutcomeLabel, SeverityLabel,
};

const EVALUATOR_LEASE_DURATION: Duration = Duration::from_secs(30);
const MAX_AUDIT_CURSOR_BYTES: usize = 2_048;
const MAX_AUDIT_CURSOR_DECODED_BYTES: usize = 1_024;

enum AdmissionOutcome {
    Evaluate(Box<AdmissionGrant>),
    ExactRetry(Box<Decision>),
    Recovered(Box<FinalizedDecision>),
}

pub fn build_router(state: AppState) -> Router {
    let telemetry = state.telemetry.clone();
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/v1/intents", post(create_intent))
        .route("/v1/intents/{intent_id}/decision", get(get_decision))
        .route("/v1/audit/events", get(query_audit_events))
        .route(
            "/v1/audit/intents/{intent_id}",
            get(query_intent_audit_events),
        )
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
        .layer(middleware::from_fn_with_state(
            telemetry,
            crate::request_id::assign,
        ))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn metrics(State(state): State<AppState>) -> Response {
    let replay_counts = match state.store.durable_replay_counts().await {
        Ok(counts) => Some(counts),
        Err(_) => {
            state
                .telemetry
                .record_audit_failure(AuditOperation::ReadVerification);
            tracing::warn!(
                event_name = "telemetry.replay_snapshot.unavailable",
                error_code = "DURABLE_STATE_UNAVAILABLE",
                "Durable replay telemetry snapshot was unavailable"
            );
            None
        }
    };
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.telemetry.render_prometheus(replay_counts),
    )
        .into_response()
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
            if is_audit_failure(&store_error) {
                state
                    .telemetry
                    .record_audit_failure(AuditOperation::AdmissionWrite);
            }
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
                if is_audit_failure(&store_error) {
                    state
                        .telemetry
                        .record_audit_failure(AuditOperation::AdmissionWrite);
                }
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
        Ok(AdmissionOutcome::Evaluate(admitted)) => {
            state
                .telemetry
                .record_idempotency(IdempotencyOutcome::NewEvaluation);
            *admitted
        }
        Ok(AdmissionOutcome::ExactRetry(decision)) => {
            state
                .telemetry
                .record_idempotency(IdempotencyOutcome::ExactRetry);
            return Json(decision).into_response();
        }
        Ok(AdmissionOutcome::Recovered(finalized)) => {
            state
                .telemetry
                .record_idempotency(IdempotencyOutcome::Recovered);
            state.telemetry.record_decision(finalized.decision.decision);
            tracing::info!(
                event_name = "decision.recovery_finalized",
                audit_event_id = finalized.audit_event.event.event_id,
                decision_kind = ?finalized.decision.decision,
                "Recovered Intent finalized with durable Audit evidence"
            );
            return Json(finalized.decision).into_response();
        }
        Err(error) => {
            if matches!(error, StoreError::IdempotencyConflict { .. }) {
                state
                    .telemetry
                    .record_idempotency(IdempotencyOutcome::Conflict);
            } else if matches!(error, StoreError::IdempotencyInProgress { .. }) {
                state
                    .telemetry
                    .record_idempotency(IdempotencyOutcome::InProgress);
            }
            if is_audit_failure(&error) {
                state
                    .telemetry
                    .record_audit_failure(AuditOperation::AdmissionWrite);
            }
            return store_error_response(&request_id, "admit or recover Intent", error);
        }
    };
    tracing::info!(
        event_name = "intent.admitted",
        audit_event_id = admitted.admitted.audit_event.event.event_id,
        "Intent admitted with durable Audit evidence"
    );
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
    let evaluation_id = atf_core::new_ulid();
    let resolved_policy = state.resolve_policy(&intent, evaluated_at).await;
    let history = match state
        .store
        .capture_risk_history(&intent, &state.risk_rule_set, evaluated_at)
        .await
    {
        Ok(history) => history,
        Err(error) => return store_error_response(&request_id, "load Evaluation history", error),
    };
    let evaluation_context = match build_evaluation_context(
        &state,
        &intent,
        &evaluation_id,
        evaluated_at,
        resolved_policy
            .as_ref()
            .ok()
            .map(|resolved| resolved.bundle()),
        history.repository(),
    ) {
        Ok(context) => context,
        Err(error) => return store_error_response(&request_id, "build Evaluation Context", error),
    };
    let freshness: Vec<_> = evaluation_context
        .evidence_envelopes()
        .map(|evidence| evidence.freshness_at(evaluated_at))
        .collect();
    state.telemetry.record_freshness(&freshness);
    if let Err(error) = state
        .store
        .persist_evaluation_context(EvaluationContextPersistence {
            organization_id: agent_principal.organization_id.clone(),
            expected_intent_hash: admitted.admitted.intent_hash.clone(),
            evaluator_lease: admitted.evaluator_lease.clone(),
            context: evaluation_context.clone(),
        })
        .await
    {
        if is_audit_failure(&error) {
            state
                .telemetry
                .record_audit_failure(AuditOperation::ContextWrite);
        }
        return store_error_response(&request_id, "persist Evaluation Context", error);
    }

    let policy_started = Instant::now();
    let policy_result = match &resolved_policy {
        Ok(policy) => policy.evaluate(&intent, &evaluation_context),
        Err(_) => Err(atf_policy::PolicyError::Unavailable),
    };
    let policy_metric_outcome = match &policy_result {
        Ok(outcome) if outcome.decision == PolicyDecision::Permit => PolicyOutcomeLabel::Permit,
        Ok(_) => PolicyOutcomeLabel::Forbid,
        Err(_) => PolicyOutcomeLabel::Error,
    };
    state.telemetry.record_policy(
        policy_metric_outcome,
        policy_result
            .as_ref()
            .map_or(0, |outcome| outcome.policy_ids.len()),
        policy_started.elapsed(),
    );
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
    let risk_started = Instant::now();
    let (risk_evaluation, risk_evidence, risk_error) = match &policy_result {
        Ok(outcome) if outcome.decision == PolicyDecision::Permit => {
            let result = atf_risk::evaluate_context(
                &intent,
                &state.risk_rule_set,
                &evaluation_context,
                &history,
            );
            match result {
                Ok(result) => {
                    state.telemetry.record_risk(
                        RiskOutcomeLabel::Succeeded,
                        risk_started.elapsed(),
                        result
                            .findings
                            .iter()
                            .map(|finding| match finding.severity {
                                atf_risk::Severity::Info => SeverityLabel::Info,
                                atf_risk::Severity::Medium => SeverityLabel::Medium,
                                atf_risk::Severity::High => SeverityLabel::High,
                                atf_risk::Severity::Critical => SeverityLabel::Critical,
                            }),
                    );
                    let rule_set_version = result.rule_set_version.clone();
                    let rule_set_hash = result.rule_set_hash.clone();
                    let risk_history = result.history.clone();
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
                        Some(result),
                        RiskEvaluatedPayload {
                            risk_rule_set_version: Some(rule_set_version),
                            risk_rule_set_hash: Some(rule_set_hash),
                            history: Some(risk_history),
                            outcome: OptionalModuleOutcome::Succeeded { result: evidence },
                        },
                        None,
                    )
                }
                Err(error) => {
                    state.telemetry.record_risk(
                        RiskOutcomeLabel::Error,
                        risk_started.elapsed(),
                        std::iter::empty(),
                    );
                    tracing::warn!(
                        request_id = request_id.as_str(),
                        error_code = error.code(),
                        "Risk evaluation failed closed"
                    );
                    (
                        None,
                        RiskEvaluatedPayload {
                            risk_rule_set_version: Some(state.risk_rule_set.version().into()),
                            risk_rule_set_hash: Some(state.risk_rule_set.rule_set_hash().into()),
                            history: Some(history.clone()),
                            outcome: OptionalModuleOutcome::Error {
                                error_code: error.code().into(),
                            },
                        },
                        Some(error),
                    )
                }
            }
        }
        Ok(_) => {
            state.telemetry.record_risk(
                RiskOutcomeLabel::NotRun,
                risk_started.elapsed(),
                std::iter::empty(),
            );
            (
                None,
                RiskEvaluatedPayload {
                    risk_rule_set_version: Some(state.risk_rule_set.version().into()),
                    risk_rule_set_hash: Some(state.risk_rule_set.rule_set_hash().into()),
                    history: None,
                    outcome: OptionalModuleOutcome::NotRun {
                        reason_code: "POLICY_FORBID".into(),
                    },
                },
                None,
            )
        }
        Err(_) => {
            state.telemetry.record_risk(
                RiskOutcomeLabel::NotRun,
                risk_started.elapsed(),
                std::iter::empty(),
            );
            (
                None,
                RiskEvaluatedPayload {
                    risk_rule_set_version: Some(state.risk_rule_set.version().into()),
                    risk_rule_set_hash: Some(state.risk_rule_set.rule_set_hash().into()),
                    history: None,
                    outcome: OptionalModuleOutcome::NotRun {
                        reason_code: "POLICY_ERROR".into(),
                    },
                },
                None,
            )
        }
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

    let policy_input = match &policy_result {
        Ok(outcome) => atf_decision::PolicyDecisionInput::Evaluated(outcome),
        Err(_) => atf_decision::PolicyDecisionInput::Error {
            error_code: "POLICY_EVALUATION_ERROR",
        },
    };
    let risk_input = match (
        risk_evaluation.as_ref(),
        risk_error.as_ref(),
        &policy_result,
    ) {
        (Some(evaluation), None, _) => atf_decision::RiskDecisionInput::Evaluated(evaluation),
        (None, Some(error), _) => atf_decision::RiskDecisionInput::Error {
            error_code: error.code(),
        },
        (None, None, Ok(_)) => atf_decision::RiskDecisionInput::NotRun {
            reason_code: "POLICY_FORBID",
        },
        (None, None, Err(_)) => atf_decision::RiskDecisionInput::NotRun {
            reason_code: "POLICY_ERROR",
        },
        (Some(_), Some(_), _) => unreachable!("Risk cannot succeed and error"),
    };
    let decision = match atf_decision::decide(atf_decision::DecisionInput {
        decision_id: atf_core::new_ulid(),
        intent: &intent,
        evaluation_context: &evaluation_context,
        policy: policy_input,
        risk: risk_input,
    }) {
        Ok(decision) => decision,
        Err(error) => {
            tracing::error!(
                request_id = request_id.as_str(),
                error_code = error.code(),
                "Decision input binding failed closed"
            );
            return store_error_response(
                &request_id,
                "bind Decision",
                StoreError::InvalidRepositoryInput {
                    reason: error.code().into(),
                },
            );
        }
    };
    let finalized = match state
        .store
        .finalize_decision(FinalizationInput {
            organization_id: intent.principal.organization_id.clone(),
            intent_id: intent.intent_id.clone(),
            evaluator_lease,
            expected_intent_hash: admitted.admitted.intent_hash.clone(),
            expected_lifecycle_version: admitted.admitted.lifecycle.version,
            evaluation: EvaluationInput {
                evaluation_id,
                evaluation_context_hash: evaluation_context.evaluation_context_hash().into(),
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
        Err(error) => {
            if is_audit_failure(&error) {
                state
                    .telemetry
                    .record_audit_failure(AuditOperation::DecisionWrite);
            }
            return store_error_response(&request_id, "finalize Decision", error);
        }
    };

    state.telemetry.record_decision(finalized.decision.decision);
    tracing::info!(
        event_name = "decision.finalized",
        audit_event_id = finalized.audit_event.event.event_id,
        decision_kind = ?finalized.decision.decision,
        "Decision finalized with durable Audit evidence"
    );

    Json(finalized.decision).into_response()
}

fn build_evaluation_context(
    state: &AppState,
    intent: &TransactionIntent,
    evaluation_id: &str,
    evaluation_time: Timestamp,
    policy: Option<&atf_policy::PolicyBundle>,
    history: &RepositorySnapshot,
) -> Result<EvaluationContext, StoreError> {
    let profile = validate_profile(intent).map_err(|error| StoreError::InvalidRepositoryInput {
        reason: format!("validated Intent lost its Profile: {error}"),
    })?;
    let policy = match policy {
        Some(bundle) => VersionedArtifactReference::available(
            bundle.bundle_id(),
            bundle.policy_version(),
            bundle.bundle_hash(),
        )?,
        None => VersionedArtifactReference::unavailable("POLICY_ARTIFACT_UNAVAILABLE")?,
    };
    let risk = VersionedArtifactReference::available(
        state.risk_rule_set.engine_version(),
        state.risk_rule_set.version(),
        state.risk_rule_set.rule_set_hash(),
    )?;
    EvaluationContext::new(EvaluationContextInput {
        evaluation_id: evaluation_id.into(),
        intent_id: intent.intent_id.clone(),
        intent_hash: intent.canonical_hash(),
        evaluation_time,
        environment: state.identity.environment().into(),
        profile_id: profile.id().into(),
        profile_version: profile.version().into(),
        policy,
        risk,
        context_snapshot_id: atf_core::new_ulid(),
        agent_context: intent.context.clone(),
        evidence: Vec::new(),
        evidence_trust_policy: EvidenceTrustPolicyReference::not_configured(
            "TRUST_POLICY_NOT_CONFIGURED",
        )?,
        history: history.clone(),
        market_data: ExternalSnapshotReference::unavailable("MARKET_DATA_SNAPSHOT_UNAVAILABLE")?,
        simulation: SimulationReference::not_run("SIMULATOR_NOT_IMPLEMENTED")?,
    })
    .map_err(StoreError::from)
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
            recover_expired_intent(store, &intent, environment).await
        }
        Err(error) => Err(error),
    }
}

async fn recover_expired_intent(
    store: &Store,
    intent: &TransactionIntent,
    environment: &str,
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
    let context = match store
        .load_evaluation_context_for_intent(organization_id, &intent.intent_id)
        .await?
    {
        Some(stored) => stored.context,
        None => {
            let chain = store.load_verified_audit_chain(organization_id).await?;
            let context = build_recovery_context(intent, environment, &chain)?;
            store
                .persist_evaluation_context(EvaluationContextPersistence {
                    organization_id: organization_id.clone(),
                    expected_intent_hash: admitted.intent_hash.clone(),
                    evaluator_lease: evaluator_lease.clone(),
                    context: context.clone(),
                })
                .await?;
            context
        }
    };
    let evaluator_lease = store
        .renew_evaluator_lease(&evaluator_lease, EVALUATOR_LEASE_DURATION)
        .await?;
    let finalized = store
        .finalize_decision(recovery_finalization(admitted, evaluator_lease, &context))
        .await?;
    Ok(AdmissionOutcome::Recovered(Box::new(finalized)))
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
            Ok(AdmissionOutcome::ExactRetry(Box::new(finalized.decision)))
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
    context: &EvaluationContext,
) -> FinalizationInput {
    let (risk_rule_set_version, risk_rule_set_hash) = context
        .risk()
        .available_parts()
        .map_or((None, None), |(_, version, hash)| {
            (Some(version.into()), Some(hash.into()))
        });
    FinalizationInput {
        organization_id: admitted.organization_id,
        intent_id: admitted.intent.intent_id.clone(),
        expected_intent_hash: admitted.intent_hash,
        expected_lifecycle_version: admitted.lifecycle.version,
        evaluator_lease,
        evaluation: EvaluationInput {
            evaluation_id: context.evaluation_id().into(),
            evaluation_context_hash: context.evaluation_context_hash().into(),
            evaluated_at: context.evaluation_time(),
            policy: PolicyEvaluatedPayload {
                outcome: RequiredModuleOutcome::Error {
                    error_code: "RECOVERY_REPLAY_NOT_IMPLEMENTED".into(),
                },
                policy_ids: Vec::new(),
            },
            risk: RiskEvaluatedPayload {
                risk_rule_set_version,
                risk_rule_set_hash,
                history: None,
                outcome: OptionalModuleOutcome::NotRun {
                    reason_code: "POLICY_ERROR".into(),
                },
            },
            simulation: SimulationCompletedPayload {
                outcome: OptionalModuleOutcome::NotRun {
                    reason_code: context.simulation().reason_code().into(),
                },
            },
        },
        decision: atf_decision::decide(atf_decision::DecisionInput {
            decision_id: atf_core::new_ulid(),
            intent: &admitted.intent,
            evaluation_context: context,
            policy: atf_decision::PolicyDecisionInput::Error {
                error_code: "RECOVERY_REPLAY_NOT_IMPLEMENTED",
            },
            risk: atf_decision::RiskDecisionInput::NotRun {
                reason_code: "POLICY_ERROR",
            },
        })
        .expect("recovery Context is already bound to its admitted Intent"),
        decided_at: Timestamp::now_millis(),
    }
}

fn build_recovery_context(
    intent: &TransactionIntent,
    environment: &str,
    history: &[atf_store::StoredAuditEvent],
) -> Result<EvaluationContext, StoreError> {
    let profile = validate_profile(intent).map_err(|error| StoreError::InvalidRepositoryInput {
        reason: format!("admitted Intent lost its Profile during recovery: {error}"),
    })?;
    let tail = history
        .last()
        .ok_or_else(|| StoreError::IncompleteAdmissionEvidence {
            organization_id: intent.principal.organization_id.clone(),
            intent_id: intent.intent_id.clone(),
        })?;
    let through_sequence =
        u64::try_from(tail.sequence).map_err(|_| StoreError::InvalidRepositoryInput {
            reason: "Audit history sequence cannot be represented by Evaluation Context".into(),
        })?;
    EvaluationContext::new(EvaluationContextInput {
        evaluation_id: atf_core::new_ulid(),
        intent_id: intent.intent_id.clone(),
        intent_hash: intent.canonical_hash(),
        evaluation_time: Timestamp::now_millis(),
        environment: environment.into(),
        profile_id: profile.id().into(),
        profile_version: profile.version().into(),
        policy: VersionedArtifactReference::unavailable("RECOVERY_REPLAY_NOT_IMPLEMENTED")?,
        risk: VersionedArtifactReference::unavailable("RECOVERY_REPLAY_NOT_IMPLEMENTED")?,
        context_snapshot_id: atf_core::new_ulid(),
        agent_context: intent.context.clone(),
        evidence: Vec::new(),
        evidence_trust_policy: EvidenceTrustPolicyReference::not_configured(
            "TRUST_POLICY_NOT_CONFIGURED",
        )?,
        history: RepositorySnapshot::new(
            format!(
                "audit-chain:{}:{through_sequence}",
                intent.principal.organization_id
            ),
            through_sequence,
            tail.event_hash.clone(),
        )?,
        market_data: ExternalSnapshotReference::unavailable("RECOVERY_REPLAY_NOT_IMPLEMENTED")?,
        simulation: SimulationReference::not_run("RECOVERY_REPLAY_NOT_IMPLEMENTED")?,
    })
    .map_err(StoreError::from)
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

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditQueryParameters {
    intent_id: Option<String>,
    agent_id: Option<String>,
    event_type: Option<EventType>,
    occurred_from: Option<Timestamp>,
    occurred_to: Option<Timestamp>,
    limit: Option<u16>,
    cursor: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuditQueryResponse {
    schema_version: u8,
    organization_id: String,
    chain: AuditChainResponse,
    events: Vec<AuditEventResponse>,
    pagination: AuditPaginationResponse,
}

#[derive(Debug, Serialize)]
struct AuditChainResponse {
    status: AuditChainStatus,
    through_sequence: i64,
    through_event_hash: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum AuditChainStatus {
    Verified,
}

#[derive(Debug, Serialize)]
struct AuditEventResponse {
    sequence: i64,
    event_hash: String,
    event: AuditEvent,
    evaluation_id: Option<String>,
    decision_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct AuditPaginationResponse {
    order: &'static str,
    limit: u16,
    next_cursor: Option<String>,
}

async fn query_audit_events(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
    query: Result<Query<AuditQueryParameters>, QueryRejection>,
) -> Result<Json<AuditQueryResponse>, Response> {
    query_audit_events_inner(state, request_id, headers, None, query).await
}

async fn query_intent_audit_events(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(intent_id): Path<String>,
    headers: HeaderMap,
    query: Result<Query<AuditQueryParameters>, QueryRejection>,
) -> Result<Json<AuditQueryResponse>, Response> {
    query_audit_events_inner(state, request_id, headers, Some(intent_id), query).await
}

async fn query_audit_events_inner(
    state: AppState,
    request_id: RequestId,
    headers: HeaderMap,
    path_intent_id: Option<String>,
    query: Result<Query<AuditQueryParameters>, QueryRejection>,
) -> Result<Json<AuditQueryResponse>, Response> {
    let principal = authenticate_operator(&state, &headers, &request_id).await?;
    if !principal.roles.iter().any(|role| role.can_read_audit()) {
        return Err(ApiError::audit_events_not_found().into_response(&request_id));
    }
    let Query(mut parameters) =
        query.map_err(|_| ApiError::audit_query_invalid().into_response(&request_id))?;
    if let Some(intent_id) = path_intent_id {
        if parameters.intent_id.is_some() {
            return Err(ApiError::audit_query_invalid().into_response(&request_id));
        }
        parameters.intent_id = Some(intent_id);
    }
    let cursor = parameters
        .cursor
        .as_deref()
        .map(decode_audit_cursor)
        .transpose()
        .map_err(|_| ApiError::audit_query_invalid().into_response(&request_id))?;
    let query = AuditQuery::new(
        &principal.organization_id,
        parameters.intent_id,
        parameters.agent_id,
        parameters.event_type,
        parameters.occurred_from,
        parameters.occurred_to,
        parameters.limit.unwrap_or(DEFAULT_AUDIT_QUERY_PAGE_SIZE),
        cursor,
    )
    .map_err(|_| ApiError::audit_query_invalid().into_response(&request_id))?;
    let page = state
        .store
        .query_verified_audit_events(&principal.operator_id, query)
        .await
        .map_err(|error| audit_query_error(&state, &request_id, error))?;
    if let (Some(first), Some(last)) = (page.events.first(), page.events.last()) {
        tracing::info!(
            event_name = "audit.page.returned",
            first_audit_event_id = first.event.event_id,
            last_audit_event_id = last.event.event_id,
            event_count = page.events.len(),
            "Verified Audit page returned"
        );
    } else {
        tracing::info!(
            event_name = "audit.page.returned",
            event_count = 0,
            "Verified empty Audit page returned"
        );
    }
    audit_query_response(page)
        .map(Json)
        .map_err(|error| store_error_response(&request_id, "encode Audit query", error))
}

fn decode_audit_cursor(encoded: &str) -> Result<atf_store::AuditQueryCursor, StoreError> {
    if encoded.is_empty()
        || encoded.len() > MAX_AUDIT_CURSOR_BYTES
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "Audit cursor encoding is invalid".into(),
        });
    }
    let bytes =
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| StoreError::InvalidRepositoryInput {
                reason: "Audit cursor encoding is invalid".into(),
            })?;
    if bytes.len() > MAX_AUDIT_CURSOR_DECODED_BYTES {
        return Err(StoreError::InvalidRepositoryInput {
            reason: "Audit cursor is too large".into(),
        });
    }
    atf_store::AuditQueryCursor::from_canonical_bytes(&bytes)
}

fn audit_query_response(page: AuditQueryPage) -> Result<AuditQueryResponse, StoreError> {
    let next_cursor = page
        .next_cursor
        .as_ref()
        .map(|cursor| {
            cursor
                .canonical_bytes()
                .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
        })
        .transpose()?;
    Ok(AuditQueryResponse {
        schema_version: 1,
        organization_id: page.organization_id,
        chain: AuditChainResponse {
            status: AuditChainStatus::Verified,
            through_sequence: page.chain.through_sequence,
            through_event_hash: page.chain.through_event_hash,
        },
        events: page
            .events
            .into_iter()
            .map(|stored| AuditEventResponse {
                sequence: stored.sequence,
                event_hash: stored.event_hash,
                event: stored.event,
                evaluation_id: stored.evaluation_id,
                decision_id: stored.decision_id,
            })
            .collect(),
        pagination: AuditPaginationResponse {
            order: "SEQUENCE_ASC",
            limit: page.limit,
            next_cursor,
        },
    })
}

fn audit_query_error(state: &AppState, request_id: &RequestId, error: StoreError) -> Response {
    if matches!(error, StoreError::InvalidRepositoryInput { .. }) {
        return ApiError::audit_query_invalid().into_response(request_id);
    }
    if matches!(
        error,
        StoreError::AuditReadAuthorizationDenied { .. } | StoreError::OrganizationNotFound { .. }
    ) {
        ApiError::audit_events_not_found().into_response(request_id)
    } else {
        if matches!(
            error,
            StoreError::AuditChainCorrupt { .. }
                | StoreError::DurableStateCorrupt { .. }
                | StoreError::IncompleteAdmissionEvidence { .. }
                | StoreError::IncompleteDecisionEvidence { .. }
        ) {
            state
                .telemetry
                .record_audit_failure(AuditOperation::ReadVerification);
        }
        store_error_response(request_id, "query Audit events", error)
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
        .map_err(|error| policy_mutation_error(&state, &request_id, error))?;
    tracing::info!(
        event_name = "policy.activated",
        audit_event_id = active.last_event_id,
        "Policy activation recorded with durable Audit evidence"
    );
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
        .map_err(|error| policy_mutation_error(&state, &request_id, error))?;
    tracing::info!(
        event_name = "policy.rolled_back",
        audit_event_id = active.last_event_id,
        "Policy rollback recorded with durable Audit evidence"
    );
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
        .map_err(|error| {
            if is_audit_failure(&error) {
                state
                    .telemetry
                    .record_audit_failure(AuditOperation::ReadVerification);
            }
            store_error_response(request_id, "resolve Operator", error)
        })?
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

fn policy_mutation_error(state: &AppState, request_id: &RequestId, error: StoreError) -> Response {
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
        if is_audit_failure(&error) {
            state
                .telemetry
                .record_audit_failure(AuditOperation::PolicyWrite);
        }
        store_error_response(request_id, "change active Policy Bundle", error)
    }
}

fn is_audit_failure(error: &StoreError) -> bool {
    matches!(
        error,
        StoreError::Database(_)
            | StoreError::DurableStateCorrupt { .. }
            | StoreError::IdentityStateCorrupt { .. }
            | StoreError::OperatorStateCorrupt { .. }
            | StoreError::PolicyStateCorrupt { .. }
            | StoreError::RiskStateCorrupt { .. }
            | StoreError::IncompleteAdmissionEvidence { .. }
            | StoreError::IncompleteDecisionEvidence { .. }
            | StoreError::AuditChainCorrupt { .. }
    )
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
