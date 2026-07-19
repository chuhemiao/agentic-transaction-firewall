use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;

use atf_audit::EventType;
use atf_decision::Decision;
use atf_policy::PolicyDecision;

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

/// Always ready today: every dependency is in-memory. A persistent-store
/// version of this service would check that store's connectivity here
/// instead (PRD §22.9).
async fn readyz() -> &'static str {
    "ready"
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

    {
        let mut ledger = state
            .audit_ledger
            .lock()
            .expect("audit ledger lock poisoned");
        ledger.append(
            EventType::IntentReceived,
            Some(intent.intent_id.clone()),
            serde_json::json!({ "idempotency_key": intent.idempotency_key }),
        );
    }

    let policy_result = state.policy_bundle.evaluate(&intent);
    {
        let data = match &policy_result {
            Ok(outcome) => serde_json::json!({
                "decision": format!("{:?}", outcome.decision),
                "policy_ids": outcome.policy_ids,
            }),
            Err(err) => serde_json::json!({ "error": err.to_string() }),
        };
        let mut ledger = state
            .audit_ledger
            .lock()
            .expect("audit ledger lock poisoned");
        ledger.append(
            EventType::PolicyEvaluated,
            Some(intent.intent_id.clone()),
            data,
        );
    }

    // PRD §10.1.2: a forbidden/errored request never reaches Risk scoring.
    let risk_findings = match &policy_result {
        Ok(outcome) if outcome.decision == PolicyDecision::Permit => {
            atf_risk::evaluate(&intent, &state.risk_config)
        }
        _ => Vec::new(),
    };
    {
        let mut ledger = state
            .audit_ledger
            .lock()
            .expect("audit ledger lock poisoned");
        ledger.append(
            EventType::RiskEvaluated,
            Some(intent.intent_id.clone()),
            serde_json::json!({ "findings": risk_findings }),
        );
    }

    let decision = atf_decision::decide(&intent, policy_result, &risk_findings);

    state
        .decisions
        .lock()
        .expect("decisions map lock poisoned")
        .insert(intent.intent_id.clone(), decision.clone());

    Json(decision).into_response()
}

/// `GET /v1/intents/{intent_id}/decision` (PRD §22.2).
async fn get_decision(
    State(state): State<AppState>,
    Path(intent_id): Path<String>,
) -> Result<Json<Decision>, Response> {
    state
        .decisions
        .lock()
        .expect("decisions map lock poisoned")
        .get(&intent_id)
        .cloned()
        .map(Json)
        .ok_or_else(|| {
            error_response(
                StatusCode::NOT_FOUND,
                format!("no decision recorded for intent `{intent_id}`"),
            )
        })
}
