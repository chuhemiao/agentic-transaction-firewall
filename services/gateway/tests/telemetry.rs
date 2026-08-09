//! DS-033 safe Metrics and structured tracing contract through the real
//! Gateway and an isolated PostgreSQL database.

mod support;

use atf_gateway::{build_metrics_router, build_router};
use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use std::error::Error;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use tracing_subscriber::fmt::MakeWriter;

use support::{
    body_json, error_json, operator_authorization, post_intent_request, post_intent_value_request,
    sample_intent_json, test_state, TestDatabase,
};

#[tokio::test]
async fn prometheus_snapshot_uses_only_fixed_labels_for_representative_paths(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("telemetry_metrics").await?;
    let store = database.connect().await?;
    let state = test_state(store.clone());
    let app = build_router(state.clone());
    let metrics_app = build_metrics_router(state);
    let intent_id = "01J0000000000000000000TM01";

    assert_eq!(
        app.clone()
            .oneshot(Request::builder().uri("/healthz").body(Body::empty())?)
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(post_intent_request(intent_id, "12.50"))
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(post_intent_request(intent_id, "12.50"))
            .await?
            .status(),
        StatusCode::OK
    );
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/private/PAYLOAD_SECRET_CANARY?token=CREDENTIAL_CANARY")
                    .body(Body::empty())?,
            )
            .await?
            .status(),
        StatusCode::NOT_FOUND
    );

    let metrics = metrics_text(metrics_app).await?;
    assert!(metrics.contains(
        "atf_gateway_http_requests_total{method=\"GET\",route=\"/healthz\",status_class=\"2xx\"} 1"
    ));
    assert!(metrics.contains(
        "atf_gateway_http_requests_total{method=\"POST\",route=\"/v1/intents\",status_class=\"2xx\"} 2"
    ));
    assert!(metrics.contains(
        "atf_gateway_http_requests_total{method=\"GET\",route=\"UNMATCHED\",status_class=\"4xx\"} 1"
    ));
    assert!(metrics.contains("atf_gateway_decisions_total{kind=\"PERMIT\"} 1"));
    assert!(metrics
        .contains("atf_gateway_policy_evaluation_duration_seconds_count{outcome=\"PERMIT\"} 1"));
    assert!(metrics
        .contains("atf_gateway_risk_evaluation_duration_seconds_count{outcome=\"SUCCEEDED\"} 1"));
    assert!(metrics.contains("atf_gateway_idempotency_requests_total{outcome=\"EXACT_RETRY\"} 1"));
    assert!(metrics.contains("atf_gateway_evidence_freshness_total{state=\"NOT_PROVIDED\"} 1"));
    assert!(metrics.contains("atf_gateway_replays_total{mode=\"ORIGINAL\"} 0"));
    assert!(metrics.contains("atf_gateway_replays_total{mode=\"COUNTERFACTUAL\"} 0"));
    assert!(metrics.contains("atf_gateway_replay_metrics_available 1"));

    for forbidden in [
        "alpha-lab",
        intent_id,
        "PAYLOAD_SECRET_CANARY",
        "CREDENTIAL_CANARY",
        "token=",
        "x-atf-identity-signature",
    ] {
        assert!(
            !metrics.contains(forbidden),
            "Prometheus output leaked forbidden value {forbidden}"
        );
    }

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn verified_audit_read_failures_are_counted_without_tenant_labels(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("telemetry_audit_failure").await?;
    let store = database.connect().await?;
    let state = test_state(store.clone());
    let app = build_router(state.clone());
    let metrics_app = build_metrics_router(state);

    database
        .corrupt_audit_event_for_test("alpha-lab", 1)
        .await?;
    let response = app
        .clone()
        .oneshot(audit_request("/v1/audit/events?limit=10"))
        .await?;
    error_json(
        response,
        StatusCode::INTERNAL_SERVER_ERROR,
        "DURABLE_STATE_INTEGRITY_ERROR",
    )
    .await?;

    let metrics = metrics_text(metrics_app).await?;
    assert!(metrics.contains("atf_gateway_audit_failures_total{operation=\"READ_VERIFICATION\"} 1"));
    assert!(!metrics.contains("alpha-lab"));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn failed_audit_backed_admission_is_counted_and_metrics_remain_scrapeable(
) -> Result<(), Box<dyn Error>> {
    let database = provisioned_database("telemetry_audit_write_failure").await?;
    let store = database.connect().await?;
    let state = test_state(store.clone());
    let app = build_router(state.clone());
    let metrics_app = build_metrics_router(state);
    store.close().await;

    let response = app
        .clone()
        .oneshot(post_intent_request("01J0000000000000000000TM03", "12.50"))
        .await?;
    error_json(
        response,
        StatusCode::SERVICE_UNAVAILABLE,
        "DURABLE_STATE_UNAVAILABLE",
    )
    .await?;

    let metrics = metrics_text(metrics_app).await?;
    assert!(metrics.contains("atf_gateway_audit_failures_total{operation=\"ADMISSION_WRITE\"} 1"));
    assert!(metrics.contains("atf_gateway_replay_metrics_available 0"));

    database.destroy().await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn json_trace_links_request_and_audit_event_without_credentials_or_payload(
) -> Result<(), Box<dyn Error>> {
    let captured = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .without_time()
        .with_current_span(true)
        .with_span_list(true)
        .with_writer(captured.clone())
        .finish();
    tracing::subscriber::set_global_default(subscriber)
        .expect("telemetry integration test owns the process subscriber");

    let database = provisioned_database("telemetry_redaction").await?;
    let store = database.connect().await?;
    let app = build_router(test_state(store.clone()));
    let intent_id = "01J0000000000000000000TM02";
    let mut intent = sample_intent_json(intent_id, "12.50");
    intent["mandate"]["purpose"] = serde_json::json!("PAYLOAD_SECRET_CANARY");
    let request = post_intent_value_request(intent);
    let identity_signature = request
        .headers()
        .get("x-atf-identity-signature")
        .expect("signed request has a signature")
        .to_str()?
        .to_owned();

    assert_eq!(app.clone().oneshot(request).await?.status(), StatusCode::OK);
    let authorization = operator_authorization();
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/audit/events?event_type=DecisionRecorded&limit=10")
                .header("x-atf-organization-id", "alpha-lab")
                .header("authorization", &authorization)
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    let request_id = response
        .headers()
        .get("x-atf-request-id")
        .expect("response has a correlation ID")
        .to_str()?
        .to_owned();
    let body = body_json(response).await?;
    let audit_event_id = body["events"][0]["event"]["event_id"]
        .as_str()
        .expect("Audit response includes its event ID");

    let logs = captured.contents();
    for line in logs.lines().filter(|line| !line.is_empty()) {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|error| panic!("structured log line is not JSON: {error}: {line}"));
    }
    assert!(
        logs.contains("http.request.completed"),
        "captured logs did not include request completion: {logs}"
    );
    assert!(logs.contains(&request_id));
    assert!(logs.contains(audit_event_id));
    assert!(logs.contains("audit.page.returned"));
    for forbidden in [
        "PAYLOAD_SECRET_CANARY",
        authorization.as_str(),
        identity_signature.as_str(),
        "event_type=DecisionRecorded",
        "x-atf-identity-envelope",
        "x-atf-identity-signature",
    ] {
        assert!(
            !logs.contains(forbidden),
            "structured logs leaked forbidden value {forbidden}"
        );
    }

    store.close().await;
    database.destroy().await?;
    Ok(())
}

async fn provisioned_database(label: &str) -> Result<TestDatabase, Box<dyn Error>> {
    let database = TestDatabase::create(label).await?;
    database.seed_organization("alpha-lab").await?;
    Ok(database)
}

async fn metrics_text(app: axum::Router) -> Result<String, Box<dyn Error>> {
    let response = app.oneshot(support::operations_metrics_request()).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .expect("Prometheus response has a content type")
            .to_str()?,
        "text/plain; version=0.0.4; charset=utf-8"
    );
    Ok(String::from_utf8(
        to_bytes(response.into_body(), usize::MAX).await?.to_vec(),
    )?)
}

fn audit_request(uri: &str) -> Request<Body> {
    Request::builder()
        .uri(uri)
        .header("x-atf-organization-id", "alpha-lab")
        .header("authorization", operator_authorization())
        .body(Body::empty())
        .expect("test Audit request is valid")
}

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedLogs {
    fn contents(&self) -> String {
        String::from_utf8(
            self.0
                .lock()
                .expect("captured log lock is not poisoned")
                .clone(),
        )
        .expect("structured logs are UTF-8")
    }
}

impl Write for CapturedLogs {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("captured log lock is poisoned"))?
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> MakeWriter<'writer> for CapturedLogs {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}
