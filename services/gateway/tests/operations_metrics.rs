//! ADR-0004 executable boundary tests for the isolated Metrics surface.

#[allow(dead_code)]
mod support;

use std::convert::Infallible;
use std::error::Error;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use atf_gateway::{
    build_metrics_router, build_metrics_router_with_http_config, build_router, GatewayHttpConfig,
    HttpRequestLimits, HttpTimeouts, OperationalRateLimit,
};
use axum::body::{to_bytes, Body, Bytes, HttpBody};
use axum::http::{header::WWW_AUTHENTICATE, HeaderValue, Method, Request, StatusCode};
use http_body::Frame;
use tower::ServiceExt;

use support::{error_json, test_state, TestDatabase};

const VERIFIED_HEADER: &str = "x-atf-operations-verified";
const PUBLIC_KEY_HEADER: &str = "x-atf-operations-public-key";
const TEST_ED25519_SPKI: &str =
    "302a300506032b65700321001111111111111111111111111111111111111111111111111111111111111111";

struct PendingBody;

impl HttpBody for PendingBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Pending
    }
}

#[tokio::test]
async fn metrics_router_requires_operations_auth_and_exposes_only_get_metrics(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("operations_metrics_route").await?;
    let store = database.connect().await?;
    let metrics = build_metrics_router(test_state(store.clone()));

    let missing = metrics
        .clone()
        .oneshot(Request::builder().uri("/metrics").body(Body::empty())?)
        .await?;
    assert!(!missing.headers().contains_key(WWW_AUTHENTICATE));
    error_json(missing, StatusCode::UNAUTHORIZED, "AUTHENTICATION_REQUIRED").await?;

    let response = metrics
        .clone()
        .oneshot(operations_request(Method::GET, "/metrics")?)
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/plain; version=0.0.4; charset=utf-8"
    );
    assert!(response.headers().contains_key("x-atf-request-id"));
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-store");
    let body = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
    assert!(body.contains("atf_gateway_replay_metrics_available 1"));

    error_json(
        metrics
            .clone()
            .oneshot(operations_request(Method::GET, "/healthz")?)
            .await?,
        StatusCode::NOT_FOUND,
        "ROUTE_NOT_FOUND",
    )
    .await?;
    error_json(
        metrics
            .oneshot(operations_request(Method::POST, "/metrics")?)
            .await?,
        StatusCode::METHOD_NOT_ALLOWED,
        "METHOD_NOT_ALLOWED",
    )
    .await?;

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn operations_assertion_is_closed_bounded_and_ignored_by_business_router(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("operations_assertion").await?;
    let store = database.connect().await?;
    let state = test_state(store.clone());
    let metrics = build_metrics_router(state.clone());

    for request in [
        Request::builder()
            .uri("/metrics")
            .header(VERIFIED_HEADER, "MTLS_V0")
            .header(PUBLIC_KEY_HEADER, TEST_ED25519_SPKI)
            .body(Body::empty())?,
        Request::builder()
            .uri("/metrics")
            .header(VERIFIED_HEADER, "MTLS_V1")
            .header(PUBLIC_KEY_HEADER, TEST_ED25519_SPKI.to_ascii_uppercase())
            .body(Body::empty())?,
        Request::builder()
            .uri("/metrics")
            .header(VERIFIED_HEADER, "MTLS_V1")
            .header(PUBLIC_KEY_HEADER, "00")
            .body(Body::empty())?,
        Request::builder()
            .uri("/metrics")
            .header(VERIFIED_HEADER, "MTLS_V1")
            .header(PUBLIC_KEY_HEADER, "11".repeat(2_049))
            .body(Body::empty())?,
    ] {
        error_json(
            metrics.clone().oneshot(request).await?,
            StatusCode::UNAUTHORIZED,
            "AUTHENTICATION_REQUIRED",
        )
        .await?;
    }

    let mut duplicate = operations_request(Method::GET, "/metrics")?;
    duplicate.headers_mut().append(
        PUBLIC_KEY_HEADER,
        HeaderValue::from_static(TEST_ED25519_SPKI),
    );
    error_json(
        metrics.oneshot(duplicate).await?,
        StatusCode::UNAUTHORIZED,
        "AUTHENTICATION_REQUIRED",
    )
    .await?;

    error_json(
        build_router(state)
            .oneshot(operations_request(Method::GET, "/metrics")?)
            .await?,
        StatusCode::NOT_FOUND,
        "ROUTE_NOT_FOUND",
    )
    .await?;

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn operations_principal_has_an_independent_finite_rate_limit() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("operations_rate_limit").await?;
    let store = database.connect().await?;
    let generous = OperationalRateLimit::new(60_000, 60_000, 64)?;
    let config = GatewayHttpConfig::new(
        HttpRequestLimits::default(),
        HttpTimeouts::default(),
        generous,
        OperationalRateLimit::new(1, 1, 64)?,
    );
    let metrics = build_metrics_router_with_http_config(test_state(store.clone()), config);

    assert_eq!(
        metrics
            .clone()
            .oneshot(operations_request(Method::GET, "/metrics")?)
            .await?
            .status(),
        StatusCode::OK
    );
    let limited = metrics
        .oneshot(operations_request(Method::GET, "/metrics")?)
        .await?;
    assert!(limited.headers().contains_key("retry-after"));
    error_json(limited, StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED").await?;

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn metrics_surface_preserves_body_header_timeout_and_security_bounds(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("operations_http_bounds").await?;
    let store = database.connect().await?;
    let state = test_state(store.clone());
    let generous = OperationalRateLimit::new(60_000, 60_000, 64)?;

    let limits = GatewayHttpConfig::new(
        HttpRequestLimits::new(8, 256, 16)?,
        HttpTimeouts::new(Duration::from_secs(1), Duration::from_millis(500))?,
        generous.clone(),
        generous.clone(),
    );
    let metrics = build_metrics_router_with_http_config(state.clone(), limits);
    let mut oversized_body = operations_request(Method::GET, "/metrics")?;
    *oversized_body.body_mut() = Body::from(vec![b'x'; 9]);
    let response = metrics.clone().oneshot(oversized_body).await?;
    assert_security_headers(&response);
    error_json(
        response,
        StatusCode::PAYLOAD_TOO_LARGE,
        "REQUEST_BODY_TOO_LARGE",
    )
    .await?;

    let mut oversized_header = operations_request(Method::GET, "/metrics")?;
    oversized_header
        .headers_mut()
        .insert("x-padding", HeaderValue::from_str(&"x".repeat(300))?);
    let response = metrics.oneshot(oversized_header).await?;
    assert_security_headers(&response);
    error_json(
        response,
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        "REQUEST_HEADERS_TOO_LARGE",
    )
    .await?;

    let timeout = GatewayHttpConfig::new(
        HttpRequestLimits::default(),
        HttpTimeouts::new(Duration::from_millis(20), Duration::from_millis(10))?,
        generous.clone(),
        generous,
    );
    let timeout_metrics = build_metrics_router_with_http_config(state, timeout);
    let mut pending = operations_request(Method::GET, "/metrics")?;
    *pending.body_mut() = Body::new(PendingBody);
    let response = timeout_metrics.oneshot(pending).await?;
    assert_security_headers(&response);
    error_json(response, StatusCode::REQUEST_TIMEOUT, "REQUEST_TIMEOUT").await?;

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn metrics_surface_keeps_a_finite_source_rate_limit() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("operations_source_rate").await?;
    let store = database.connect().await?;
    let generous = OperationalRateLimit::new(60_000, 60_000, 64)?;
    let config = GatewayHttpConfig::new(
        HttpRequestLimits::default(),
        HttpTimeouts::default(),
        OperationalRateLimit::new(1, 1, 64)?,
        generous,
    );
    let metrics = build_metrics_router_with_http_config(test_state(store.clone()), config);

    assert_eq!(
        metrics
            .clone()
            .oneshot(operations_request(Method::GET, "/metrics")?)
            .await?
            .status(),
        StatusCode::OK
    );
    let limited = metrics
        .oneshot(operations_request(Method::GET, "/metrics")?)
        .await?;
    error_json(limited, StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED").await?;

    store.close().await;
    database.destroy().await?;
    Ok(())
}

fn operations_request(method: Method, uri: &str) -> Result<Request<Body>, Box<dyn Error>> {
    Ok(Request::builder()
        .method(method)
        .uri(uri)
        .header(VERIFIED_HEADER, "MTLS_V1")
        .header(PUBLIC_KEY_HEADER, TEST_ED25519_SPKI)
        .body(Body::empty())?)
}

fn assert_security_headers(response: &axum::response::Response) {
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
}
