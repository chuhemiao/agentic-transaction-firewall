//! DS-034 HTTP resource-boundary tests through the real Gateway router.

mod common;

use std::convert::Infallible;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use atf_gateway::{
    build_router_with_http_config, GatewayHttpConfig, GatewayServerConfig, HttpRequestLimits,
    HttpTimeouts, OperationalRateLimit,
};
use axum::body::{Body, Bytes, HttpBody};
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use http_body::Frame;
use tower::ServiceExt;

use common::{error_json, get_decision_request, post_intent_request, test_state, TestDatabase};

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

struct FailingBody;

impl HttpBody for FailingBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(Some(Err(io::Error::other("BODY_TRANSPORT_CANARY"))))
    }
}

#[tokio::test]
async fn oversized_body_and_headers_fail_with_safe_stable_codes() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("security_oversize").await?;
    let store = database.connect().await?;
    let config = http_config(
        HttpRequestLimits::new(1_024, 128, 16)?,
        HttpTimeouts::new(Duration::from_secs(1), Duration::from_millis(500))?,
        generous_rate_limit()?,
        generous_rate_limit()?,
    );
    let app = build_router_with_http_config(test_state(store.clone()), config);

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::from(vec![b'x'; 1_025]))?,
        )
        .await?;
    assert_security_headers(&response);
    error_json(
        response,
        StatusCode::PAYLOAD_TOO_LARGE,
        "REQUEST_BODY_TOO_LARGE",
    )
    .await?;

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header("x-padding", "x".repeat(256))
                .body(Body::empty())?,
        )
        .await?;
    assert_security_headers(&response);
    error_json(
        response,
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        "REQUEST_HEADERS_TOO_LARGE",
    )
    .await?;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::new(FailingBody))?,
        )
        .await?;
    let error = error_json(response, StatusCode::BAD_REQUEST, "REQUEST_BODY_INVALID").await?;
    assert!(!error.to_string().contains("BODY_TRANSPORT_CANARY"));

    let count_app = build_router_with_http_config(
        test_state(store.clone()),
        http_config(
            HttpRequestLimits::new(1_024, 2_048, 2)?,
            HttpTimeouts::default(),
            generous_rate_limit()?,
            generous_rate_limit()?,
        ),
    );
    let response = count_app
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header("x-one", "1")
                .header("x-two", "2")
                .header("x-three", "3")
                .body(Body::empty())?,
        )
        .await?;
    error_json(
        response,
        StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
        "REQUEST_HEADERS_TOO_LARGE",
    )
    .await?;

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn slow_upload_and_evaluation_have_distinct_bounded_failures() -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("security_timeout").await?;
    database.seed_organization("alpha-lab").await?;
    let store = database.connect().await?;

    let slow_upload = build_router_with_http_config(
        test_state(store.clone()),
        http_config(
            HttpRequestLimits::default(),
            HttpTimeouts::new(Duration::from_millis(20), Duration::from_millis(10))?,
            generous_rate_limit()?,
            generous_rate_limit()?,
        ),
    );
    let response = slow_upload
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::new(PendingBody))?,
        )
        .await?;
    error_json(response, StatusCode::REQUEST_TIMEOUT, "REQUEST_TIMEOUT").await?;

    let evaluation_timeout = build_router_with_http_config(
        test_state(store.clone()),
        http_config(
            HttpRequestLimits::default(),
            HttpTimeouts::new(Duration::from_secs(1), Duration::from_nanos(1))?,
            generous_rate_limit()?,
            generous_rate_limit()?,
        ),
    );
    let response = evaluation_timeout
        .oneshot(post_intent_request("01J0000000000000000000T340", "12.50"))
        .await?;
    error_json(response, StatusCode::GATEWAY_TIMEOUT, "EVALUATION_TIMEOUT").await?;
    assert_eq!(database.business_record_counts().await?, (0, 0, 0, 0, 0, 0));

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn source_rate_limit_uses_socket_ip_and_ignores_forwarding_headers(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("security_source_rate").await?;
    let store = database.connect().await?;
    let app = build_router_with_http_config(
        test_state(store.clone()),
        http_config(
            HttpRequestLimits::default(),
            HttpTimeouts::default(),
            OperationalRateLimit::new(1, 1, 64)?,
            generous_rate_limit()?,
        ),
    );

    let first = health_request("203.0.113.7:41000".parse()?, "198.51.100.10")?;
    let response = app.clone().oneshot(first).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_security_headers(&response);

    let second = health_request("203.0.113.7:42000".parse()?, "198.51.100.11")?;
    let response = app.clone().oneshot(second).await?;
    assert!(response.headers().contains_key("retry-after"));
    error_json(response, StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED").await?;

    let third = health_request("203.0.113.8:41000".parse()?, "198.51.100.10")?;
    assert_eq!(app.oneshot(third).await?.status(), StatusCode::OK);

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[tokio::test]
async fn repeated_agent_requests_are_limited_before_a_second_admission(
) -> Result<(), Box<dyn Error>> {
    let database = TestDatabase::create("security_principal_rate").await?;
    database.seed_organization("alpha-lab").await?;
    let store = database.connect().await?;
    let app = build_router_with_http_config(
        test_state(store.clone()),
        http_config(
            HttpRequestLimits::default(),
            HttpTimeouts::default(),
            generous_rate_limit()?,
            OperationalRateLimit::new(1, 1, 64)?,
        ),
    );

    let mut forged = post_intent_request("01J0000000000000000000R339", "12.50");
    forged
        .headers_mut()
        .insert("x-atf-identity-signature", "00".repeat(64).parse()?);
    let forged = app.clone().oneshot(forged).await?;
    error_json(
        forged,
        StatusCode::UNAUTHORIZED,
        "IDENTITY_SIGNATURE_INVALID",
    )
    .await?;

    let first = app
        .clone()
        .oneshot(post_intent_request("01J0000000000000000000R340", "12.50"))
        .await?;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 1, 8));

    let second = app
        .clone()
        .oneshot(post_intent_request("01J0000000000000000000R341", "12.50"))
        .await?;
    error_json(second, StatusCode::TOO_MANY_REQUESTS, "RATE_LIMITED").await?;
    assert_eq!(database.business_record_counts().await?, (1, 1, 1, 1, 1, 8));

    let first_operator = app
        .clone()
        .oneshot(get_decision_request(
            "01J0000000000000000000R349",
            "alpha-lab",
        ))
        .await?;
    error_json(first_operator, StatusCode::NOT_FOUND, "DECISION_NOT_FOUND").await?;
    let second_operator = app
        .clone()
        .oneshot(get_decision_request(
            "01J0000000000000000000R349",
            "alpha-lab",
        ))
        .await?;
    error_json(
        second_operator,
        StatusCode::TOO_MANY_REQUESTS,
        "RATE_LIMITED",
    )
    .await?;

    let metrics = app
        .oneshot(Request::builder().uri("/metrics").body(Body::empty())?)
        .await?;
    let metrics = axum::body::to_bytes(metrics.into_body(), usize::MAX).await?;
    let metrics = std::str::from_utf8(&metrics)?;
    assert!(
        metrics.contains("atf_gateway_request_rejections_total{reason=\"PRINCIPAL_RATE_LIMIT\"} 2")
    );

    store.close().await;
    database.destroy().await?;
    Ok(())
}

#[test]
fn public_plaintext_bind_requires_explicit_trusted_proxy_tls_boundary() {
    assert!(GatewayServerConfig::new("127.0.0.1".parse().unwrap(), 8080, false).is_ok());
    assert!(GatewayServerConfig::new("0.0.0.0".parse().unwrap(), 8080, false).is_err());
    assert!(GatewayServerConfig::new("0.0.0.0".parse().unwrap(), 8080, true).is_ok());
    assert!(GatewayServerConfig::new("127.0.0.1".parse().unwrap(), 0, false).is_err());
    assert!(HttpRequestLimits::new(0, 1, 1).is_err());
    assert!(HttpTimeouts::new(Duration::ZERO, Duration::ZERO).is_err());
    assert!(OperationalRateLimit::new(0, 0, 0).is_err());
}

fn http_config(
    request: HttpRequestLimits,
    timeouts: HttpTimeouts,
    source: OperationalRateLimit,
    principal: OperationalRateLimit,
) -> GatewayHttpConfig {
    GatewayHttpConfig::new(request, timeouts, source, principal)
}

fn generous_rate_limit() -> Result<OperationalRateLimit, Box<dyn Error>> {
    Ok(OperationalRateLimit::new(60_000, 60_000, 64)?)
}

fn health_request(peer: SocketAddr, forwarded_for: &str) -> Result<Request<Body>, Box<dyn Error>> {
    let mut request = Request::builder()
        .uri("/healthz")
        .header("x-forwarded-for", forwarded_for)
        .header("forwarded", format!("for={forwarded_for}"))
        .body(Body::empty())?;
    request.extensions_mut().insert(ConnectInfo(peer));
    Ok(request)
}

fn assert_security_headers(response: &axum::response::Response) {
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["x-content-type-options"], "nosniff");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
}
