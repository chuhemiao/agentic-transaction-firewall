use std::collections::HashMap;
use std::error::Error as _;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use atf_identity::IdentityEnvelope;
use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, MatchedPath, Request, State};
use axum::http::{header, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use http_body_util::LengthLimitError;

use crate::error::ApiError;
use crate::request_id::RequestId;
use crate::telemetry::{GatewayTelemetry, RequestRejection};

const MAX_BODY_BYTES: usize = 16 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 128 * 1024;
const MAX_HEADER_COUNT: usize = 256;
const MAX_TIMEOUT: Duration = Duration::from_secs(120);
const MAX_REQUESTS_PER_MINUTE: u32 = 60_000;
const MAX_RATE_LIMIT_KEYS: usize = 100_000;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const RATE_LIMIT_STALE_AFTER: Duration = Duration::from_secs(120);

const FORWARDED: HeaderName = HeaderName::from_static("forwarded");
const X_FORWARDED_FOR: HeaderName = HeaderName::from_static("x-forwarded-for");
const X_FORWARDED_HOST: HeaderName = HeaderName::from_static("x-forwarded-host");
const X_FORWARDED_PROTO: HeaderName = HeaderName::from_static("x-forwarded-proto");
const X_REAL_IP: HeaderName = HeaderName::from_static("x-real-ip");

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequestLimits {
    max_body_bytes: usize,
    max_header_bytes: usize,
    max_header_count: usize,
}

impl HttpRequestLimits {
    pub fn new(
        max_body_bytes: usize,
        max_header_bytes: usize,
        max_header_count: usize,
    ) -> Result<Self, GatewayHttpConfigError> {
        if !(1..=MAX_BODY_BYTES).contains(&max_body_bytes) {
            return Err(GatewayHttpConfigError("request body byte limit"));
        }
        if !(1..=MAX_HEADER_BYTES).contains(&max_header_bytes) {
            return Err(GatewayHttpConfigError("request header byte limit"));
        }
        if !(1..=MAX_HEADER_COUNT).contains(&max_header_count) {
            return Err(GatewayHttpConfigError("request header count limit"));
        }
        Ok(Self {
            max_body_bytes,
            max_header_bytes,
            max_header_count,
        })
    }
}

impl Default for HttpRequestLimits {
    fn default() -> Self {
        Self::new(256 * 1024, 32 * 1024, 64).expect("default HTTP request limits are valid")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpTimeouts {
    request: Duration,
    evaluation: Duration,
}

impl HttpTimeouts {
    pub fn new(request: Duration, evaluation: Duration) -> Result<Self, GatewayHttpConfigError> {
        if request.is_zero() || request > MAX_TIMEOUT {
            return Err(GatewayHttpConfigError("request timeout"));
        }
        if evaluation.is_zero() || evaluation > request {
            return Err(GatewayHttpConfigError("evaluation timeout"));
        }
        Ok(Self {
            request,
            evaluation,
        })
    }
}

impl Default for HttpTimeouts {
    fn default() -> Self {
        Self::new(Duration::from_secs(30), Duration::from_secs(15))
            .expect("default HTTP timeouts are valid")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationalRateLimit {
    requests_per_minute: u32,
    burst: u32,
    max_keys: usize,
}

impl OperationalRateLimit {
    pub fn new(
        requests_per_minute: u32,
        burst: u32,
        max_keys: usize,
    ) -> Result<Self, GatewayHttpConfigError> {
        if !(1..=MAX_REQUESTS_PER_MINUTE).contains(&requests_per_minute) {
            return Err(GatewayHttpConfigError("rate limit requests per minute"));
        }
        if burst == 0 || burst > requests_per_minute {
            return Err(GatewayHttpConfigError("rate limit burst"));
        }
        if !(1..=MAX_RATE_LIMIT_KEYS).contains(&max_keys) {
            return Err(GatewayHttpConfigError("rate limit key capacity"));
        }
        Ok(Self {
            requests_per_minute,
            burst,
            max_keys,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayHttpConfig {
    request: HttpRequestLimits,
    timeouts: HttpTimeouts,
    source_rate: OperationalRateLimit,
    principal_rate: OperationalRateLimit,
}

impl GatewayHttpConfig {
    pub fn new(
        request: HttpRequestLimits,
        timeouts: HttpTimeouts,
        source_rate: OperationalRateLimit,
        principal_rate: OperationalRateLimit,
    ) -> Self {
        Self {
            request,
            timeouts,
            source_rate,
            principal_rate,
        }
    }

    pub fn from_env() -> Result<Self, GatewayHttpConfigError> {
        let max_keys = usize_env("ATF_RATE_LIMIT_MAX_KEYS", 4_096)?;
        Ok(Self::new(
            HttpRequestLimits::new(
                usize_env("ATF_MAX_REQUEST_BODY_BYTES", 256 * 1024)?,
                usize_env("ATF_MAX_REQUEST_HEADER_BYTES", 32 * 1024)?,
                usize_env("ATF_MAX_REQUEST_HEADERS", 64)?,
            )?,
            HttpTimeouts::new(
                duration_millis_env("ATF_REQUEST_TIMEOUT_MILLIS", 30_000)?,
                duration_millis_env("ATF_EVALUATION_TIMEOUT_MILLIS", 15_000)?,
            )?,
            OperationalRateLimit::new(
                u32_env("ATF_SOURCE_RATE_LIMIT_PER_MINUTE", 600)?,
                u32_env("ATF_SOURCE_RATE_LIMIT_BURST", 100)?,
                max_keys,
            )?,
            OperationalRateLimit::new(
                u32_env("ATF_PRINCIPAL_RATE_LIMIT_PER_MINUTE", 120)?,
                u32_env("ATF_PRINCIPAL_RATE_LIMIT_BURST", 30)?,
                max_keys,
            )?,
        ))
    }
}

impl Default for GatewayHttpConfig {
    fn default() -> Self {
        Self::new(
            HttpRequestLimits::default(),
            HttpTimeouts::default(),
            OperationalRateLimit::new(600, 100, 4_096).expect("default source rate limit is valid"),
            OperationalRateLimit::new(120, 30, 4_096)
                .expect("default principal rate limit is valid"),
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayServerConfig {
    bind_address: IpAddr,
    port: u16,
    tls_terminated_by_trusted_proxy: bool,
}

impl GatewayServerConfig {
    pub fn new(
        bind_address: IpAddr,
        port: u16,
        tls_terminated_by_trusted_proxy: bool,
    ) -> Result<Self, GatewayHttpConfigError> {
        if port == 0 {
            return Err(GatewayHttpConfigError("listen port"));
        }
        if !bind_address.is_loopback() && !tls_terminated_by_trusted_proxy {
            return Err(GatewayHttpConfigError(
                "non-loopback binding requires trusted proxy TLS termination",
            ));
        }
        Ok(Self {
            bind_address,
            port,
            tls_terminated_by_trusted_proxy,
        })
    }

    pub fn from_env() -> Result<Self, GatewayHttpConfigError> {
        let bind_address = std::env::var("ATF_BIND_ADDRESS")
            .unwrap_or_else(|_| "127.0.0.1".into())
            .parse()
            .map_err(|_| GatewayHttpConfigError("bind address"))?;
        let port = std::env::var("PORT")
            .unwrap_or_else(|_| "8080".into())
            .parse()
            .map_err(|_| GatewayHttpConfigError("listen port"))?;
        let tls_terminated = bool_env("ATF_TLS_TERMINATED_BY_TRUSTED_PROXY", false)?;
        Self::new(bind_address, port, tls_terminated)
    }

    pub fn socket_address(self) -> SocketAddr {
        SocketAddr::new(self.bind_address, self.port)
    }

    pub fn tls_terminated_by_trusted_proxy(self) -> bool {
        self.tls_terminated_by_trusted_proxy
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GatewayHttpConfigError(&'static str);

impl fmt::Display for GatewayHttpConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid Gateway HTTP {} configuration", self.0)
    }
}

impl std::error::Error for GatewayHttpConfigError {}

#[derive(Clone)]
pub(crate) struct HttpRuntime(Arc<HttpRuntimeInner>);

struct HttpRuntimeInner {
    config: GatewayHttpConfig,
    source_limiter: KeyedRateLimiter,
    principal_limiter: KeyedRateLimiter,
    telemetry: GatewayTelemetry,
}

impl HttpRuntime {
    pub(crate) fn new(config: GatewayHttpConfig, telemetry: GatewayTelemetry) -> Self {
        Self(Arc::new(HttpRuntimeInner {
            source_limiter: KeyedRateLimiter::new(&config.source_rate),
            principal_limiter: KeyedRateLimiter::new(&config.principal_rate),
            config,
            telemetry,
        }))
    }

    pub(crate) fn check_agent(&self, envelope: &IdentityEnvelope) -> Result<(), RateLimitExceeded> {
        let key = hashed_key(
            b"ATF_OPERATIONAL_RATE_PRINCIPAL_V1\0AGENT\0",
            &[&envelope.organization_id, &envelope.agent_id],
        );
        self.0.principal_limiter.check(key)
    }

    pub(crate) fn check_operator(
        &self,
        issuer_id: &str,
        subject_fingerprint: &str,
    ) -> Result<(), RateLimitExceeded> {
        let key = hashed_key(
            b"ATF_OPERATIONAL_RATE_PRINCIPAL_V1\0OPERATOR\0",
            &[issuer_id, subject_fingerprint],
        );
        self.0.principal_limiter.check(key)
    }
}

pub(crate) async fn enforce(
    State(runtime): State<HttpRuntime>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .cloned()
        .expect("request ID middleware is the outer HTTP boundary");
    let source = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_else(|| "IN_PROCESS_UNKNOWN".into());
    let source_key = hashed_key(b"ATF_OPERATIONAL_RATE_SOURCE_V1\0", &[&source]);
    if let Err(exceeded) = runtime.0.source_limiter.check(source_key) {
        runtime
            .0
            .telemetry
            .record_request_rejection(RequestRejection::SourceRateLimit);
        return secured(rate_limited_response(&request_id, exceeded));
    }

    if request.headers().len() > runtime.0.config.request.max_header_count
        || header_bytes(request.headers()) > runtime.0.config.request.max_header_bytes
    {
        runtime
            .0
            .telemetry
            .record_request_rejection(RequestRejection::HeadersTooLarge);
        return secured(ApiError::headers_too_large().into_response(&request_id));
    }
    remove_forwarding_headers(request.headers_mut());

    let request_timeout = runtime.0.config.timeouts.request;
    let evaluation_timeout = runtime.0.config.timeouts.evaluation;
    let max_body_bytes = runtime.0.config.request.max_body_bytes;
    let evaluation_route = request
        .extensions()
        .get::<MatchedPath>()
        .is_some_and(|path| path.as_str() == "/v1/intents");
    let timed = tokio::time::timeout(request_timeout, async {
        let (parts, body) = request.into_parts();
        let body = match to_bytes(body, max_body_bytes).await {
            Ok(body) => body,
            Err(error) => {
                if error
                    .source()
                    .is_some_and(|source| source.is::<LengthLimitError>())
                {
                    runtime
                        .0
                        .telemetry
                        .record_request_rejection(RequestRejection::BodyTooLarge);
                    return ApiError::body_too_large().into_response(&request_id);
                }
                return ApiError::body_rejection(axum::http::StatusCode::BAD_REQUEST)
                    .into_response(&request_id);
            }
        };
        let request = Request::from_parts(parts, Body::from(body));
        if evaluation_route {
            match tokio::time::timeout(evaluation_timeout, next.run(request)).await {
                Ok(response) => response,
                Err(_) => {
                    runtime
                        .0
                        .telemetry
                        .record_request_rejection(RequestRejection::EvaluationTimeout);
                    ApiError::evaluation_timeout().into_response(&request_id)
                }
            }
        } else {
            next.run(request).await
        }
    })
    .await;

    match timed {
        Ok(response) => secured(response),
        Err(_) => {
            runtime
                .0
                .telemetry
                .record_request_rejection(RequestRejection::RequestTimeout);
            secured(ApiError::request_timeout().into_response(&request_id))
        }
    }
}

pub(crate) fn principal_rate_limited_response(
    runtime: &HttpRuntime,
    request_id: &RequestId,
    exceeded: RateLimitExceeded,
) -> Response {
    runtime
        .0
        .telemetry
        .record_request_rejection(RequestRejection::PrincipalRateLimit);
    rate_limited_response(request_id, exceeded)
}

fn rate_limited_response(request_id: &RequestId, exceeded: RateLimitExceeded) -> Response {
    let mut response = ApiError::rate_limited().into_response(request_id);
    let retry_after = HeaderValue::from_str(&exceeded.retry_after_seconds.to_string())
        .expect("bounded retry delay is a valid Header value");
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, retry_after);
    response
}

fn secured(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

fn header_bytes(headers: &axum::http::HeaderMap) -> usize {
    headers.iter().fold(0usize, |total, (name, value)| {
        total
            .saturating_add(name.as_str().len())
            .saturating_add(value.as_bytes().len())
            .saturating_add(4)
    })
}

fn remove_forwarding_headers(headers: &mut axum::http::HeaderMap) {
    for name in [
        &FORWARDED,
        &X_FORWARDED_FOR,
        &X_FORWARDED_HOST,
        &X_FORWARDED_PROTO,
        &X_REAL_IP,
    ] {
        headers.remove(name);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct RateLimitExceeded {
    retry_after_seconds: u64,
}

struct KeyedRateLimiter {
    interval: Duration,
    burst_tolerance: Duration,
    max_keys: usize,
    buckets: Mutex<HashMap<String, Bucket>>,
}

struct Bucket {
    theoretical_arrival: Instant,
    last_seen: Instant,
}

impl KeyedRateLimiter {
    fn new(config: &OperationalRateLimit) -> Self {
        let window_nanos = u64::try_from(RATE_LIMIT_WINDOW.as_nanos())
            .expect("the fixed rate-limit window fits u64 nanoseconds");
        let interval = Duration::from_nanos(window_nanos / u64::from(config.requests_per_minute));
        let burst_tolerance = interval
            .checked_mul(config.burst.saturating_sub(1))
            .unwrap_or(RATE_LIMIT_WINDOW);
        Self {
            interval,
            burst_tolerance,
            max_keys: config.max_keys,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn check(&self, key: String) -> Result<(), RateLimitExceeded> {
        let now = Instant::now();
        let mut buckets = self
            .buckets
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !buckets.contains_key(&key) && buckets.len() >= self.max_keys {
            buckets
                .retain(|_, bucket| now.duration_since(bucket.last_seen) < RATE_LIMIT_STALE_AFTER);
            if buckets.len() >= self.max_keys {
                return Err(RateLimitExceeded {
                    retry_after_seconds: RATE_LIMIT_STALE_AFTER.as_secs(),
                });
            }
        }
        let bucket = buckets.entry(key).or_insert(Bucket {
            theoretical_arrival: now,
            last_seen: now,
        });
        let allowed_at = bucket
            .theoretical_arrival
            .checked_sub(self.burst_tolerance)
            .unwrap_or(now);
        bucket.last_seen = now;
        if now < allowed_at {
            let delay = allowed_at.duration_since(now);
            let retry_after_seconds = u64::try_from(delay.as_millis().div_ceil(1_000))
                .unwrap_or(u64::MAX)
                .max(1);
            return Err(RateLimitExceeded {
                retry_after_seconds,
            });
        }
        bucket.theoretical_arrival = bucket
            .theoretical_arrival
            .max(now)
            .checked_add(self.interval)
            .unwrap_or(now + RATE_LIMIT_WINDOW);
        Ok(())
    }
}

fn hashed_key(domain: &[u8], fields: &[&str]) -> String {
    let mut input = Vec::with_capacity(
        domain.len() + fields.iter().map(|field| field.len() + 1).sum::<usize>(),
    );
    input.extend_from_slice(domain);
    for field in fields {
        input.extend_from_slice(field.as_bytes());
        input.push(0);
    }
    atf_core::sha256_hex(&input)
}

fn usize_env(name: &'static str, default: usize) -> Result<usize, GatewayHttpConfigError> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .parse()
        .map_err(|_| GatewayHttpConfigError(name))
}

fn u32_env(name: &'static str, default: u32) -> Result<u32, GatewayHttpConfigError> {
    std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .parse()
        .map_err(|_| GatewayHttpConfigError(name))
}

fn duration_millis_env(
    name: &'static str,
    default: u64,
) -> Result<Duration, GatewayHttpConfigError> {
    let millis = std::env::var(name)
        .unwrap_or_else(|_| default.to_string())
        .parse()
        .map_err(|_| GatewayHttpConfigError(name))?;
    Ok(Duration::from_millis(millis))
}

fn bool_env(name: &'static str, default: bool) -> Result<bool, GatewayHttpConfigError> {
    match std::env::var(name) {
        Ok(value) if value == "true" => Ok(true),
        Ok(value) if value == "false" => Ok(false),
        Ok(_) => Err(GatewayHttpConfigError(name)),
        Err(_) => Ok(default),
    }
}
