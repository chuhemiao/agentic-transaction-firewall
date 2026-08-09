use axum::extract::Request;
use axum::extract::State;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;
use tracing::Instrument;

use crate::telemetry::GatewayTelemetry;

pub(crate) const REQUEST_ID_HEADER: &str = "x-atf-request-id";

#[derive(Clone, Debug)]
pub(crate) struct RequestId(String);

impl RequestId {
    fn generate() -> Self {
        Self(atf_core::new_ulid())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

pub(crate) async fn assign(
    State(telemetry): State<GatewayTelemetry>,
    mut request: Request,
    next: Next,
) -> Response {
    // Never trust a caller-provided correlation value. A fresh server ID is
    // the authority for this hop and overwrites the response header.
    let request_id = RequestId::generate();
    request.extensions_mut().insert(request_id.clone());
    let dimensions = telemetry.request_dimensions(&request);
    let span = tracing::info_span!(
        "http.request",
        request_id = request_id.as_str(),
        http_method = dimensions.method(),
        http_route = dimensions.route(),
        http_status = tracing::field::Empty,
    );

    async move {
        let started = Instant::now();
        let mut response = next.run(request).await;
        let duration = started.elapsed();
        let status = response.status();
        telemetry.record_request(dimensions, status, duration);
        tracing::Span::current().record("http_status", status.as_u16());
        tracing::info!(
            event_name = "http.request.completed",
            duration_micros = u64::try_from(duration.as_micros()).unwrap_or(u64::MAX),
            "Gateway request completed"
        );
        let value = HeaderValue::from_str(request_id.as_str())
            .expect("server-generated ULIDs are valid HTTP header values");
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
        response
    }
    .instrument(span)
    .await
}
