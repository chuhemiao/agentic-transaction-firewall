use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

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

pub(crate) async fn assign(mut request: Request, next: Next) -> Response {
    // Never trust a caller-provided correlation value. A fresh server ID is
    // the authority for this hop and overwrites the response header.
    let request_id = RequestId::generate();
    request.extensions_mut().insert(request_id.clone());

    let mut response = next.run(request).await;
    let value = HeaderValue::from_str(request_id.as_str())
        .expect("server-generated ULIDs are valid HTTP header values");
    response.headers_mut().insert(REQUEST_ID_HEADER, value);
    response
}
