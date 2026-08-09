use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName};
use axum::middleware::Next;
use axum::response::Response;

use crate::error::ApiError;
use crate::middleware::{principal_rate_limited_response, HttpRuntime};
use crate::principal::{OperationsPrincipal, RequestPrincipal};
use crate::request_id::RequestId;

const VERIFIED_HEADER: HeaderName = HeaderName::from_static("x-atf-operations-verified");
const PUBLIC_KEY_HEADER: HeaderName = HeaderName::from_static("x-atf-operations-public-key");
const VERIFIED_ASSERTION_VERSION: &str = "MTLS_V1";
const MIN_SPKI_BYTES: usize = 32;
const MAX_SPKI_BYTES: usize = 2_048;

pub(crate) async fn authenticate(
    State(runtime): State<HttpRuntime>,
    mut request: Request,
    next: Next,
) -> Response {
    let request_id = request
        .extensions()
        .get::<RequestId>()
        .cloned()
        .expect("request ID middleware is the outer HTTP boundary");
    let principal = match parse_assertion(request.headers()) {
        Ok(principal) => principal,
        Err(reason) => {
            tracing::warn!(
                event_name = "operations.authentication.rejected",
                error_code = "OPERATIONS_ASSERTION_INVALID",
                rejection_reason = reason.as_str(),
                "Operations assertion was rejected"
            );
            return ApiError::operations_authentication_required().into_response(&request_id);
        }
    };
    if let Err(exceeded) = runtime.check_operations(principal.credential_fingerprint()) {
        return principal_rate_limited_response(&runtime, &request_id, exceeded);
    }

    request.headers_mut().remove(&VERIFIED_HEADER);
    request.headers_mut().remove(&PUBLIC_KEY_HEADER);
    request.extensions_mut().insert(principal);
    next.run(request).await
}

fn parse_assertion(headers: &HeaderMap) -> Result<OperationsPrincipal, AssertionRejection> {
    let verified =
        exactly_one_header(headers, &VERIFIED_HEADER).ok_or(AssertionRejection::VerifiedHeader)?;
    if verified != VERIFIED_ASSERTION_VERSION {
        return Err(AssertionRejection::Version);
    }
    let public_key = exactly_one_header(headers, &PUBLIC_KEY_HEADER)
        .ok_or(AssertionRejection::PublicKeyHeader)?;
    if public_key.len() % 2 != 0
        || !(MIN_SPKI_BYTES * 2..=MAX_SPKI_BYTES * 2).contains(&public_key.len())
        || !public_key
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(AssertionRejection::PublicKeyEncoding);
    }
    let spki = hex::decode(public_key).map_err(|_| AssertionRejection::PublicKeyEncoding)?;
    if !is_canonical_der_sequence(&spki) {
        return Err(AssertionRejection::PublicKeyDer);
    }
    RequestPrincipal::Operations(OperationsPrincipal::from_spki(&spki))
        .into_operations()
        .ok_or(AssertionRejection::Principal)
}

#[derive(Clone, Copy)]
enum AssertionRejection {
    VerifiedHeader,
    Version,
    PublicKeyHeader,
    PublicKeyEncoding,
    PublicKeyDer,
    Principal,
}

impl AssertionRejection {
    fn as_str(self) -> &'static str {
        match self {
            Self::VerifiedHeader => "VERIFIED_HEADER",
            Self::Version => "VERSION",
            Self::PublicKeyHeader => "PUBLIC_KEY_HEADER",
            Self::PublicKeyEncoding => "PUBLIC_KEY_ENCODING",
            Self::PublicKeyDer => "PUBLIC_KEY_DER",
            Self::Principal => "PRINCIPAL",
        }
    }
}

fn exactly_one_header<'a>(headers: &'a HeaderMap, name: &HeaderName) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}

fn is_canonical_der_sequence(value: &[u8]) -> bool {
    if value.len() < 2 || value[0] != 0x30 {
        return false;
    }
    let first_length = value[1];
    let (header_length, content_length) = if first_length & 0x80 == 0 {
        (2usize, usize::from(first_length))
    } else {
        let length_bytes = usize::from(first_length & 0x7f);
        if length_bytes == 0 || length_bytes > 4 || value.len() < 2 + length_bytes {
            return false;
        }
        let bytes = &value[2..2 + length_bytes];
        if bytes[0] == 0 || (length_bytes == 1 && bytes[0] < 0x80) {
            return false;
        }
        let content_length = bytes.iter().fold(0usize, |length, byte| {
            length
                .saturating_mul(256)
                .saturating_add(usize::from(*byte))
        });
        (2 + length_bytes, content_length)
    };
    header_length.checked_add(content_length) == Some(value.len())
}

#[cfg(test)]
mod tests {
    use super::is_canonical_der_sequence;

    #[test]
    fn der_envelope_is_exact_and_canonical() {
        assert!(is_canonical_der_sequence(&[0x30, 0x02, 0x05, 0x00]));
        assert!(!is_canonical_der_sequence(&[0x30, 0x01, 0x05, 0x00]));
        assert!(!is_canonical_der_sequence(&[0x30, 0x81, 0x02, 0x05, 0x00]));
        assert!(!is_canonical_der_sequence(&[0x31, 0x02, 0x05, 0x00]));
    }
}
