use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use atf_store::operator_subject_fingerprint;
use axum::http::{header::AUTHORIZATION, HeaderMap};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use jsonwebtoken::jwk::{Jwk, JwkSet, KeyAlgorithm, KeyOperations, PublicKeyUse};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::{redirect::Policy, Client, Url};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};

const MAX_BEARER_BYTES: usize = 16 * 1024;
const MAX_DISCOVERY_BYTES: usize = 64 * 1024;
const MAX_JWKS_BYTES: usize = 1024 * 1024;
const MAX_JWKS_KEYS: usize = 64;
const UNKNOWN_KID_REFRESH_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct OperatorAuthConfig {
    issuer_id: String,
    issuer: String,
    audience: String,
    discovery_url: Url,
    jwks_url: Url,
    algorithms: Vec<Algorithm>,
    max_token_lifetime: Duration,
    clock_skew: Duration,
    jwks_freshness: Duration,
    network_timeout: Duration,
    ca_certificate_pem: Option<Vec<u8>>,
}

impl OperatorAuthConfig {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer_id: impl Into<String>,
        issuer: impl Into<String>,
        audience: impl Into<String>,
        discovery_url: impl AsRef<str>,
        jwks_url: impl AsRef<str>,
        algorithms: Vec<Algorithm>,
        max_token_lifetime: Duration,
        clock_skew: Duration,
        jwks_freshness: Duration,
        network_timeout: Duration,
        ca_certificate_pem: Option<Vec<u8>>,
    ) -> Result<Self, OperatorAuthConfigError> {
        let issuer_id = issuer_id.into();
        let issuer = issuer.into();
        let audience = audience.into();
        if !canonical_identifier(&issuer_id) {
            return Err(OperatorAuthConfigError("issuer_id"));
        }
        if audience.is_empty()
            || audience.trim() != audience
            || audience.len() > 512
            || audience.bytes().any(|byte| byte.is_ascii_control())
        {
            return Err(OperatorAuthConfigError("audience"));
        }
        secure_url(&issuer).map_err(|_| OperatorAuthConfigError("issuer"))?;
        let discovery_url = secure_url(discovery_url.as_ref())
            .map_err(|_| OperatorAuthConfigError("discovery_url"))?;
        let jwks_url =
            secure_url(jwks_url.as_ref()).map_err(|_| OperatorAuthConfigError("jwks_url"))?;
        if algorithms.is_empty()
            || algorithms.len() > 8
            || algorithms.iter().any(|algorithm| !asymmetric(*algorithm))
        {
            return Err(OperatorAuthConfigError("algorithms"));
        }
        let distinct: HashSet<Algorithm> = algorithms.iter().copied().collect();
        if distinct.len() != algorithms.len() {
            return Err(OperatorAuthConfigError("algorithms"));
        }
        if !(Duration::from_secs(1)..=Duration::from_secs(3_600)).contains(&max_token_lifetime) {
            return Err(OperatorAuthConfigError("max_token_lifetime"));
        }
        if clock_skew > Duration::from_secs(120) {
            return Err(OperatorAuthConfigError("clock_skew"));
        }
        if !(Duration::from_secs(1)..=Duration::from_secs(3_600)).contains(&jwks_freshness) {
            return Err(OperatorAuthConfigError("jwks_freshness"));
        }
        if !(Duration::from_millis(100)..=Duration::from_secs(30)).contains(&network_timeout) {
            return Err(OperatorAuthConfigError("network_timeout"));
        }
        Ok(Self {
            issuer_id,
            issuer,
            audience,
            discovery_url,
            jwks_url,
            algorithms,
            max_token_lifetime,
            clock_skew,
            jwks_freshness,
            network_timeout,
            ca_certificate_pem,
        })
    }

    pub fn parse_algorithms(value: &str) -> Result<Vec<Algorithm>, OperatorAuthConfigError> {
        let mut algorithms = Vec::new();
        for name in value.split(',') {
            let algorithm = match name.trim() {
                "RS256" => Algorithm::RS256,
                "RS384" => Algorithm::RS384,
                "RS512" => Algorithm::RS512,
                "PS256" => Algorithm::PS256,
                "PS384" => Algorithm::PS384,
                "PS512" => Algorithm::PS512,
                "ES256" => Algorithm::ES256,
                "ES384" => Algorithm::ES384,
                "EdDSA" => Algorithm::EdDSA,
                _ => return Err(OperatorAuthConfigError("algorithms")),
            };
            algorithms.push(algorithm);
        }
        if algorithms.is_empty() {
            return Err(OperatorAuthConfigError("algorithms"));
        }
        Ok(algorithms)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorAuthConfigError(&'static str);

impl fmt::Display for OperatorAuthConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid Operator authentication {} configuration",
            self.0
        )
    }
}

impl std::error::Error for OperatorAuthConfigError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedOperatorToken {
    pub issuer_id: String,
    pub subject_fingerprint: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OperatorAuthError {
    Rejected,
}

#[derive(Clone)]
pub struct OperatorAuthenticator {
    inner: Arc<AuthenticatorInner>,
}

struct AuthenticatorInner {
    config: OperatorAuthConfig,
    source: KeySource,
    cache: RwLock<Option<KeyCache>>,
    refresh_lock: Mutex<()>,
}

enum KeySource {
    Remote(Client),
    Static(JwkSet),
}

struct KeyCache {
    jwks: JwkSet,
    fetched_at: Instant,
}

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct AccessTokenClaims {
    iss: String,
    sub: String,
    #[allow(dead_code)]
    aud: Audience,
    exp: i64,
    iat: i64,
    nbf: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl OperatorAuthenticator {
    pub async fn initialize(config: OperatorAuthConfig) -> Result<Self, OperatorAuthConfigError> {
        let mut builder = Client::builder()
            .https_only(true)
            .redirect(Policy::none())
            .no_proxy()
            .connect_timeout(config.network_timeout)
            .timeout(config.network_timeout)
            .user_agent("atf-gateway/0.1");
        if let Some(pem) = &config.ca_certificate_pem {
            let certificate = reqwest::Certificate::from_pem(pem)
                .map_err(|_| OperatorAuthConfigError("ca_certificate_pem"))?;
            builder = builder.add_root_certificate(certificate);
        }
        let client = builder
            .build()
            .map_err(|_| OperatorAuthConfigError("http_client"))?;
        let authenticator = Self {
            inner: Arc::new(AuthenticatorInner {
                config,
                source: KeySource::Remote(client),
                cache: RwLock::new(None),
                refresh_lock: Mutex::new(()),
            }),
        };
        authenticator
            .validate_discovery()
            .await
            .map_err(|_| OperatorAuthConfigError("discovery"))?;
        authenticator
            .refresh(true)
            .await
            .map_err(|_| OperatorAuthConfigError("jwks"))?;
        Ok(authenticator)
    }

    fn from_jwks(
        config: OperatorAuthConfig,
        jwks: JwkSet,
    ) -> Result<Self, OperatorAuthConfigError> {
        validate_jwks(&jwks, &config).map_err(|_| OperatorAuthConfigError("jwks"))?;
        Ok(Self {
            inner: Arc::new(AuthenticatorInner {
                config,
                source: KeySource::Static(jwks.clone()),
                cache: RwLock::new(Some(KeyCache {
                    jwks,
                    fetched_at: Instant::now(),
                })),
                refresh_lock: Mutex::new(()),
            }),
        })
    }

    #[cfg(debug_assertions)]
    #[doc(hidden)]
    pub fn from_test_jwks(
        config: OperatorAuthConfig,
        jwks: JwkSet,
    ) -> Result<Self, OperatorAuthConfigError> {
        Self::from_jwks(config, jwks)
    }

    pub(crate) async fn verify(
        &self,
        headers: &HeaderMap,
    ) -> Result<VerifiedOperatorToken, OperatorAuthError> {
        let now = i64::try_from(jsonwebtoken::get_current_timestamp())
            .map_err(|_| OperatorAuthError::Rejected)?;
        self.verify_at(headers, now).await
    }

    async fn verify_at(
        &self,
        headers: &HeaderMap,
        now: i64,
    ) -> Result<VerifiedOperatorToken, OperatorAuthError> {
        let token = bearer_token(headers)?;
        let header = strict_header(token)?;
        if !matches!(header.typ.as_deref(), Some("at+jwt" | "application/at+jwt"))
            || !asymmetric(header.alg)
            || !self.inner.config.algorithms.contains(&header.alg)
        {
            return Err(OperatorAuthError::Rejected);
        }
        let kid = header
            .kid
            .as_deref()
            .filter(|value| canonical_identifier(value))
            .ok_or(OperatorAuthError::Rejected)?;
        let jwk = self.key_for(kid, header.alg).await?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|_| OperatorAuthError::Rejected)?;
        let mut validation = Validation::new(header.alg);
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        validation.set_issuer(&[&self.inner.config.issuer]);
        validation.set_audience(&[&self.inner.config.audience]);
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.leeway = 0;
        let decoded = decode::<AccessTokenClaims>(token, &key, &validation)
            .map_err(|_| OperatorAuthError::Rejected)?;
        let claims = decoded.claims;
        validate_claim_times(&claims, now, &self.inner.config)?;
        if claims.iss != self.inner.config.issuer
            || !audience_contains(&claims.aud, &self.inner.config.audience)
            || claims.sub.is_empty()
            || claims.sub.len() > 512
            || claims
                .sub
                .bytes()
                .any(|byte| byte == 0 || byte.is_ascii_control())
        {
            return Err(OperatorAuthError::Rejected);
        }
        let subject_fingerprint = operator_subject_fingerprint(&claims.iss, &claims.sub)
            .map_err(|_| OperatorAuthError::Rejected)?;
        Ok(VerifiedOperatorToken {
            issuer_id: self.inner.config.issuer_id.clone(),
            subject_fingerprint,
        })
    }

    pub(crate) async fn check_ready(&self) -> Result<(), OperatorAuthError> {
        self.ensure_fresh().await?;
        let cache = self.inner.cache.read().await;
        let Some(cache) = cache.as_ref() else {
            return Err(OperatorAuthError::Rejected);
        };
        if cache.fetched_at.elapsed() > self.inner.config.jwks_freshness {
            return Err(OperatorAuthError::Rejected);
        }
        validate_jwks(&cache.jwks, &self.inner.config)
    }

    async fn key_for(&self, kid: &str, algorithm: Algorithm) -> Result<Jwk, OperatorAuthError> {
        self.ensure_fresh().await?;
        if let Some(key) = self.cached_key(kid, algorithm).await? {
            return Ok(key);
        }
        self.refresh_unknown_kid().await?;
        self.cached_key(kid, algorithm)
            .await?
            .ok_or(OperatorAuthError::Rejected)
    }

    async fn cached_key(
        &self,
        kid: &str,
        algorithm: Algorithm,
    ) -> Result<Option<Jwk>, OperatorAuthError> {
        let cache = self.inner.cache.read().await;
        let Some(cache) = cache.as_ref() else {
            return Ok(None);
        };
        let mut matches = cache
            .jwks
            .keys
            .iter()
            .filter(|key| key.common.key_id.as_deref() == Some(kid));
        let Some(key) = matches.next() else {
            return Ok(None);
        };
        if matches.next().is_some() || !usable_key(key, algorithm, &self.inner.config) {
            return Err(OperatorAuthError::Rejected);
        }
        Ok(Some(key.clone()))
    }

    async fn ensure_fresh(&self) -> Result<(), OperatorAuthError> {
        let fresh =
            self.inner.cache.read().await.as_ref().is_some_and(|cache| {
                cache.fetched_at.elapsed() <= self.inner.config.jwks_freshness
            });
        if fresh {
            Ok(())
        } else {
            self.refresh(false).await
        }
    }

    async fn refresh_unknown_kid(&self) -> Result<(), OperatorAuthError> {
        let _guard = self.inner.refresh_lock.lock().await;
        let minimum_age = self
            .inner
            .config
            .jwks_freshness
            .min(UNKNOWN_KID_REFRESH_COOLDOWN);
        if self
            .inner
            .cache
            .read()
            .await
            .as_ref()
            .is_some_and(|cache| cache.fetched_at.elapsed() < minimum_age)
        {
            return Ok(());
        }
        let jwks = match &self.inner.source {
            KeySource::Remote(client) => {
                fetch_json(client, self.inner.config.jwks_url.clone(), MAX_JWKS_BYTES).await?
            }
            KeySource::Static(jwks) => jwks.clone(),
        };
        validate_jwks(&jwks, &self.inner.config)?;
        *self.inner.cache.write().await = Some(KeyCache {
            jwks,
            fetched_at: Instant::now(),
        });
        Ok(())
    }

    async fn refresh(&self, force: bool) -> Result<(), OperatorAuthError> {
        let _guard = self.inner.refresh_lock.lock().await;
        if !force
            && self
                .inner
                .cache
                .read()
                .await
                .as_ref()
                .is_some_and(|cache| cache.fetched_at.elapsed() <= self.inner.config.jwks_freshness)
        {
            return Ok(());
        }
        let jwks = match &self.inner.source {
            KeySource::Remote(client) => {
                fetch_json(client, self.inner.config.jwks_url.clone(), MAX_JWKS_BYTES).await?
            }
            KeySource::Static(jwks) => jwks.clone(),
        };
        validate_jwks(&jwks, &self.inner.config)?;
        *self.inner.cache.write().await = Some(KeyCache {
            jwks,
            fetched_at: Instant::now(),
        });
        Ok(())
    }

    async fn validate_discovery(&self) -> Result<(), OperatorAuthError> {
        let KeySource::Remote(client) = &self.inner.source else {
            return Ok(());
        };
        let document: DiscoveryDocument = fetch_json(
            client,
            self.inner.config.discovery_url.clone(),
            MAX_DISCOVERY_BYTES,
        )
        .await?;
        if document.issuer != self.inner.config.issuer
            || document.jwks_uri != self.inner.config.jwks_url.as_str()
        {
            return Err(OperatorAuthError::Rejected);
        }
        Ok(())
    }
}

fn validate_claim_times(
    claims: &AccessTokenClaims,
    now: i64,
    config: &OperatorAuthConfig,
) -> Result<(), OperatorAuthError> {
    let skew =
        i64::try_from(config.clock_skew.as_secs()).map_err(|_| OperatorAuthError::Rejected)?;
    let max_lifetime = i64::try_from(config.max_token_lifetime.as_secs())
        .map_err(|_| OperatorAuthError::Rejected)?;
    if claims.iat < 0
        || claims.exp <= claims.iat
        || claims
            .exp
            .checked_sub(claims.iat)
            .is_none_or(|lifetime| lifetime > max_lifetime)
        || claims.iat > now.saturating_add(skew)
        || claims.exp < now.saturating_sub(skew)
        || now > claims.iat.saturating_add(max_lifetime).saturating_add(skew)
        || claims.nbf.is_some_and(|nbf| nbf > now.saturating_add(skew))
    {
        return Err(OperatorAuthError::Rejected);
    }
    Ok(())
}

fn audience_contains(audience: &Audience, expected: &str) -> bool {
    match audience {
        Audience::One(value) => value == expected,
        Audience::Many(values) => values.iter().any(|value| value == expected),
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<&str, OperatorAuthError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next().ok_or(OperatorAuthError::Rejected)?;
    if values.next().is_some() {
        return Err(OperatorAuthError::Rejected);
    }
    let value = value.to_str().map_err(|_| OperatorAuthError::Rejected)?;
    let mut parts = value.split(' ');
    let scheme = parts.next().ok_or(OperatorAuthError::Rejected)?;
    let token = parts.next().ok_or(OperatorAuthError::Rejected)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.len() > MAX_BEARER_BYTES
        || parts.next().is_some()
        || !token.is_ascii()
    {
        return Err(OperatorAuthError::Rejected);
    }
    Ok(token)
}

fn strict_header(token: &str) -> Result<jsonwebtoken::Header, OperatorAuthError> {
    let mut segments = token.split('.');
    let encoded = segments.next().ok_or(OperatorAuthError::Rejected)?;
    if segments.next().is_none() || segments.next().is_none() || segments.next().is_some() {
        return Err(OperatorAuthError::Rejected);
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| OperatorAuthError::Rejected)?;
    if bytes.len() > 4_096 {
        return Err(OperatorAuthError::Rejected);
    }
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| OperatorAuthError::Rejected)?;
    let object = value.as_object().ok_or(OperatorAuthError::Rejected)?;
    if object.len() != 3
        || !object
            .keys()
            .all(|key| matches!(key.as_str(), "alg" | "typ" | "kid"))
    {
        return Err(OperatorAuthError::Rejected);
    }
    for field in ["alg", "typ", "kid"] {
        if !object.get(field).is_some_and(serde_json::Value::is_string) {
            return Err(OperatorAuthError::Rejected);
        }
    }
    decode_header(token).map_err(|_| OperatorAuthError::Rejected)
}

fn validate_jwks(jwks: &JwkSet, config: &OperatorAuthConfig) -> Result<(), OperatorAuthError> {
    if jwks.keys.is_empty() || jwks.keys.len() > MAX_JWKS_KEYS {
        return Err(OperatorAuthError::Rejected);
    }
    let mut kids = HashSet::new();
    let mut usable = 0_usize;
    for key in &jwks.keys {
        let Some(kid) = key.common.key_id.as_deref() else {
            continue;
        };
        if !canonical_identifier(kid) || !kids.insert(kid) {
            return Err(OperatorAuthError::Rejected);
        }
        if config
            .algorithms
            .iter()
            .any(|algorithm| usable_key(key, *algorithm, config))
        {
            usable += 1;
        }
    }
    if usable == 0 {
        Err(OperatorAuthError::Rejected)
    } else {
        Ok(())
    }
}

fn usable_key(key: &Jwk, algorithm: Algorithm, config: &OperatorAuthConfig) -> bool {
    if !config.algorithms.contains(&algorithm)
        || key_algorithm(key.common.key_algorithm) != Some(algorithm)
        || matches!(
            key.common.public_key_use,
            Some(PublicKeyUse::Encryption | PublicKeyUse::Other(_))
        )
        || key
            .common
            .key_operations
            .as_ref()
            .is_some_and(|operations| !operations.contains(&KeyOperations::Verify))
    {
        return false;
    }
    DecodingKey::from_jwk(key).is_ok()
}

fn key_algorithm(value: Option<KeyAlgorithm>) -> Option<Algorithm> {
    match value? {
        KeyAlgorithm::RS256 => Some(Algorithm::RS256),
        KeyAlgorithm::RS384 => Some(Algorithm::RS384),
        KeyAlgorithm::RS512 => Some(Algorithm::RS512),
        KeyAlgorithm::PS256 => Some(Algorithm::PS256),
        KeyAlgorithm::PS384 => Some(Algorithm::PS384),
        KeyAlgorithm::PS512 => Some(Algorithm::PS512),
        KeyAlgorithm::ES256 => Some(Algorithm::ES256),
        KeyAlgorithm::ES384 => Some(Algorithm::ES384),
        KeyAlgorithm::EdDSA => Some(Algorithm::EdDSA),
        _ => None,
    }
}

async fn fetch_json<T: DeserializeOwned>(
    client: &Client,
    url: Url,
    max_bytes: usize,
) -> Result<T, OperatorAuthError> {
    let mut response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| OperatorAuthError::Rejected)?;
    if !response.status().is_success()
        || response
            .content_length()
            .is_some_and(|length| length > max_bytes as u64)
    {
        return Err(OperatorAuthError::Rejected);
    }
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(str::trim);
    if !content_type.is_some_and(|value| value == "application/json" || value.ends_with("+json")) {
        return Err(OperatorAuthError::Rejected);
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| OperatorAuthError::Rejected)?
    {
        if bytes.len().saturating_add(chunk.len()) > max_bytes {
            return Err(OperatorAuthError::Rejected);
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| OperatorAuthError::Rejected)
}

fn secure_url(value: &str) -> Result<Url, ()> {
    let url = Url::parse(value).map_err(|_| ())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        Err(())
    } else {
        Ok(url)
    }
}

fn canonical_identifier(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

const fn asymmetric(algorithm: Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::EdDSA
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use atf_store::operator_subject_fingerprint;
    use axum::http::{HeaderMap, HeaderValue};
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::{json, Value};
    use std::time::Duration;

    const NOW: i64 = 1_786_156_800;
    const ISSUER: &str = "https://issuer.example.test";
    const AUDIENCE: &str = "https://atf.example.test";

    fn config() -> OperatorAuthConfig {
        OperatorAuthConfig::new(
            "corp-idp",
            ISSUER,
            AUDIENCE,
            "https://issuer.example.test/.well-known/openid-configuration",
            "https://issuer.example.test/keys",
            vec![jsonwebtoken::Algorithm::EdDSA],
            Duration::from_secs(900),
            Duration::from_secs(120),
            Duration::from_secs(300),
            Duration::from_secs(3),
            None,
        )
        .unwrap()
    }

    fn authenticator() -> OperatorAuthenticator {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let jwks: jsonwebtoken::jwk::JwkSet = serde_json::from_value(json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()),
                "use": "sig",
                "key_ops": ["verify"],
                "alg": "EdDSA",
                "kid": "key-1"
            }]
        }))
        .unwrap();
        OperatorAuthenticator::from_jwks(config(), jwks).unwrap()
    }

    fn claims() -> Value {
        json!({
            "iss": ISSUER,
            "sub": "operator-subject-1",
            "aud": ["unrelated", AUDIENCE],
            "iat": NOW - 30,
            "nbf": NOW - 30,
            "exp": NOW + 300,
            "email": "ignored@example.test",
            "roles": ["org_admin"],
            "organization_id": "attacker-selected"
        })
    }

    fn token(header: Value, claims: Value, signing_key: &SigningKey) -> String {
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header}.{claims}");
        let signature = signing_key.sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    fn headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn validates_rfc9068_token_and_ignores_authorization_claims() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let token = token(
            json!({"typ":"at+jwt", "alg":"EdDSA", "kid":"key-1"}),
            claims(),
            &signing_key,
        );
        let verified = authenticator()
            .verify_at(&headers(&token), NOW)
            .await
            .unwrap();
        assert_eq!(verified.issuer_id, "corp-idp");
        assert_eq!(
            verified.subject_fingerprint,
            operator_subject_fingerprint(ISSUER, "operator-subject-1").unwrap()
        );
    }

    #[tokio::test]
    async fn rejects_header_claim_signature_time_and_key_confusion() {
        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let wrong_key = SigningKey::from_bytes(&[8; 32]);
        let valid_header = json!({"typ":"application/at+jwt", "alg":"EdDSA", "kid":"key-1"});
        let mut cases = Vec::new();
        cases.push(token(
            json!({"typ":"JWT", "alg":"EdDSA", "kid":"key-1"}),
            claims(),
            &signing_key,
        ));
        cases.push(token(
            json!({"typ":"at+jwt", "alg":"EdDSA", "kid":"unknown"}),
            claims(),
            &signing_key,
        ));
        cases.push(token(json!({"typ":"at+jwt", "alg":"EdDSA", "kid":"key-1", "jku":"https://attacker.test/jwks"}), claims(), &signing_key));
        cases.push(token(valid_header.clone(), claims(), &wrong_key));
        let none_header = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&json!({"typ":"at+jwt", "alg":"none", "kid":"key-1"})).unwrap(),
        );
        let none_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims()).unwrap());
        cases.push(format!("{none_header}.{none_claims}.unsigned"));

        for (field, value) in [
            ("iss", json!("https://wrong-issuer.test")),
            ("aud", json!(["wrong-audience"])),
            ("sub", json!("")),
            ("iat", json!(NOW + 121)),
            ("nbf", json!(NOW + 121)),
            ("exp", json!(NOW - 121)),
        ] {
            let mut changed = claims();
            changed[field] = value;
            cases.push(token(valid_header.clone(), changed, &signing_key));
        }
        let mut too_long = claims();
        too_long["iat"] = json!(NOW - 10);
        too_long["exp"] = json!(NOW + 901);
        cases.push(token(valid_header, too_long, &signing_key));

        for rejected in cases {
            assert!(authenticator()
                .verify_at(&headers(&rejected), NOW)
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn requires_exactly_one_bounded_bearer_credential() {
        let authenticator = authenticator();
        assert!(authenticator
            .verify_at(&HeaderMap::new(), NOW)
            .await
            .is_err());

        let mut duplicate = HeaderMap::new();
        duplicate.append("authorization", "Bearer one.two.three".parse().unwrap());
        duplicate.append("authorization", "Bearer four.five.six".parse().unwrap());
        assert!(authenticator.verify_at(&duplicate, NOW).await.is_err());

        let mut query_style = HeaderMap::new();
        query_style.insert("authorization", "Basic secret".parse().unwrap());
        assert!(authenticator.verify_at(&query_style, NOW).await.is_err());
    }

    #[test]
    fn configuration_and_jwks_reject_insecure_or_ambiguous_authority() {
        assert!(OperatorAuthConfig::new(
            "corp-idp",
            "http://issuer.example.test",
            AUDIENCE,
            "https://issuer.example.test/discovery",
            "https://issuer.example.test/keys",
            vec![jsonwebtoken::Algorithm::EdDSA],
            Duration::from_secs(900),
            Duration::from_secs(120),
            Duration::from_secs(300),
            Duration::from_secs(3),
            None,
        )
        .is_err());
        assert!(OperatorAuthConfig::new(
            "corp-idp",
            ISSUER,
            AUDIENCE,
            "https://issuer.example.test/discovery",
            "https://issuer.example.test/keys",
            vec![jsonwebtoken::Algorithm::HS256],
            Duration::from_secs(900),
            Duration::from_secs(120),
            Duration::from_secs(300),
            Duration::from_secs(3),
            None,
        )
        .is_err());
        assert!(OperatorAuthConfig::new(
            "corp-idp",
            ISSUER,
            AUDIENCE,
            "https://issuer.example.test/discovery",
            "https://issuer.example.test/keys",
            vec![jsonwebtoken::Algorithm::EdDSA],
            Duration::from_secs(3_601),
            Duration::from_secs(120),
            Duration::from_secs(300),
            Duration::from_secs(3),
            None,
        )
        .is_err());

        let signing_key = SigningKey::from_bytes(&[7; 32]);
        let key = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()),
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "EdDSA",
            "kid": "duplicate"
        });
        let jwks = serde_json::from_value(json!({"keys": [key.clone(), key]})).unwrap();
        assert!(OperatorAuthenticator::from_jwks(config(), jwks).is_err());
    }
}
