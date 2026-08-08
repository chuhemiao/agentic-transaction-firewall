use atf_core::Timestamp;
use atf_gateway::{AppState, IdentityGatewayConfig, OperatorAuthConfig, OperatorAuthenticator};
use atf_identity::{AgentRecord, AgentStatus, IdentityEnvelope, IdentityKeyRecord};
use atf_intent::TransactionIntent;
use atf_policy::{PolicyBundle, PolicyBundleLoadContext};
use atf_risk::RiskRuleSet;
use atf_store::{
    operator_subject_fingerprint, AuthenticatedAdmissionInput, OperatorKind, OperatorRegistration,
    OperatorRole, Store,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Duration as ChronoDuration, Timelike, Utc};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, Executor, PgConnection, PgPool,
};
use std::{
    env,
    error::Error,
    path::Path,
    process,
    str::FromStr,
    sync::OnceLock,
    time::Duration,
    time::{SystemTime, UNIX_EPOCH},
};

pub const AUDIENCE: &str = "atf-gateway";
pub const ENVIRONMENT: &str = "test";
pub const AGENT_ID: &str = "research-agent-01";
pub const KEY_ID: &str = "identity-key-01";
pub const OPERATOR_ISSUER: &str = "https://issuer.example.test";
pub const OPERATOR_AUDIENCE: &str = "https://atf.example.test";
pub const OPERATOR_SUBJECT: &str = "operator-subject-1";
pub const TEST_RISK_RULE_SET_VERSION: &str = "risk-rules-test-permissive-1";

const SIGNING_KEY_SEED: [u8; 32] = [42; 32];

pub fn test_state(store: Store) -> AppState {
    test_state_with_policy_dir(store, Path::new("../../policies/examples"))
}

#[allow(dead_code)]
pub fn test_state_with_default_risk(store: Store) -> AppState {
    test_state_with_policy_dir_and_risk(
        store,
        Path::new("../../policies/examples"),
        RiskRuleSet::default(),
    )
}

#[allow(dead_code)]
pub fn test_durable_policy_state(store: Store) -> AppState {
    AppState::new_durable(
        "alpha-lab".into(),
        "development".into(),
        "atf-example-payments".into(),
        test_risk_rule_set(),
        store,
        IdentityGatewayConfig::new(AUDIENCE, ENVIRONMENT)
            .expect("test identity context is canonical"),
        test_operator_authenticator(),
    )
}

#[allow(dead_code)]
pub fn test_state_with_forbid_all_policy(store: Store) -> AppState {
    test_state_with_policy_dir(store, Path::new("tests/fixtures/forbid-all-policy"))
}

fn test_state_with_policy_dir(store: Store, relative_dir: &Path) -> AppState {
    test_state_with_policy_dir_and_risk(store, relative_dir, test_risk_rule_set())
}

fn test_state_with_policy_dir_and_risk(
    store: Store,
    relative_dir: &Path,
    risk_rule_set: RiskRuleSet,
) -> AppState {
    let evaluated_at = Timestamp::now();
    let bundle_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative_dir);
    AppState::new(
        PolicyBundle::from_dir(
            &bundle_dir,
            &PolicyBundleLoadContext {
                organization_id: "alpha-lab".into(),
                environment: "development".into(),
                evaluated_at,
            },
        )
        .unwrap_or_else(|error| {
            panic!(
                "test Policy Bundle {} must be valid: {error}",
                bundle_dir.display()
            )
        }),
        risk_rule_set,
        store,
        IdentityGatewayConfig::new(AUDIENCE, ENVIRONMENT)
            .expect("test identity context is canonical"),
        test_operator_authenticator(),
    )
}

pub fn test_risk_rule_set() -> RiskRuleSet {
    let mut document: serde_json::Value =
        serde_json::from_str(include_str!("../../../../risk-rules/default.json"))
            .expect("default Risk Rule Set is JSON");
    document["rule_set_version"] = serde_json::json!(TEST_RISK_RULE_SET_VERSION);
    document["rules"]["vendor_price_deviation"]["missing_data"] =
        serde_json::json!("NOT_APPLICABLE");
    RiskRuleSet::from_json(&document.to_string()).expect("test Risk Rule Set is valid")
}

fn test_operator_authenticator() -> OperatorAuthenticator {
    let signing_key = operator_signing_key();
    let jwks = serde_json::from_value(serde_json::json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(signing_key.verifying_key().as_bytes()),
            "use": "sig",
            "key_ops": ["verify"],
            "alg": "EdDSA",
            "kid": "operator-key-1"
        }]
    }))
    .expect("test JWKS is valid");
    let config = OperatorAuthConfig::new(
        "corp-idp",
        OPERATOR_ISSUER,
        OPERATOR_AUDIENCE,
        "https://issuer.example.test/.well-known/openid-configuration",
        "https://issuer.example.test/keys",
        vec![jsonwebtoken::Algorithm::EdDSA],
        Duration::from_secs(900),
        Duration::from_secs(120),
        Duration::from_secs(300),
        Duration::from_secs(3),
        None,
    )
    .expect("test Operator authentication config is valid");
    OperatorAuthenticator::from_test_jwks(config, jwks).expect("test JWKS is usable")
}

pub fn sample_intent_json(intent_id: &str, amount: &str) -> serde_json::Value {
    serde_json::json!({
        "spec_version": "1.0",
        "intent_id": intent_id,
        "idempotency_key": format!("idem-{intent_id}"),
        "created_at": test_time(-60).to_string(),
        "expires_at": test_time(60 * 60).to_string(),
        "principal": { "organization_id": "alpha-lab", "agent_id": "research-agent-01" },
        "mandate": {
            "mandate_id": "mandate-001",
            "purpose": "test",
            "human_authorized": true
        },
        "action": { "category": "payment", "operation": "purchase_api_resource" },
        "resource": {
            "protocol": "x402",
            "resource_id": "btc-orderbook-2026-07-01",
            "resource_type": "dataset"
        },
        "transaction": {
            "network": "eip155:8453",
            "asset": "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913",
            "amount": amount,
            "destination": "eip155:8453:0x1111111111111111111111111111111111111111",
            "max_fee": "0.10"
        },
        "context": {}
    })
}

pub fn post_intent_request(intent_id: &str, amount: &str) -> Request<Body> {
    post_intent_value_request(sample_intent_json(intent_id, amount))
}

pub fn post_intent_value_request(intent: serde_json::Value) -> Request<Body> {
    let validated: TransactionIntent = serde_json::from_value(intent.clone()).unwrap();
    let intent_hash = validated.canonical_hash();
    signed_post_intent_request(
        intent,
        format!("nonce-{}", &intent_hash[..32]),
        AUDIENCE,
        ENVIRONMENT,
    )
}

#[allow(dead_code)]
pub fn signed_post_intent_request(
    intent: serde_json::Value,
    nonce: impl Into<String>,
    audience: &str,
    environment: &str,
) -> Request<Body> {
    let validated: TransactionIntent = serde_json::from_value(intent.clone()).unwrap();
    let (envelope, signature) = signed_identity(&validated, nonce.into(), audience, environment);
    Request::builder()
        .method("POST")
        .uri("/v1/intents")
        .header("content-type", "application/json")
        .header(
            "x-atf-identity-envelope",
            hex::encode(envelope.canonical_bytes()),
        )
        .header("x-atf-identity-signature", hex::encode(signature))
        .body(Body::from(serde_json::to_vec(&intent).unwrap()))
        .unwrap()
}

#[allow(dead_code)]
pub fn authenticated_admission_input(
    intent: TransactionIntent,
    lease_duration: Duration,
) -> AuthenticatedAdmissionInput {
    let intent_hash = intent.canonical_hash();
    let (envelope, signature) = signed_identity(
        &intent,
        format!("nonce-{}", &intent_hash[..32]),
        AUDIENCE,
        ENVIRONMENT,
    );
    AuthenticatedAdmissionInput {
        intent,
        envelope,
        signature,
        audience: AUDIENCE.into(),
        environment: ENVIRONMENT.into(),
        received_at: test_time(0),
        lease_duration,
    }
}

#[allow(dead_code)]
pub fn get_decision_request(intent_id: &str, organization_id: &str) -> Request<Body> {
    Request::builder()
        .uri(format!("/v1/intents/{intent_id}/decision"))
        .header("x-atf-organization-id", organization_id)
        .header("authorization", operator_authorization())
        .body(Body::empty())
        .unwrap()
}

pub fn operator_authorization() -> String {
    format!("Bearer {}", operator_token())
}

fn operator_token() -> String {
    let now = Utc::now().timestamp();
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "typ": "at+jwt",
            "alg": "EdDSA",
            "kid": "operator-key-1"
        }))
        .unwrap(),
    );
    let claims = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&serde_json::json!({
            "iss": OPERATOR_ISSUER,
            "sub": OPERATOR_SUBJECT,
            "aud": OPERATOR_AUDIENCE,
            "iat": now - 30,
            "nbf": now - 30,
            "exp": now + 300,
            "role": "org_admin",
            "organization_id": "attacker-selected"
        }))
        .unwrap(),
    );
    let signing_input = format!("{header}.{claims}");
    let signature = operator_signing_key().sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn operator_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

pub async fn body_json(
    response: axum::response::Response,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub async fn error_json(
    response: axum::response::Response,
    expected_status: StatusCode,
    expected_code: &str,
) -> Result<serde_json::Value, Box<dyn Error>> {
    assert_eq!(response.status(), expected_status);
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .expect("errors are JSON")
            .to_str()?,
        "application/json"
    );
    let header_request_id = response
        .headers()
        .get("x-atf-request-id")
        .expect("every Gateway response has a request ID")
        .to_str()?
        .to_owned();
    let body = body_json(response).await?;
    let object = body.as_object().expect("the error body is a JSON object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();

    assert_eq!(keys, ["code", "details", "message", "request_id"]);
    assert_eq!(body["code"], expected_code);
    assert!(body["message"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(body["request_id"], header_request_id);
    assert_eq!(header_request_id.len(), 26);
    assert!(header_request_id.bytes().all(|byte| byte.is_ascii_digit()
        || matches!(byte, b'A'..=b'H' | b'J'..=b'K' | b'M'..=b'N' | b'P'..=b'T' | b'V'..=b'Z')));
    assert!(body["details"].is_array());
    Ok(body)
}

pub struct TestDatabase {
    admin: PgConnection,
    pool: PgPool,
    name: String,
    pub url: String,
}

impl TestDatabase {
    pub async fn create(label: &str) -> Result<Self, Box<dyn Error>> {
        let admin_url = env::var("ATF_TEST_DATABASE_URL").expect(
            "ATF_TEST_DATABASE_URL must allow the test to create and drop PostgreSQL databases",
        );
        let admin_options = PgConnectOptions::from_str(&admin_url)?;
        let name = format!("atf_ds005_{label}_{}", unique_suffix());
        let quoted_name = quote_identifier(&name);
        let mut admin = PgConnection::connect_with(&admin_options).await?;
        admin
            .execute(format!("CREATE DATABASE {quoted_name}").as_str())
            .await?;

        let database_options = admin_options.database(&name);
        let url = database_options.to_url_lossy().to_string();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .connect_with(database_options)
            .await?;
        atf_store::migrate_pool(&pool).await?;

        Ok(Self {
            admin,
            pool,
            name,
            url,
        })
    }

    pub async fn connect(&self) -> Result<Store, atf_store::StoreError> {
        Store::connect(&self.url).await
    }

    pub async fn seed_organization(&self, organization_id: &str) -> Result<(), Box<dyn Error>> {
        sqlx::query("INSERT INTO organizations (organization_id) VALUES ($1)")
            .bind(organization_id)
            .execute(&self.pool)
            .await?;
        let store = self.connect().await?;
        let signing_key = signing_key();
        store
            .provision_agent(
                agent_record(organization_id),
                "test-operator",
                test_time(-7_200),
            )
            .await?;
        store
            .register_identity_key(
                organization_id,
                IdentityKeyRecord::from_public_key_bytes(
                    AGENT_ID.into(),
                    KEY_ID.into(),
                    signing_key.verifying_key().as_bytes(),
                    test_time(-3_600),
                    Some(test_time(24 * 60 * 60)),
                    None,
                )?,
                "test-operator",
                test_time(-3_599),
            )
            .await?;
        if organization_id == "alpha-lab" {
            store
                .provision_operator(
                    OperatorRegistration {
                        operator_id: "operator-1".into(),
                        issuer_id: "corp-idp".into(),
                        subject_fingerprint: operator_subject_fingerprint(
                            OPERATOR_ISSUER,
                            OPERATOR_SUBJECT,
                        )?,
                        principal_kind: OperatorKind::Human,
                        audit_organization_id: organization_id.into(),
                        created_at: test_time(-7_200),
                    },
                    "test-db-admin",
                    test_time(-3_500),
                )
                .await?;
            store
                .grant_operator_role(
                    "operator-1",
                    organization_id,
                    OperatorRole::Auditor,
                    "test-db-admin",
                    "TEST_ACCESS",
                    test_time(-3_400),
                )
                .await?;
        }
        store.close().await;
        Ok(())
    }

    pub async fn business_record_counts(
        &self,
    ) -> Result<(i64, i64, i64, i64, i64, i64), sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT
                (SELECT count(*) FROM idempotency_reservations),
                (SELECT count(*) FROM intents),
                (SELECT count(*) FROM evaluation_contexts),
                (SELECT count(*) FROM evaluations),
                (SELECT count(*) FROM decisions),
                (SELECT count(*) FROM audit_events
                 WHERE event_type NOT IN (
                    'AgentRegistered',
                    'AgentStatusChanged',
                    'IdentityKeyRegistered',
                    'IdentityKeyRevoked',
                    'OperatorRegistered',
                    'OperatorStatusChanged',
                    'OperatorRoleGranted',
                    'OperatorRoleRevoked'
                 ))
            "#,
        )
        .fetch_one(&self.pool)
        .await
    }

    pub async fn destroy(self) -> Result<(), Box<dyn Error>> {
        self.pool.close().await;
        let quoted_name = quote_identifier(&self.name);
        let mut admin = self.admin;
        admin
            .execute(format!("DROP DATABASE {quoted_name}").as_str())
            .await?;
        Ok(())
    }
}

fn signed_identity(
    intent: &TransactionIntent,
    nonce: String,
    audience: &str,
    environment: &str,
) -> (IdentityEnvelope, [u8; 64]) {
    let intent_hash = intent.canonical_hash();
    let envelope = IdentityEnvelope {
        domain: "ATF_INTENT_V1".into(),
        organization_id: intent.principal.organization_id.clone(),
        agent_id: intent.principal.agent_id.clone(),
        key_id: KEY_ID.into(),
        intent_hash: intent_hash.clone(),
        issued_at: test_time(-1),
        expires_at: test_time(4 * 60),
        nonce,
        audience: audience.into(),
        environment: environment.into(),
    };
    let signature = signing_key().sign(&envelope.canonical_bytes()).to_bytes();
    (envelope, signature)
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SIGNING_KEY_SEED)
}

fn agent_record(organization_id: &str) -> AgentRecord {
    AgentRecord {
        agent_id: AGENT_ID.into(),
        organization_id: organization_id.into(),
        owner_user_id: "test-user".into(),
        agent_type: "research".into(),
        model_provider: "test".into(),
        model_name: "deterministic-model".into(),
        agent_version: "1.0.0".into(),
        code_hash: "a".repeat(64),
        deployment_environment: ENVIRONMENT.into(),
        allowed_tools: vec!["mcp-market-data".into()],
        allowed_adapters: vec!["x402".into()],
        default_budget: Some("20.00".parse().unwrap()),
        risk_tier: "standard".into(),
        status: AgentStatus::Active,
        created_at: test_time(-24 * 60 * 60),
        expires_at: Some(test_time(24 * 60 * 60)),
    }
}

fn test_time(offset_seconds: i64) -> Timestamp {
    static ANCHOR: OnceLock<DateTime<Utc>> = OnceLock::new();
    let anchor = *ANCHOR.get_or_init(|| {
        let now = Utc::now();
        now.with_nanosecond(now.timestamp_subsec_millis() * 1_000_000)
            .expect("a millisecond-aligned test time")
    });
    Timestamp::from_datetime(anchor + ChronoDuration::seconds(offset_seconds))
}

fn unique_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after Unix epoch")
        .as_nanos();
    format!("{}_{nanos}", process::id())
}

fn quote_identifier(identifier: &str) -> String {
    assert!(
        identifier
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_'),
        "test-generated PostgreSQL identifiers must be alphanumeric"
    );
    format!("\"{identifier}\"")
}
