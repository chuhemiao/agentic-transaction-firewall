use atf_core::Timestamp;
use atf_gateway::{AppState, IdentityGatewayConfig};
use atf_identity::{AgentRecord, AgentStatus, IdentityEnvelope, IdentityKeyRecord};
use atf_intent::TransactionIntent;
use atf_policy::PolicyBundle;
use atf_risk::RiskConfig;
use atf_store::{AuthenticatedAdmissionInput, Store};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Duration as ChronoDuration, Timelike, Utc};
use ed25519_dalek::{Signer, SigningKey};
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, Executor, PgConnection, PgPool,
};
use std::{
    env,
    error::Error,
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

const SIGNING_KEY_SEED: [u8; 32] = [42; 32];

const POLICY: &str = r#"
    permit (
        principal,
        action == Action::"payment/purchase_api_resource",
        resource
    )
    when {
        context.organization_id == "alpha-lab" &&
        context.amount.lessThanOrEqual(decimal("20.0000"))
    };
"#;

pub fn test_state(store: Store) -> AppState {
    test_state_with_policy(store, POLICY)
}

pub fn test_state_with_policy(store: Store, policy: &str) -> AppState {
    AppState::new(
        policy.parse::<PolicyBundle>().expect("policy is valid"),
        RiskConfig::default(),
        store,
        IdentityGatewayConfig::new(AUDIENCE, ENVIRONMENT)
            .expect("test identity context is canonical"),
    )
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
            "destination": "eip155:8453:0x1111111111111111111111111111111111111111"
        }
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
        .body(Body::empty())
        .unwrap()
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
        store.close().await;
        Ok(())
    }

    pub async fn business_record_counts(&self) -> Result<(i64, i64, i64, i64, i64), sqlx::Error> {
        sqlx::query_as(
            r#"
            SELECT
                (SELECT count(*) FROM idempotency_reservations),
                (SELECT count(*) FROM intents),
                (SELECT count(*) FROM evaluations),
                (SELECT count(*) FROM decisions),
                (SELECT count(*) FROM audit_events
                 WHERE event_type NOT IN (
                    'AgentRegistered',
                    'AgentStatusChanged',
                    'IdentityKeyRegistered',
                    'IdentityKeyRevoked'
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
