use atf_gateway::AppState;
use atf_policy::PolicyBundle;
use atf_risk::RiskConfig;
use atf_store::Store;
use axum::body::Body;
use axum::http::Request;
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    ConnectOptions, Connection, Executor, PgConnection, PgPool,
};
use std::{
    env,
    error::Error,
    process,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

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
    AppState::new(
        POLICY.parse::<PolicyBundle>().expect("policy is valid"),
        RiskConfig::default(),
        store,
    )
}

pub fn sample_intent_json(intent_id: &str, amount: &str) -> serde_json::Value {
    serde_json::json!({
        "spec_version": "1.0",
        "intent_id": intent_id,
        "idempotency_key": format!("idem-{intent_id}"),
        "created_at": "2098-12-31T23:55:00Z",
        "expires_at": "2099-01-01T00:00:00Z",
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
    let intent = sample_intent_json(intent_id, amount);
    Request::builder()
        .method("POST")
        .uri("/v1/intents")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(&intent).unwrap()))
        .unwrap()
}

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

    pub async fn seed_organization(&self, organization_id: &str) -> Result<(), sqlx::Error> {
        sqlx::query("INSERT INTO organizations (organization_id) VALUES ($1)")
            .bind(organization_id)
            .execute(&self.pool)
            .await?;
        Ok(())
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
