use atf_core::Timestamp;
use atf_gateway::{
    build_router, AppState, IdentityGatewayConfig, OperatorAuthConfig, OperatorAuthenticator,
};
use atf_risk::RiskRuleSet;
use atf_store::Store;
use std::time::Duration;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let deployment_environment = std::env::var("ATF_DEPLOYMENT_ENVIRONMENT")
        .expect("ATF_DEPLOYMENT_ENVIRONMENT is required for signed Intent verification");
    let policy_organization_id = std::env::var("ATF_POLICY_ORGANIZATION_ID")
        .expect("ATF_POLICY_ORGANIZATION_ID is required for Policy Bundle scope validation");
    let policy_bundle_id = std::env::var("ATF_POLICY_BUNDLE_ID")
        .expect("ATF_POLICY_BUNDLE_ID is required for durable Policy selection");

    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL is required; run atf-store-migrate before starting the Gateway");
    let store = Store::connect(&database_url)
        .await
        .expect("failed to connect to a compatible ATF PostgreSQL schema");
    let active_policy = store
        .load_active_policy_bundle(
            &policy_organization_id,
            &deployment_environment,
            &policy_bundle_id,
            Timestamp::now_millis(),
        )
        .await
        .expect("failed to load the signed durable active Policy Bundle");
    tracing::info!(
        bundle_id = active_policy.bundle.bundle_id(),
        policy_version = active_policy.bundle.policy_version(),
        bundle_hash = active_policy.bundle.bundle_hash(),
        pointer_lifecycle_version = active_policy.lifecycle_version,
        "signed durable active Policy Bundle loaded"
    );
    let risk_rule_set_path = std::env::var("ATF_RISK_RULE_SET_PATH")
        .expect("ATF_RISK_RULE_SET_PATH is required for versioned Risk evaluation");
    let configured_risk_rule_set =
        RiskRuleSet::from_file(std::path::Path::new(&risk_rule_set_path))
            .expect("failed to load the configured Risk Rule Set");
    let risk_rule_set = store
        .load_risk_rule_set(
            &policy_organization_id,
            &deployment_environment,
            configured_risk_rule_set.engine_version(),
            configured_risk_rule_set.version(),
            configured_risk_rule_set.rule_set_hash(),
        )
        .await
        .expect("failed to load the exact audited durable Risk Rule Set");
    tracing::info!(
        risk_rule_set_version = risk_rule_set.version(),
        risk_rule_set_hash = risk_rule_set.rule_set_hash(),
        risk_engine_version = risk_rule_set.engine_version(),
        "audited durable Risk Rule Set loaded"
    );
    let identity = IdentityGatewayConfig::new(
        std::env::var("ATF_IDENTITY_AUDIENCE")
            .expect("ATF_IDENTITY_AUDIENCE is required for signed Intent verification"),
        deployment_environment.clone(),
    )
    .expect("Gateway identity audience/environment are invalid");
    let ca_certificate_pem = std::env::var("ATF_OPERATOR_CA_CERT_PATH")
        .ok()
        .map(std::fs::read)
        .transpose()
        .expect("failed to read ATF_OPERATOR_CA_CERT_PATH");
    let algorithms = OperatorAuthConfig::parse_algorithms(
        &std::env::var("ATF_OPERATOR_JWT_ALGORITHMS")
            .expect("ATF_OPERATOR_JWT_ALGORITHMS is required"),
    )
    .expect("ATF_OPERATOR_JWT_ALGORITHMS is invalid");
    let operator_auth_config = OperatorAuthConfig::new(
        std::env::var("ATF_OPERATOR_ISSUER_ID").expect("ATF_OPERATOR_ISSUER_ID is required"),
        std::env::var("ATF_OPERATOR_ISSUER_URL").expect("ATF_OPERATOR_ISSUER_URL is required"),
        std::env::var("ATF_OPERATOR_AUDIENCE").expect("ATF_OPERATOR_AUDIENCE is required"),
        std::env::var("ATF_OPERATOR_DISCOVERY_URL")
            .expect("ATF_OPERATOR_DISCOVERY_URL is required"),
        std::env::var("ATF_OPERATOR_JWKS_URL").expect("ATF_OPERATOR_JWKS_URL is required"),
        algorithms,
        duration_env("ATF_OPERATOR_MAX_TOKEN_LIFETIME_SECONDS", 900),
        duration_env("ATF_OPERATOR_CLOCK_SKEW_SECONDS", 120),
        duration_env("ATF_OPERATOR_JWKS_FRESHNESS_SECONDS", 300),
        Duration::from_millis(unsigned_env("ATF_OPERATOR_HTTP_TIMEOUT_MILLIS", 3_000)),
        ca_certificate_pem,
    )
    .expect("Operator authentication configuration is invalid");
    let operator_auth = OperatorAuthenticator::initialize(operator_auth_config)
        .await
        .expect("failed to initialize configured Operator issuer/JWKS");
    let state = AppState::new_durable(
        policy_organization_id,
        deployment_environment,
        policy_bundle_id,
        risk_rule_set,
        store,
        identity,
        operator_auth,
    );
    let app = build_router(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap_or_else(|err| panic!("failed to bind :{port}: {err}"));

    tracing::info!("atf-gateway listening on :{port}");
    axum::serve(listener, app)
        .await
        .expect("gateway server exited unexpectedly");
}

fn duration_env(name: &str, default_seconds: u64) -> Duration {
    Duration::from_secs(unsigned_env(name, default_seconds))
}

fn unsigned_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .unwrap_or_else(|_| panic!("{name} must be an unsigned integer"))
        })
        .unwrap_or(default)
}
