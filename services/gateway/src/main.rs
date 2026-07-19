use std::path::PathBuf;

use atf_gateway::{build_router, AppState};
use atf_policy::PolicyBundle;
use atf_risk::RiskConfig;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let policies_dir: PathBuf = std::env::var("ATF_POLICIES_DIR")
        .unwrap_or_else(|_| "policies/examples".to_string())
        .into();
    let policy_bundle = PolicyBundle::from_dir(&policies_dir).unwrap_or_else(|err| {
        panic!(
            "failed to load policy bundle from {}: {err}",
            policies_dir.display()
        )
    });

    let state = AppState::new(policy_bundle, RiskConfig::default());
    let app = build_router(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", port))
        .await
        .unwrap_or_else(|err| panic!("failed to bind :{port}: {err}"));

    tracing::info!(
        "atf-gateway listening on :{port}, policies from {}",
        policies_dir.display()
    );
    axum::serve(listener, app)
        .await
        .expect("gateway server exited unexpectedly");
}
