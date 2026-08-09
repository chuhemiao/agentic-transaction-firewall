//! atf-gateway: the HTTP entry point that wires Policy, Risk, Decision, and
//! durable Audit into one PostgreSQL-backed request path (PRD §22).
//!
//! Deliberately not wired in yet: Simulation (no `atf-simulator`), Approval
//! (no `atf-approval`), and
//! anything execution-related. This service only evaluates and records —
//! it never signs or submits a transaction. See `docs/architecture.md` for
//! what's next.

mod auth;
mod error;
mod metrics_server;
mod middleware;
mod operations;
mod operator_auth;
mod principal;
mod request_id;
mod routes;
mod state;
mod telemetry;

pub use auth::{IdentityGatewayConfig, IdentityGatewayConfigError};
pub use metrics_server::{MetricsServerConfig, MetricsServerConfigError};
pub use middleware::{
    GatewayHttpConfig, GatewayHttpConfigError, GatewayServerConfig, HttpRequestLimits,
    HttpTimeouts, OperationalRateLimit,
};
pub use operator_auth::{OperatorAuthConfig, OperatorAuthConfigError, OperatorAuthenticator};
pub use routes::{
    build_metrics_router, build_metrics_router_with_http_config, build_router,
    build_router_with_http_config,
};
pub use state::AppState;
