//! atf-gateway: the HTTP entry point that wires Policy, Risk, Decision, and
//! durable Audit into one PostgreSQL-backed request path (PRD §22).
//!
//! Deliberately not wired in yet: Identity verification (`atf-identity`),
//! Simulation (no `atf-simulator`), Approval (no `atf-approval`), and
//! anything execution-related. This service only evaluates and records —
//! it never signs or submits a transaction. See `docs/architecture.md` for
//! what's next.

mod error;
mod request_id;
mod routes;
mod state;

pub use routes::build_router;
pub use state::AppState;
