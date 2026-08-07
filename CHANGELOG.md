# Changelog

All notable changes to this project are documented here.
This project has not yet made a tagged release.

## [Unreleased]

### Added

- `atf-store` with an embedded SQLx migration runner, fail-closed Schema
  compatibility checks, and migration 0001 for tenant-scoped Intents,
  Evaluations, Decisions, Audit chain heads/events, and schema metadata.
- Real PostgreSQL migration tests covering reruns, hash/tenant constraints,
  cross-record binding, and database-enforced Audit immutability, backed by a
  version-pinned PostgreSQL 17.10 CI service.
- ADR-0002 defining PostgreSQL as the single durable state boundary,
  row-locked per-organization Audit chains, atomic admission/finalization,
  fenced evaluator recovery, fail-closed database behavior, and forward-only
  schema compatibility.
- A dependency-ordered delivery plan and one-feature-at-a-time TODO covering
  Durable Shadow Mode, reference simulation/adapters, Approval/Enforce gates,
  and ecosystem work.
- `DecisionRecorded` Audit events on the gateway request path, including the
  canonical Intent hash and organization-scoped fields needed for lifecycle
  queries.
- A repository-backed security gap matrix and Durable Shadow Mode roadmap.
- Initial workspace skeleton per PRD §36: `atf-core`, `atf-intent`,
  `atf-policy`, `atf-decision`, `atf-cli`.
- Canonical Transaction Intent type, JSON Schema validation, canonical
  serialization and hashing.
- Minimal Cedar policy evaluation.
- `atf validate-intent` and `atf evaluate` CLI commands.
- CI workflow (fmt, clippy, test).
- Project governance and security docs (README, LICENSE, SECURITY,
  CONTRIBUTING, CODE_OF_CONDUCT).

### Changed

- Restored the cargo-deny 0.20.2 baseline by exact-versioning local workspace
  dependencies and pinning CI to the official v2.1.1 Action commit.
- Updated the product requirements to PRD v1.2, making Durable Shadow Mode
  the explicit release gate before Simulator/Adapter/Approval/Enforce work.
- Recorded ADR-0001 for the decision to finish persistence, identity,
  idempotency, replay, provenance, and audit durability before execution.
- Duplicate-purchase detection now counts only prior same-organization
  `DecisionRecorded(PERMIT)` events instead of every `IntentReceived` event.

### Security

- Reviewed and allowed ISC for the ring/WebPKI code and
  CDLA-Permissive-2.0 for the WebPKI trust-anchor data introduced by SQLx's
  Rustls PostgreSQL TLS path; wildcard and unknown-source denial remain.
- Pinned `home` to 0.5.11 so SQLx remains compatible with the workspace's Rust
  1.82 floor; 0.5.12 requires Rust 1.88.
- Reviewed and explicitly allowed `Apache-2.0 WITH LLVM-exception` from the
  Cedar build path and `MIT-0` from the JSON Schema path while retaining
  wildcard and unknown-source denial.
- A previously denied request can no longer poison a later valid request by
  making it look like a duplicate purchase, and histories from different
  organizations no longer collide in that rule.
