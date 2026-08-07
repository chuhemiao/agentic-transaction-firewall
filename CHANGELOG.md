# Changelog

All notable changes to this project are documented here.
This project has not yet made a tagged release.

## [Unreleased]

### Added

- The canonical `ATF_INTENT_V1` Identity Envelope and strict Ed25519
  verification in `atf-identity`. Sorted compact JSON binds organization,
  Agent, exact Key ID, Intent hash, explicit five-minute lifetime, Nonce,
  audience and environment; Agent scope/status/lifetime and stable rejection
  codes are validated without reading the wall clock internally.
- A published Node/OpenSSL-derived Identity signature vector plus Rust tests
  for every signed-field mutation, noncanonical inputs, time boundaries,
  wrong trusted context, exact-key rotation and raw-hash fallback rejection.
- Exact durable retry and request-driven evaluator recovery in the Gateway.
  A completed same-hash POST returns the fully verified original Decision
  without rerunning Policy/Risk or adding Audit evidence; active work remains
  a bounded conflict; and expired admissions are conditionally reclaimed after
  restart with a higher fencing generation and terminated once as
  `RECOVERY_CONTEXT_UNAVAILABLE` while Evaluation Context snapshots are absent.
- Stage-boundary evaluator lease renewal plus real PostgreSQL HTTP tests for
  changed-Policy restart retry, barrier-synchronized concurrent convergence,
  expired-lease restart recovery, immutable record counts, and exact retry of
  the recovered fail-closed Decision.
- Migration 0003 and `atf-store` idempotency reservations that atomically bind
  each organization/key to one canonical Intent hash, grant one
  database-clock evaluator lease, support renewal and conditional
  expired-lease reclaim with monotonic generation fencing, and bind an
  immutable completed result to its Evaluation, Decision hash, and Audit
  evidence in the finalization transaction.
- Real PostgreSQL idempotency tests covering concurrent single-winner
  admission, different-hash conflicts, renewal/reclaim, stale-owner fencing,
  restart through a second Store, transaction rollback, fail-closed recovered
  work and completed-result tamper rejection. The Gateway now exposes stable
  `IDEMPOTENCY_CONFLICT` and `IDEMPOTENCY_IN_PROGRESS` responses before
  Policy/Risk; DS-013 builds exact retry and recovery on this boundary.
- A stable Gateway error contract: business-handler, Store, unknown-route and
  method errors return `{code,message,request_id,details}` JSON; every response
  carries a fresh server-generated `X-ATF-Request-ID` and validation details
  contain only stable semantic code/field pairs.
- `docs/api.md` with the implemented routes, safe error/status mapping,
  correlation behavior, compatibility rules and exact validation/admission
  ordering.
- Closed, versioned Intent Profile dispatch plus
  `atf.agent-commerce.payment` v1.0. It requires a typed resource, strict
  CAIP-2 network, same-chain CAIP-19 asset and CAIP-10 destination, forbids
  contract/trading fields, exposes derivable profile metadata, and rejects all
  unsupported action pairs before durable admission.
- A public Payment Profile Schema, normative `docs/intent-spec.md`, profile
  boundary/conformance tests, and Gateway/PostgreSQL proof that unsupported
  profiles leave durable state untouched.
- Deterministic common Transaction Intent semantic validation for financial
  bounds, millisecond-safe ordered timestamps with a 24-hour maximum TTL,
  valid ULIDs, and bounded nonblank identifier/purpose text. Violations expose
  stable ordered machine codes and fields; CLI and Gateway/PostgreSQL tests
  prove fail-closed behavior before durable admission and Policy/Risk.
- A closed Transaction Intent v1.0 structural contract across JSON Schema and
  Rust parsing, plus round-trip, unknown-field, version, extension, mutation,
  and golden canonical-hash tests for the existing x402 fixture.
- Migration 0002 and contract-v1 Intent lifecycle persistence with optimistic
  versions, last-event pointers, typed-event replay, compatibility backfill,
  stale-writer rejection, and atomic rollback tests on PostgreSQL.
- Explicit Shadow-only `IdentityVerificationSkipped` /
  `IDENTITY_UNVERIFIED` evidence plus typed Policy, Risk, Simulation, and
  Decision phase events committed with each Gateway finalization.
- Row-locked, per-organization PostgreSQL Audit append in `atf-store`, plus
  restart-safe verification of canonical bytes/hashes, contiguous sequence,
  predecessor links, redundant columns, and the committed chain head.
- Real PostgreSQL concurrency and corruption tests proving same-organization
  no-fork append, independent organization genesis records, and fail-closed
  handling of deletion, mutation, sequence reordering, malformed input, and a
  corrupt locked tail.
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

- Migrated the x402 and internal Payment fixtures from informal
  network/asset/destination strings to the supported CAIP-bound profile; the
  x402 fixture's locked canonical hash changed intentionally.
- Migrated valid Intent fixtures from historical 24-character pseudo-ULIDs and
  multi-decade lifetimes to valid 26-character ULIDs and five-minute TTLs; the
  x402 fixture's golden canonical hash changed intentionally.
- Restored the cargo-deny 0.20.2 baseline by exact-versioning local workspace
  dependencies and pinning CI to the official v2.1.1 Action commit.
- Updated the product requirements to PRD v1.2, making Durable Shadow Mode
  the explicit release gate before Simulator/Adapter/Approval/Enforce work.
- Recorded ADR-0001 for the decision to finish persistence, identity,
  idempotency, replay, provenance, and audit durability before execution.
- Duplicate-purchase detection now counts only prior same-organization
  `DecisionRecorded(PERMIT)` events instead of every `IntentReceived` event.

### Security

- A response lost after durable finalization no longer causes re-evaluation
  under changed Policy/Risk inputs. A crashed evaluator cannot strand work
  indefinitely once the same request is retried: database-conditional reclaim
  fences the prior owner and records a restrictive, evidence-complete ERROR
  instead of substituting current context. Signed nonce replay protection is
  still intentionally deferred to Identity wiring.
- Concurrent requests can no longer acquire two durable evaluators for the
  same organization/idempotency key, a key cannot be rebound to another
  Intent hash, and a stale evaluator cannot finalize after lease reclaim.
  Completed result mutation/deletion/truncation is rejected by PostgreSQL;
  recovered work is restricted to a fail-closed `Decision(ERROR)` until its
  immutable Evaluation Context can be reproduced.
- Raw request values, JSON Schema diagnostics, SQL/database information,
  policy text, key material and internal errors are no longer serialized by
  Gateway business errors; fail-closed Policy `Decision(ERROR)` reasons are
  fixed rather than embedding Cedar mapping diagnostics. PostgreSQL contract tests prove UTF-8, JSON,
  Schema, common-semantic and Profile rejection creates no Intent, Evaluation,
  Decision or Audit record before Policy/Risk.
- Schema-listed but semantically unimplemented actions can no longer inherit
  only common validation. Cross-chain Payment asset/payee mismatch, malformed
  CAIP IDs, missing typed resource/payee, and smuggled contract/trading fields
  now fail closed before persistence or Policy/Risk.
- Non-positive amounts/leverage, negative fees, invalid slippage, unsafe time
  windows, invalid ULIDs, and blank/oversized/unsafe common text can no longer
  reach Gateway persistence or Policy/Risk evaluation.
- Unknown Intent core fields and unsupported versions can no longer validate
  and then disappear before canonical hashing; extension data is accepted only
  inside object-valued, hash-bound `context` or `metadata`.
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
