# Changelog

All notable changes to this project are documented here.
This project has not yet made a tagged release.

## [Unreleased]

### Fixed

- `C4-GAP-001`: accepted ADR-0004 removes `/metrics` from the business Router
  and adds a metrics-only Unix-socket Router with typed
  `OperationsPrincipal(METRICS_READ)`. The supported local edge exposes a
  distinct loopback mTLS listener backed by a runtime-generated dedicated
  client CA and approved Ed25519 public key; Gateway TCP/socket remain
  unpublished. Router, resource-boundary and clean Compose tests reject
  malformed/forged assertions plus missing, wrong-CA, expired, future,
  wrong-EKU and unapproved certificates, preserve authorized process metrics
  during PostgreSQL loss, and exercise restart/trust rotation without an
  anonymous interval. C4 remains pending independent human sign-off.

- `CLI-GAP-001`: `atf evaluate` now defaults to a millisecond-aligned current
  evaluation time, matching the immutable Evaluation Context contract. A
  fail-first integration test executes the real binary without
  `--evaluated-at` and parses the resulting typed Decision.

### Added

- DS-040 Durable Shadow release-candidate review. The new checklist maps every
  PRD §32.1/§32.2 item to code, tests and runtime commands, records a STRIDE and
  five-axis assessment, and classifies every CRITICAL/HIGH gap without reducing
  severity by documentation. The initial verdict correctly blocked on the
  missing Metrics principal and independent human approval; the
  `C4-GAP-001` fix above closes the technical contradiction. README, PRD,
  Architecture, Threat Model, Roadmap, Gap Matrix and task plans now agree
  that C4 and RA-001 still await independent human sign-off.

- DS-039 supported local Durable Shadow operations. A digest-pinned,
  non-root Compose stack keeps PostgreSQL/Gateway private and exposes only a
  loopback Caddy TLS edge with a generated public CA export. One-shot migration
  and idempotent bootstrap provision generated Agent credentials, Operator
  authority, two signed Policy versions and the audited Risk Rule Set. The
  clean operations gate proves signed submit, restart/readiness, hash-identical
  Original Replay, PostgreSQL backup/isolated restore with an identical Audit
  head, audited Policy rollback/forward and bounded load. The checked-in local
  result is 50/50 successful, P95 178 ms and 28.328 evaluations/second; both PRD
  latency and throughput targets remain explicitly unmet.

- DS-038 blocking dependency, secret and Rust SAST gates. Pull-request CI now
  pins every Action to an immutable commit, runs `cargo-audit 0.22.2` against
  both lockfiles, scans complete Git history plus the current tree with
  Gitleaks 8.30.1, and forbids first-party `unsafe_code` through pinned Clippy.
  RustSec, synthetic-secret and unsafe negative fixtures prove every gate can
  fail; exact advisory/fingerprint exceptions require a code owner, reason and
  expiry within 90 days, while Cargo-tree checks invalidate an exception if
  its package becomes reachable. Dependabot covers root/fuzz Cargo and Actions.

- DS-037 executable Replay, property and fuzz conformance. A closed pure vector
  locks exact Original/Counterfactual Context and Decision hashes plus
  non-authoritative same-snapshot lineage; ten Proptest properties retain
  string-only Amounts and reject every attacker-resealed derived binding.
  `scripts/test-conformance.sh` groups Policy, pure and real-PostgreSQL Replay
  evidence, while a pinned nightly/libFuzzer target exercises the public
  Intent boundary under a bounded 15-second CI smoke.

- DS-032 bounded organization-scoped Audit queries. Authenticated
  `auditor`/`org_admin` operators can use `/v1/audit/events` or the
  Intent-specific alias with exact Intent, Agent, event-type and inclusive
  time filters. Store reauthorizes the current durable role and verifies the
  declared organization chain in one repeatable-read snapshot before exposing
  stable sequence-ordered pages. Versioned cursors bind the tenant, filters
  and chain prefix; limits default to 50 and cannot exceed 100. Real
  Gateway/PostgreSQL tests cover filters, append-stable pagination,
  cross-tenant/non-enumerating denial, malformed or rebound cursors, disabled
  subjects, role and principal confusion, and fail-closed chain corruption.

- DS-031 accepted request/order frequency Risk. Rule Set v1.3.0 binds the
  closed `AGENT` subject, `PROFILE` action scope, threshold, window,
  `REQUESTED` accounting and restrictive missing-data behavior. Authenticated
  admission now appends exact Profile/action binding in immutable
  `IntentReceived`; migration 0014 indexes the bounded aggregate, and
  Evaluation/Audit evidence records matching plus unresolved legacy counts.
  Real PostgreSQL tests cover inclusive millisecond boundaries, concurrent
  accepted requests and completed idempotent retries.

- DS-030 normalized first-time destination Risk. A versioned Payment EIP-155
  normalizer derives one lowercase history key from legacy lowercase or valid
  EIP-55 checksum-case input without rewriting the signed Intent. Migration
  0013 supports an organization/Profile/destination/time query over prior
  `DecisionRecorded(PERMIT)` evidence; Store re-verifies the typed event,
  Decision/Intent binding and normalizer output. Risk records the exact query
  and optional match, while prior DENY/cross-tenant rows and invalid or
  unsupported destinations cannot silently establish familiarity.

- DS-029 asset-aware daily cumulative-spend Risk. Migration 0012 adds the
  bounded permitted-spend index; Store captures a repeatable-read,
  organization/Agent/time/sequence-scoped PostgreSQL `NUMERIC` aggregate by
  exact bound asset and limits evidence to 256 asset groups. Risk includes the
  current Intent, converts only through one fresh verified direct
  organization-scoped `ATF_ENRICHED` quote, and emits restrictive findings for
  missing/unusable evidence, unresolved legacy assets, overflow or precision
  loss. Amount-boundary, tenant/time, parallel completion, Schema, Replay and
  real Gateway tests cover the contract.

- DS-028 bounded durable Risk-history snapshots. A closed core contract binds
  the repository sequence/hash, organization/Agent/resource/current Intent,
  evaluation window, explicit `PERMITTED` accounting and optional prior
  Decision result. Migration 0011 adds the supporting index; Gateway records
  the query/result in Risk Evaluation/Audit evidence, `atf-risk` no longer
  depends on Audit events, and both Replay modes reconstruct the exact boundary.

- DS-025 strongly bound canonical Decision v1. The closed envelope binds the
  exact Intent/Profile, Policy/Risk artifacts, Evaluation Context/snapshot,
  explicit Simulation state, evaluation/expiry times, future Approval and
  Obligation fields, and execution constraints under the domain-separated
  `ATF_DECISION_V1` hash. Store write/read verification uses that embedded
  hash, and current `DecisionRecorded` evidence mirrors every binding value.
- DS-024 context-only deterministic Policy/Risk evaluation. Public evaluators
  no longer sample time or accept separately supplied privileged values;
  Context binding covers Intent/Profile/artifact identity, while Risk verifies
  the exact Audit prefix and rejects later history. Agent vendor fields are
  never inspected, enabled vendor rules require a missing-data finding, and
  repeated evaluation produces byte-equivalent module output. Typed Risk
  Context failures merge to terminal `Decision(ERROR)` rather than treating
  an absent finding list as Permit.
- DS-023 immutable Evaluation Context: a closed canonical Schema/type binds
  Intent/Profile, one evaluation time, Policy/Risk artifacts, Agent-context
  hash, exact verified Evidence/trust-policy hash, Audit-history prefix and
  explicit market/Simulation availability. Migration 0008 atomically stores
  one snapshot plus `ContextEnriched` before Policy/Risk; final Evaluation
  rows bind its hash, and restart/tamper/fencing checks fail closed.
- Migration 0004 and `atf-store` Agent/identity-key repositories. Canonical
  organization-scoped records carry exact bytes/hashes, monotonic lifecycle
  versions and typed Audit event pointers; registration, status changes and
  irreversible key revocation commit state plus Audit atomically.
- Offline `atf identity` commands for Agent provisioning, Ed25519 public-key
  registration, Agent status changes and key revocation. Real CLI/PostgreSQL
  tests cover restart, bounded key overlap, strict key selection, lifecycle
  rejection, concurrency, rollback, tenant isolation and tamper; no command,
  durable row or Audit payload accepts private key material.
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
  restart with a higher fencing generation. DS-023 now persists or reuses an
  immutable context and terminates once as `RECOVERY_REPLAY_NOT_IMPLEMENTED`
  until deterministic replay is available.
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
  instead of substituting current context. DS-016 additionally provides
  signed hashed-Nonce replay protection.
- Concurrent requests can no longer acquire two durable evaluators for the
  same organization/idempotency key, a key cannot be rebound to another
  Intent hash, and a stale evaluator cannot finalize after lease reclaim.
  Completed result mutation/deletion/truncation is rejected by PostgreSQL;
  recovered work is restricted to a fail-closed `Decision(ERROR)` and must
  bind an immutable Evaluation Context.
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
