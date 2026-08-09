# ATF Execution TODO

This is the ordered execution checklist. Detailed scope, acceptance criteria,
verification and likely files are in [`plan.md`](plan.md). Execute one item per
feature commit unless the plan is explicitly revised.

Legend: `[x]` complete, `[~]` partial, `[ ]` not started, `NEXT` immediate task.

## Baseline gate repair

- [x] **BL-001:** restored `cargo deny 0.20.2`; reviewed new licenses,
  exact-versioned workspace path dependencies, retained restrictive policies,
  and pinned CI behavior.
- [x] **BL-002:** made cargo-deny warning-free; new duplicate versions fail,
  current unavoidable splits have exact-versioned dependency-path reasons,
  and CI rejects both new warnings and stale exceptions.

## Verified baseline — do not reopen without evidence

- [x] Canonical fixed-point Intent, Schema parsing and stable hash.
- [x] Basic Cedar Policy evaluation and Policy conformance command.
- [x] Basic Risk rules and deterministic Policy/Risk Decision merge.
- [x] In-memory Audit hash chain and `DecisionRecorded` event.
- [x] Evaluate-only Gateway POST/GET plus health/readiness routes.
- [x] Duplicate-purchase history counts only same-org prior PERMIT Decisions.
- [x] Authenticated Durable Shadow PRD v1.3 and execution-last ADR.

## Phase 2 — Durable Shadow Mode

### C1 Durable state

- [x] **DS-001:** accepted ADR-0002 for durable transactions, fenced evaluator
  recovery, forward-only migration compatibility, and row-locked per-org
  Audit chains.
- [x] **DS-002:** added `atf-store`, embedded migration runner, constrained
  tenant-aware PostgreSQL Schema, append-only Audit protection, and real
  PostgreSQL CI tests.
- [x] **DS-003:** implemented concurrent per-organization Audit append,
  consistent-snapshot reload/verification, and corruption/no-fork tests on
  PostgreSQL 17.10.
- [x] **DS-004:** added atomic admission/finalization repositories,
  canonical/evidence verification, immutable conflict rejection, and injected
  transaction-rollback tests on PostgreSQL.
- [x] **DS-005:** moved Gateway Decision/Audit state to PostgreSQL, removed the in-memory fallback, and proved readiness plus restart/second-instance reads.
- [x] **DS-006:** defined the complete lifecycle transition contract and
  versioned typed Audit payloads; current durable producers use it.
- [x] **DS-007:** persisted contract-v1 lifecycle state/version/event pointers;
  atomically emits typed phase evidence and rejects stale writers, partial
  batches, and replay/materialization drift.
- [x] **Checkpoint C1:** DS-001..DS-007 complete; restart, second-instance,
  concurrent Audit append, and invalid-transition/race tests pass.

### C2 Trusted admission

- [x] **DS-008:** closed unknown core fields in Schema and Rust parsing,
  limited the supported Intent version to `1.0`, and proved lossless/hash-bound
  extension round trips. Depends: DS-007.
- [x] **DS-009:** added deterministic common Rust semantic validation, stable
  structured codes, boundary tests, CLI failure behavior, and
  validation-before-durable-admission Gateway evidence. Depends: DS-008.
- [x] **DS-010:** added closed profile dispatch and the supported
  Agent-Commerce Payment profile, including CAIP chain binding and unsupported
  action rejection before durable admission. Depends: DS-009.
- [x] **DS-011:** added the stable safe API error envelope, server-owned
  request IDs and PostgreSQL-backed validation-before-evaluation evidence.
  Depends: DS-005, DS-009, DS-010.
- [x] **DS-012:** added atomic durable idempotency reservations, database-clock
  evaluator leases, renewal/reclaim, fencing and immutable completed results.
  Depends: DS-004, DS-011.
- [x] **DS-013:** wired exact completed retry, active-work conflict,
  stage-boundary heartbeat, concurrent single-result convergence and
  request-driven fail-closed recovery after restart. Depends: DS-012.
- [x] **DS-014:** replaced raw-hash signatures with the canonical
  domain-separated Identity Envelope, exact Key ID verification, closed time
  and scope checks, stable errors and a published Ed25519 vector. Depends: DS-008.
- [x] **DS-015:** persisted canonical Agent/key lifecycle with atomic typed
  Audit evidence, restart-safe exact-key validation, bounded rotation,
  database immutability guards and public-key-only offline provisioning.
  Depends: DS-002, DS-014.
- [x] **DS-016:** wired canonical signed Identity + atomic hashed
  nonce/idempotency semantics before Policy/Risk, including typed rejection
  and replay evidence, restart/concurrency/tenant/tamper coverage. Depends:
  DS-012..DS-015.
- [x] **DS-017:** accepted ADR-0003: Gateway-validated RFC 9068 access tokens,
  PostgreSQL-authoritative organization roles, disjoint Agent/operator
  principals, and no proxy/shared-account fallback. Explicit maintainer
  approval recorded 2026-08-08. Depends: DS-015.
- [x] **DS-018:** protected current non-health routes with disjoint typed Agent/
  Operator principals; added durable Operator/Role lifecycle, configured
  JWT/JWKS validation and non-enumerating organization Decision-read RBAC.
  Depends: DS-017.
- [x] **Checkpoint C2:** invalid, unauthenticated, cross-tenant, duplicate and
  replay requests cannot reach evaluation incorrectly.

### C3 Reproducible decisions

- [x] **DS-019:** added the closed Cedar Schema-backed Policy Bundle manifest,
  deterministic file-bound hash, exact scope/time checks and bundle identity in
  every Policy output. Depends: DS-018.
- [x] **DS-020:** persisted signed immutable Policy archives and monotonic
  active pointers with exact rollback; install/activation/rollback atomically
  bind typed Audit and current Policy-role authorization, authenticated Admin
  API and per-request Gateway selection. Depends: DS-019.
- [x] **DS-021:** added the closed versioned Risk Rule Set artifact and public
  Schema; canonical hashing binds engine compatibility, every decision field,
  missing-data behavior and lifecycle accounting boundaries, and Gateway
  evidence records the exact version/hash. Depends: DS-019.
- [x] **DS-022:** added closed provenance-bearing Evidence envelopes,
  canonical hash/freshness/allowlist/optional Ed25519 verification and the
  Risk privileged-context firewall; Agent inputs cannot overwrite verified
  values and invalid present evidence fails closed. Depends: DS-010, DS-021.
- [x] **DS-023:** persisted immutable, hash-verified Evaluation Context snapshots before Policy/Risk with typed Audit and final Evaluation binding. Depends: DS-020..DS-022.
- [x] **DS-024:** removed evaluator wall-clock and separately supplied
  privileged inputs; Policy/Risk now validate the immutable Context, Risk
  verifies its exact Audit prefix, and repeated outputs are byte-equivalent.
  Depends: DS-023.
- [x] **DS-025:** emitted closed strongly bound canonical Decisions; Store and
  `DecisionRecorded` verify the exact same bindings, and Schema rejects
  unknown core fields for all four outcomes. Depends: DS-023, DS-024.
- [x] **DS-026:** implemented authorized Original Replay with exact immutable
  artifacts/history, Decision-hash reproduction, stable fail-closed codes and
  non-authoritative Audit evidence. Depends: DS-025.
- [x] **DS-027:** implemented isolated, authorized Counterfactual Replay with
  explicit replacement artifacts, immutable new lineage, changed-outcome
  reporting and non-overwrite/restart/tamper evidence. Depends: DS-026.
- [x] **Checkpoint C3:** every Decision names immutable inputs and supports
  both exact Original and isolated Counterfactual Replay.

### C4 Release hardening

- [x] **DS-028:** moved duplicate-purchase history to typed, bounded durable
  snapshot queries with recorded inputs/results and Replay reconstruction.
  Depends: DS-024, DS-025.
- [x] **DS-029:** added asset-aware daily cumulative spend with fixed-point,
  snapshot-bounded permitted history and fail-closed quote evidence. Depends: DS-028.
- [x] **DS-030:** added versioned EIP-155 destination normalization and
  organization-scoped prior-permit familiarity with fail-closed snapshot
  evidence. Depends: DS-028.
- [x] **DS-031:** added versioned REQUESTED-boundary business request
  frequency with immutable Profile/action admission binding, bounded Store
  aggregates, concurrency enforcement and idempotent retry non-inflation.
  Depends: DS-028.
- [ ] **NEXT — DS-032:** add organization-scoped Audit query API. Depends: DS-003, DS-018, DS-025.
- [ ] **DS-033:** add safe metrics, tracing, correlation and redaction. Depends: DS-018, DS-025, DS-032.
- [ ] **DS-034:** add body/header limits, timeouts and operational rate limits. Depends: DS-018, DS-033.
- [ ] **DS-035:** standardize fail-closed dependency/readiness behavior. Depends: DS-025, DS-033, DS-034.
- [ ] **DS-036:** add real PostgreSQL restart/multi-instance/race CI suite. Depends: DS-016, DS-025, DS-035.
- [ ] **DS-037:** add Replay conformance, property tests and fuzz smoke. Depends: DS-027, DS-036.
- [ ] **DS-038:** add dependency, secret and SAST CI gates. Depends: DS-036.
- [ ] **DS-039:** ship local Compose, recovery runbooks and measured SLO baseline. Depends: DS-033, DS-036, DS-038.
- [ ] **CLI-GAP-001:** make `atf evaluate`'s default current evaluation time
  millisecond-aligned and cover the real default command path. Discovered by
  DS-030 smoke; must close before DS-040.
- [ ] **DS-040:** re-audit and close the Durable Shadow release gate. Depends: DS-028..DS-039.
- [ ] **Checkpoint C4:** human security review approves Durable Shadow; execution remains unavailable.

## Phase 3 — Reference Simulation and Adapters

- [ ] **RA-001:** implement typed/hash-bound Simulator results and merge rules. Depends: C4.
- [ ] **RA-002:** wire deterministic Mock Simulator into Shadow Gateway. Depends: RA-001.
- [ ] **RA-003:** define Adapter SDK and strict Manifest Schema. Depends: RA-001.
- [ ] **RA-004:** build Mock Adapter and Adapter conformance harness. Depends: RA-003.
- [ ] **RA-005:** implement x402 Shadow Adapter/Profile. Depends: RA-002, RA-004.
- [ ] **RA-006:** implement Safe Shadow Adapter/Profile. Depends: RA-002, RA-004.
- [ ] **RA-007:** implement Hyperliquid Shadow Adapter/Profile. Depends: RA-002, RA-004.
- [ ] **RA-008:** run three reference scenarios and close C5. Depends: RA-005..RA-007.
- [ ] **Checkpoint C5:** all adapters remain Shadow/Mock-only and pass conformance/replay.

## Phase 4 — Approval and Enforce Candidate

- [ ] **EN-001:** add atomic hierarchical Budget reservations. Depends: C4.
- [ ] **EN-002:** add Budget commit/release/expiry and recovery. Depends: EN-001.
- [ ] **EN-003:** implement hash-bound Approval domain/store. Depends: C5, EN-001.
- [ ] **EN-004:** add authenticated Approval/Admin APIs and multi-party controls. Depends: EN-003.
- [ ] **EN-005:** issue persistent single-use Execution Grants. Depends: EN-002, EN-004, RA-003.
- [ ] **EN-006:** add audited Kill Switch and default-off Enforce flag. Depends: EN-004, EN-005.
- [ ] **EN-007:** build Mock Enforce path and unknown-state handling. Depends: EN-005, EN-006, RA-004.
- [ ] **EN-008:** enable x402 sandbox execution and delivery verification. Depends: EN-007, RA-005.
- [ ] **EN-009:** enable Safe sandbox execution through external signer. Depends: EN-007, RA-006.
- [ ] **EN-010:** enable Hyperliquid sandbox execution through external API wallet. Depends: EN-007, RA-007.
- [ ] **EN-011:** implement settlement proof and reconciliation worker. Depends: EN-007..EN-010.
- [ ] **EN-012:** run failure drills and independent Enforce security review. Depends: EN-008..EN-011.
- [ ] **Checkpoint C6:** only explicitly approved sandbox/environment can enable Enforce; default remains off.

## Phase 5 — Ecosystem

- [ ] **EC-001:** TypeScript SDK with shared hashes/signature vectors. Depends: C4.
- [ ] **EC-002:** Python SDK with the same protocol contract. Depends: EC-001 contract.
- [ ] **EC-003:** MCP middleware that cannot bypass ATF decisions. Depends: EC-001, C5.
- [ ] **EC-004:** stabilize versioned public specifications and Adapter guide. Depends: released contracts.
- [ ] **EC-005:** launch documentation site, RFC workflow and release provenance. Depends: EC-004.
