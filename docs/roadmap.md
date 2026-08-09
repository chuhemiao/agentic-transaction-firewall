# Roadmap

This is the security-delivery view of the roadmap. `README.md` remains the
live feature-status summary; `docs/PRD.md` §31 remains the product plan. The
detailed dependency graph, task acceptance criteria and verification commands
are in [`../tasks/plan.md`](../tasks/plan.md); the one-item-at-a-time execution
queue is [`../tasks/todo.md`](../tasks/todo.md). Gap evidence remains in
`docs/audit-gap-matrix.md`, and the execution-last rationale is recorded in
`docs/decisions/0001-durable-shadow-before-enforce.md`. The accepted
durable-state transaction and Audit-chain contract is
`docs/decisions/0002-durable-state-contract.md`; the accepted operator trust
boundary is `docs/decisions/0003-operator-authentication.md`.

## Current release: Durable Shadow Mode

The P0.x numbers identify product capabilities, not a literal implementation
order. The executable order is:

1. durable state and lifecycle (`DS-001`..`DS-007`);
2. strict Intent contract and authenticated/idempotent admission
   (`DS-008`..`DS-018`);
3. versioned Policy/Risk/Context before Decision binding and Replay
   (`DS-019`..`DS-027`);
4. stateful Risk, query/observability, operational hardening and re-audit
   (`DS-028`..`DS-040`).

- [x] BL-001 Restore the cargo-deny baseline without weakening wildcard,
  license, or source policy; pin CI to cargo-deny 0.20.2 semantics.
- [x] BL-002 Make that baseline warning-free: deny new duplicate versions,
  retain only exact-versioned compatibility exceptions with dependency-path
  reasons, and make local/CI `-D warnings` reject stale exceptions.
- [x] DS-001 Fix the PostgreSQL ownership boundary, per-organization
  chain-head locking, atomic admission/finalization, fenced evaluator
  recovery, and migration compatibility in ADR-0002.
- [x] DS-002 Add `atf-store`, embedded migrations, schema-version fail-closed
  checks, tenant constraints, and database-enforced append-only Audit rows;
  run the migration suite against PostgreSQL 17.10 in CI.
- [x] DS-003 Serialize each organization's Audit appends with a locked head;
  verify persisted canonical bytes/hash/order/head after restart and reject
  corruption before extending a bad tail.
- [x] DS-004 Commit canonical Intent + `IntentReceived` and Evaluation +
  Decision + bound `DecisionRecorded` in separate short transactions; gate
  reads on canonical/hash/Audit verification and prove rollback at injected
  Audit failures.
- [x] DS-005 Make PostgreSQL the Gateway's only Decision/Audit path; prove
  restart/second-instance reads and fail readiness/requests closed when the
  required store is unavailable.
- [x] DS-006 Define the initial 21-state lifecycle and exhaustive fail-closed
  transition table; add versioned typed payloads for all canonical Audit
  events and migrate current durable producers away from free-form JSON.
- [x] DS-007 Persist lifecycle state/version/event pointers, atomically emit
  the typed evaluation phases, replay evidence on reads, and prove stale-writer
  rejection plus batch rollback on PostgreSQL.
- [x] DS-008 Close the Intent core envelope in both Schema and Rust parsing,
  support only v1.0, retain extensions only in object-valued hash-bound
  `context`/`metadata`, and lock the compatible fixture's canonical hash.
- [x] DS-009 Add deterministic common semantic validation for financial
  bounds, ordered/limited timestamps, ULIDs, identifiers and purpose text;
  return stable structured codes and reject invalid Gateway input before
  durable admission or Policy/Risk.
- [x] DS-010 Dispatch the versioned Agent-Commerce Payment profile, enforce
  typed-resource and same-chain CAIP-2/10/19 relationships, forbid fields owned
  by other financial profiles, and reject every unsupported action pair before
  durable admission or Policy/Risk.
- [x] DS-011 Standardize safe Gateway errors as
  `{code,message,request_id,details}`, generate a server-owned request ID for
  every response, and prove Schema/common/Profile rejection leaves no durable
  record before Policy/Risk.
- [x] DS-012 Add the atomic PostgreSQL idempotency reservation, database-clock
  evaluator lease renewal/reclaim, generation fencing, fail-closed recovered
  completion, and immutable Evaluation/Decision/hash result binding.
- [x] DS-013 Return the verified original Decision for completed same-hash
  retries, renew active leases between evaluation stages, converge concurrent
  callers on one durable result, and recover expired admissions after restart
  as one generation-fenced fail-closed `Decision(ERROR)`.
- [x] DS-014 Replace raw Intent-hash signatures with the canonical
  `ATF_INTENT_V1` Envelope, strict binding/time validation, exact Key ID
  selection, stable errors and a published Ed25519 conformance vector.
- [x] DS-015 Persist canonical organization-scoped Agent and exact Ed25519
  public-key lifecycle records with activation/expiry/revocation windows,
  atomic typed Audit evidence, restart verification and offline public-key-only
  operator commands.
- [x] DS-016 Require the canonical detached Identity Envelope/signature before
  Policy/Risk; atomically bind hashed Nonces to the exact durable
  Agent/Key/Intent/idempotency tuple and persist typed verified, rejected and
  replay evidence. Exact retry, concurrent conflict, restart, tenant isolation
  and tamper tests are green.
- [x] DS-017 Accepted ADR-0003 selects Gateway-validated short-lived RFC 9068
  access tokens plus per-request PostgreSQL subject/organization-role
  authorization. Agent/operator principals are disjoint and no selector,
  proxy Header, anonymous path, or shared account grants authority. Explicit
  maintainer approval was recorded on 2026-08-08.
- [x] DS-018 Implement the accepted verifier, durable operator/role lifecycle,
  typed principals, organization-scoped Decision-read RBAC, and
  non-enumerating denial behavior. Migration 0006, offline subject/role
  commands, configured HTTPS JWT/JWKS validation, per-request local revocation,
  restart/redaction/confused-deputy coverage and real HTTP/PostgreSQL smoke are
  complete.

- [x] P0.1 PostgreSQL persistence for accepted Intents, Decisions, and the
  append-only Audit chain. The Gateway has no process-local fallback, and real
  PostgreSQL tests cover concurrent append, restart, second-instance reads,
  tenant scoping, and unavailable-storage readiness.
- [x] P0.2 Intent lifecycle state machine. The 22 stable states, terminal states,
  complete allowed-transition table, explicit module outcomes, typed event
  payloads, PostgreSQL state/version enforcement, intermediate phase events,
  replay verification, and atomic event/state transitions are implemented and
  tested. New Gateway admissions use `IDENTITY_VERIFIED`; the old
  `IDENTITY_UNVERIFIED` state remains compatibility-only and is never upgraded
  or interpreted as authenticated. The product remains evaluate-only because
  execution is not implemented.
- [x] P0.3 Record every gateway outcome as `DecisionRecorded`, bound to the
  Intent hash. Duplicate-purchase history counts only same-organization
  `PERMIT` decisions; DENY does not poison later requests.
- [x] P0.4 Durable, concurrent idempotency and replay protection. DS-012/DS-013
  provide reservation/result storage, lease/fencing, exact completed retry and
  request-driven fail-closed recovery; DS-016 adds PostgreSQL-authoritative
  authenticated Nonce replay protection.
- [x] P0.5 Domain-separated Agent identity envelopes wired before Policy and
  Risk, with current durable exact-Key verification and typed request evidence.
- [x] Versioned Risk Rule Set. DS-021 binds engine compatibility, enabled
  rules, severities, thresholds, deny lists, missing-data behavior, history
  windows and lifecycle accounting boundaries into a canonical hash returned
  by every Risk result and recorded by current Gateway evidence.
- [x] P0.6 Versioned `EvaluationContext`; DS-023 persists the exact immutable
  input snapshot before evaluation, and DS-024 makes Policy/Risk validate and
  consume that snapshot without wall-clock or separate privileged inputs.
- [x] P0.7 Strong Decision binding plus original/counterfactual deterministic
  replay. DS-025 completes the closed canonical Decision v1 and matching Audit
  binding; DS-026 completes authorized exact Original Replay with immutable
  Risk archives and non-authoritative evidence. DS-027 adds immutable,
  separately identified Counterfactual output with exact selected artifacts,
  changed-outcome reporting and no authoritative overwrite.
- [x] DS-028 Bounded durable Risk history. An indexed repeatable-read query
  records exact organization/Agent/resource/time/sequence inputs and its
  optional prior permitted result; Gateway, Risk and both Replay modes share
  the typed snapshot contract without handing Audit events to the evaluator.
- [x] DS-029 Asset-aware daily cumulative spend. The Rule Set fixes a
  `PERMITTED` boundary, valuation asset, limit and window; Store records a
  fixed-point per-asset aggregate at the Context repository boundary, and
  missing direct verified quote evidence produces a restrictive finding.
- [x] DS-030 Normalized first-time destination. The Payment Profile's
  versioned EIP-155 normalizer derives a lowercase organization-wide history
  key without changing signed Intent bytes; Store returns at most one verified
  prior permit at the Context boundary, and DENY/cross-tenant/unsafe
  normalization cannot establish familiarity or silently preserve Permit.
- [x] DS-031 Accepted request/order frequency. Rule Set v1.3.0 fixes the
  `AGENT`/`PROFILE` scope, maximum, window and `REQUESTED` boundary; migration
  0014 indexes immutable Profile/action-bound admission evidence, and real
  PostgreSQL tests cover inclusive boundaries, concurrent threshold
  enforcement and completed-retry non-inflation.
- [x] DS-032 Organization-scoped Audit queries. Current auditor/admin
  authority is rechecked in the repeatable-read Store transaction; exact
  filters and a tenant/filter/chain-prefix-bound cursor expose only verified,
  append-stable pages of at most 100 events.
- [x] DS-033 Safe metrics and tracing. Prometheus output uses only closed
  route/outcome/severity dimensions for request, Decision, Policy, Risk,
  Replay, idempotency, freshness and Audit-failure signals; JSON request spans
  link the response Request ID to allowlisted durable Audit event IDs, and
  captured canaries prove credential/signature/payload redaction.
- [x] DS-034 Bounded HTTP boundary. Every route has finite body/Header and
  request limits, Intent evaluation has a nested deadline, and process-local
  source plus verified-principal GCRA limits return stable safe errors. The
  server defaults to loopback and makes trusted-proxy TLS assumptions explicit.
- [x] DS-035 Fail-closed serving dependencies. Liveness remains independent of
  readiness, which now verifies compatible PostgreSQL, the configured signed
  active Policy and Operator JWKS. Database, Bundle, bounded-history Snapshot,
  Audit and lock failures have closed metrics and cannot expose a new Decision
  before its durable evidence commits atomically.
- [x] DS-036 Repeatable multi-instance persistence suite. One local/CI command
  runs migrations, Audit/lifecycle/idempotency/Nonce races, restart recovery,
  two independent Gateway states and bounded real lock/deadlock failures on
  PostgreSQL 17.10. CI repeats it twice; test-only Compose runs the same gate.
- [x] DS-037 Replay/property/fuzz conformance. Fixed pure vectors lock exact
  Original/Counterfactual Context and Decision hashes plus lineage; Proptest
  covers string-only Amount encoding and every attacker-resealed binding
  class; real PostgreSQL Replay and a bounded nightly Intent fuzz smoke run in
  CI.
- [~] P0.8 Context provenance, freshness, and trusted enrichment. DS-022 adds
  the closed canonical Evidence contract, exact source/kind trust allowlists,
  optional strict Ed25519 verification, explicit freshness and the Risk
  privileged-context firewall; DS-023 durably binds verified Evidence and its
  trust-policy identity. Production enrichers remain future work.
- [x] P0.9 Versioned, hashed, scoped, signed Policy Bundles. DS-019 provides
  deterministic identity/Cedar Schema validation; DS-020 adds immutable
  archives, strict publisher proof, audited active pointers, authenticated
  activation/rollback and per-request Gateway resolution.
- [x] P0.10 Metrics and organization-scoped Audit query API for current
  components. DS-032 completes the bounded verified query surface and DS-033
  completes low-cardinality metrics plus safe trace/Audit correlation. Future
  component metrics ship with their Simulator/Adapter/Approval owners.

No real wallet, exchange, approval, or execution integration starts before
Durable Shadow Mode is complete and re-audited.

**Immediate next task:** `DS-038` — add dependency vulnerability, secret and
SAST gates with pinned tools and reviewed exception ownership.

## Later releases

- **Reference simulation/adapters:** Mock Simulator and Adapter first, then
  x402, Safe, and Hyperliquid behind conformance tests.
- **Approval and Enforce Mode:** approval binding, single-use execution
  grants, Kill Switch, settlement verification, and reconciliation.
- **Community:** TypeScript/Python SDKs, MCP middleware, and documentation
  site.
