# Roadmap

This is the security-delivery view of the roadmap. `README.md` remains the
live feature-status summary; `docs/PRD.md` §31 remains the product plan. The
detailed dependency graph, task acceptance criteria and verification commands
are in [`../tasks/plan.md`](../tasks/plan.md); the one-item-at-a-time execution
queue is [`../tasks/todo.md`](../tasks/todo.md). Gap evidence remains in
`docs/audit-gap-matrix.md`, and the execution-last rationale is recorded in
`docs/decisions/0001-durable-shadow-before-enforce.md`. The accepted
durable-state transaction and Audit-chain contract is
`docs/decisions/0002-durable-state-contract.md`.

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

- [x] P0.1 PostgreSQL persistence for accepted Intents, Decisions, and the
  append-only Audit chain. The Gateway has no process-local fallback, and real
  PostgreSQL tests cover concurrent append, restart, second-instance reads,
  tenant scoping, and unavailable-storage readiness.
- [x] P0.2 Intent lifecycle state machine. The 22 stable states, terminal states,
  complete allowed-transition table, explicit module outcomes, typed event
  payloads, PostgreSQL state/version enforcement, intermediate phase events,
  replay verification, and atomic event/state transitions are implemented and
  tested. Identity is explicitly `IDENTITY_UNVERIFIED` until DS-016, so this
  remains evaluate-only.
- [x] P0.3 Record every gateway outcome as `DecisionRecorded`, bound to the
  Intent hash. Duplicate-purchase history counts only same-organization
  `PERMIT` decisions; DENY does not poison later requests.
- [ ] P0.4 Durable, concurrent idempotency and replay protection.
- [ ] P0.5 Domain-separated Agent identity envelopes wired before Policy and
  Risk.
- [ ] P0.6 Versioned `EvaluationContext`; remove direct wall-clock and
  untrusted context reads from decision-making rules.
- [ ] P0.7 Original and counterfactual deterministic replay.
- [ ] P0.8 Context provenance, freshness, and trusted enrichment.
- [ ] P0.9 Versioned, hashed, scoped, validated Policy Bundles.
- [ ] P0.10 Metrics and organization-scoped Audit query API.

No real wallet, exchange, approval, or execution integration starts before
Durable Shadow Mode is complete and re-audited.

**Immediate next task:** `DS-012` — add the atomic PostgreSQL idempotency
reservation and evaluator-lease state required for exact retry, conflict and
recovery semantics.

## Later releases

- **Reference simulation/adapters:** Mock Simulator and Adapter first, then
  x402, Safe, and Hyperliquid behind conformance tests.
- **Approval and Enforce Mode:** approval binding, single-use execution
  grants, Kill Switch, settlement verification, and reconciliation.
- **Community:** TypeScript/Python SDKs, MCP middleware, and documentation
  site.
