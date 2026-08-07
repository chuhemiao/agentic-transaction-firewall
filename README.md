# Agentic Transaction Firewall (ATF)

Agentic Transaction Firewall is a protocol-neutral, wallet-neutral, venue-neutral
open-source control layer for AI Agent financial transactions.

It sits between AI Agents and wallets, exchanges, DeFi protocols, Treasury systems,
x402 services, and other payment networks. Every irreversible or high-risk
financial action must be expressed as a canonical Transaction Intent and pass
through identity verification, policy evaluation, financial risk evaluation,
simulation, and (when required) approval before it is allowed to execute.

```
Agent Intent
  -> Canonical Transaction Intent
  -> Identity & Semantic Validation
  -> Versioned Evaluation Context
  -> Policy Evaluation
  -> Financial Risk Evaluation
  -> Simulation
  -> Bound Decision
  -> Approval
  -> Single-use Execution Grant
  -> Execution Adapter
  -> Settlement Verification
  -> Immutable Audit
```

ATF does not create wallets, does not custody assets, does not invent a new
payment protocol, and does not replace exchanges, Fireblocks, Privy, Safe,
Coinbase CDP, or AWS AgentCore. It provides the shared control-plane semantics
those systems can sit behind.

Current product vision and release gates: [`docs/PRD.md`](docs/PRD.md)
(v1.2, Durable Shadow Mode revision).

## Status

This repository is in **Phase 2: Durable Shadow Mode**. Phase 1 is complete;
the current release gate requires persistence, lifecycle/idempotency,
Gateway identity, deterministic replay, context provenance, versioned bundles,
and observability before any real execution work begins (PRD §31–32).
Only the following crates are implemented so far:

- `crates/atf-core` — shared domain primitives, stable Intent lifecycle states,
  and the fail-closed pure transition validator.
- `crates/atf-intent` — canonical Transaction Intent type, closed JSON Schema
  and matching fail-closed Serde shape, supported `spec_version` set (`1.0`),
  canonical serialization and hashing, plus deterministic common semantic
  validation. Unknown core fields are rejected; arbitrary extensions survive
  only inside object-valued `context` or `metadata` and are hash-bound.
  Financial bounds, millisecond-aligned ordered timestamps with a 24-hour
  maximum TTL, valid ULIDs, and bounded nonblank identifiers/text fail closed
  with stable machine-readable codes. A closed profile dispatcher now accepts
  exactly the versioned Agent-Commerce Payment profile
  (`payment/purchase_api_resource`), enforces its resource and CAIP-2/10/19
  chain-binding rules, and rejects every other action pair as unsupported.
- `crates/atf-identity` — Agent registration records plus the DS-014
  `ATF_INTENT_V1` Identity Envelope: explicitly sorted canonical JSON binds
  organization, Agent, exact key ID, Intent hash, five-minute lifetime, nonce,
  audience and environment before strict Ed25519 verification. The registry
  never tries every key and returns typed verified identity facts. Persistence,
  nonce consumption and Gateway wiring remain DS-015/DS-016.
- `crates/atf-policy` — minimal Cedar policy evaluation over a Transaction
  Intent.
- `crates/atf-risk` — a first Financial Risk Engine pass: deterministic,
  stateless MVP rules (request expiry, single-transaction cap, fee ratio,
  vendor price deviation, high-risk network/protocol), plus one
  history-dependent rule (duplicate purchase within 24h). The Gateway runs it
  over the organization's verified PostgreSQL Audit chain; local callers can
  still supply an `atf-audit::AuditLedger`. It counts only prior
  `DecisionRecorded(PERMIT)` events — a received or denied request is not
  treated as a purchase.
- `crates/atf-audit` — the Audit Ledger domain logic: hash-chained events,
  append-only tamper detection (`verify_chain`), and version-1 typed payloads
  for all canonical PRD lifecycle/administrative events. Event-to-state
  effects reuse `atf-core`'s transition table; malformed, mismatched, unknown,
  or post-terminal evidence fails closed. Its standalone `AuditLedger` remains
  an in-memory domain utility; the Gateway uses `atf-store` as the persistent
  writer/verifier and has no in-memory Audit fallback.
- `crates/atf-decision` — the Decision model and the real PRD §10.1 merge
  algorithm (Policy + Risk; no Simulator branch yet).
- `crates/atf-store` — the SQLx/PostgreSQL persistence boundary, embedded
  migration runner, schema compatibility check, and initial constrained
  tables for organizations, Intents, Evaluations, Decisions, idempotency
  reservations, per-organization Audit heads/events, and schema metadata. It row-locks each organization's
  head for concurrent Audit append and can reload/verify canonical bytes,
  hashes, sequence, predecessor links, and the head after restart. Its two
  coarse repository transactions atomically commit canonical Intent +
  `RECEIVED/v1` + `IntentReceived`, then typed Identity/Policy/Risk/Simulation
  evidence + Evaluation + Decision + the final lifecycle state at `v6`.
  Migration 0002 stores state, optimistic version, contract version, update
  time, and the last state-producing Audit event pointer. Migration 0003 adds
  immutable organization/key -> Intent-hash bindings, database-clock evaluator
  leases, monotonically increasing fencing generations, and completed
  Evaluation/Decision/hash references. Admission creates the reservation,
  Intent and `IntentReceived` atomically; finalization verifies the active
  lease and completes the reservation with the Decision transaction. Expired
  leases can be conditionally reclaimed, but generation >1 can only finalize
  a fail-closed `ERROR` until Evaluation Context snapshots exist. Contract-v1 reads
  replay typed events and reject any materialized-state mismatch; concurrent
  finalizers cannot both advance the same Intent. The Gateway uses this
  boundary for all accepted Intents, Evaluations, Decisions, Audit writes, and
  Decision reads.
- `cli/atf-cli` — `atf validate-intent`, `atf evaluate`, and `atf policy test`.
- `services/gateway` (`atf-gateway`) — an HTTP service wiring Policy, Risk
  (including the history-dependent duplicate-purchase check), Decision, and
  Audit into one request path: `POST /v1/intents` and
  `GET /v1/intents/{id}/decision`, plus `/healthz`/`/readyz`. PostgreSQL is
  required at startup, `/readyz` verifies live storage/schema compatibility,
  and restart/second-instance reads return the committed Decision. GET uses
  `X-ATF-Organization-ID` to select the tenant record, but that header is not
  authentication. Until Identity is wired, the Gateway emits
  `IdentityVerificationSkipped` and stores `IDENTITY_UNVERIFIED`; that branch
  is Shadow-only and conveys no execution authority. Identity and organization
  authorization are still missing.
  Business-route, Router and durable-store failures now share the stable
  `{code,message,request_id,details}` JSON contract documented in
  `docs/api.md`. Every response receives a fresh server-generated
  `X-ATF-Request-ID`; raw Schema, SQL, policy and key/internal error text is
  not returned. Full trace/Audit propagation remains later observability work.
  A second same-hash request with an active evaluator/recovery lease stops
  before Policy/Risk, while a same-key/different-hash request returns
  `IDEMPOTENCY_CONFLICT`. DS-013 now returns the verified original Decision for
  completed same-hash retries without re-evaluation, renews leases between
  Policy/Risk stages, and conditionally reclaims expired admissions after a
  retry. Until immutable Evaluation Context exists, recovered work records one
  fail-closed `Decision(ERROR)` instead of re-evaluating under current inputs.
  Never executes anything — evaluate-only.

The durable-state contract is fixed in
[`ADR-0002`](docs/decisions/0002-durable-state-contract.md): PostgreSQL is the
single authority, Audit chains are serialized per organization, and admission
and finalization use separate atomic transactions with fenced evaluator
recovery. `DS-002` provides the store/migration/schema foundation; the
`DS-003` concurrent append/verifier, `DS-004` admission/finalization
repositories, `DS-005` Gateway cutover, and `DS-006` lifecycle/typed Audit
domain contract are complete. `DS-007` persists and replays lifecycle state
and atomically emits Identity/Policy/Risk/Simulation/Decision events. `DS-008`
closes the Intent envelope/version contract. `DS-009` adds common semantic
validation before durable admission and Policy/Risk. Its documented fixture
migration replaces historical 24-character pseudo-ULIDs and multi-decade TTLs
with a valid ULID and five-minute lifetime, so the fixture's locked canonical
hash changes intentionally. `DS-010` adds the protocol-neutral
`atf.agent-commerce.payment` v1.0 profile used by the example, migrates its
network/asset/destination identifiers to CAIP form, and locks the resulting
new hash. x402 proof/delivery semantics remain a later Adapter concern.
`DS-011` centralizes safe Gateway errors, adds server-owned request IDs, and
proves Schema/common/Profile rejection leaves all durable business tables
empty before Policy/Risk. `DS-012` adds the atomic durable idempotency
reservation, evaluator lease/fencing token and immutable completed-result
binding. `DS-013` adds exact completed retry, stage-boundary lease heartbeats,
concurrent result convergence, and request-driven fail-closed recovery of
expired admissions. `DS-014` replaces raw-hash signatures with the canonical,
domain-separated Identity Envelope and exact-key verification. `DS-015`,
durable Agent/key lifecycle and offline provisioning, is next.

`schemas/` has `transaction-intent.schema.json` (enforced by `atf-intent`),
`profiles/payment-intent-v1.schema.json` (the structural companion to the
Rust profile validator),
`decision.schema.json` (validated in CI against real `atf-decision` output),
and `audit-event.schema.json` (validated in CI against real `atf-audit`
output).

Everything else in the workspace (simulator, approval engine, adapters,
SDKs) is scaffolded as an empty directory with a `README.md` describing
what belongs there and which roadmap phase will fill it in — see PRD §31
for the phase plan.

No real wallet, exchange, or production secret is wired into this repository.
Execution is not implemented; every code path defaults to **Shadow Mode**
semantics (evaluate only, never execute).

## Roadmap

### Immediate TODO

1. ~~`atf-risk` — a first Financial Risk Engine pass.~~ Done: request
   expiry, single-transaction cap, fee ratio, vendor price deviation,
   high-risk network/protocol.
2. ~~Finish the PRD §10.1 Decision merge algorithm in `atf-decision`.~~ Done
   for Policy + Risk (Simulator branch still pending `atf-simulator`).
3. ~~A `conformance/policy-tests` harness (`atf policy test`).~~ Done: loads
   `*.json` cases (inline intent + expected Cedar permit/forbid), runs them
   against a declared policy bundle, exits non-zero on any failure.
4. ~~Risk rules that need history/state (PRD §12.2).~~ Partly done:
   `atf_risk::evaluate_with_history`/`evaluate_with_events` add a
   duplicate-purchase check
   (same Organization + Agent + Resource within 24h, reading only prior
   `DecisionRecorded(PERMIT)` events) — verified end-to-end through
   `services/gateway`; a prior DENY does not poison a later valid request,
   and one organization's history cannot affect another. Daily cumulative
   spend, first-time destination address, and order frequency are still
   not implemented; their configured lifecycle boundary (PERMITTED vs.
   EXECUTED vs. SETTLED) must be explicit.
5. ~~`atf-identity` — Agent registration + Ed25519 identity-signature
   verification (PRD §17.2).~~ Done as a library and hardened in DS-014: its
   in-memory registry verifies only the declared Key ID over canonical
   domain-separated Envelope bytes, supports explicit rotation overlap, and
   gates Agent status, organization, environment and lifetime. Still not
   called from `services/gateway` — see item 8 and item 14.
6. ~~`schemas/decision.schema.json` and `schemas/audit-event.schema.json`.~~
   Done: both validated in CI against real output (`atf-decision` and
   `atf-audit` respectively).
7. ~~`atf-audit` — the Audit Ledger (PRD §16).~~ Done as a library:
   hash-chained `AuditEvent`s, append-only, `verify_chain()` detects
   after-the-fact tampering. The Gateway now writes and verifies the durable
   per-organization chain through `atf-store`; the in-memory ledger is not a
   production fallback.
8. ~~`services/gateway` — wire Policy/Risk/Decision/Audit into one request
   path.~~ Done: `POST /v1/intents` runs Policy → (if permitted) Risk →
   Decision merge, atomically persists `IntentReceived`, Evaluation, Decision,
   typed intermediate phase events, lifecycle state/version, and bound
   `DecisionRecorded`, and reads the verified Decision back for
   `GET /v1/intents/{id}/decision`. Policy/Risk/Simulation outcomes are typed
   in canonical Evaluation evidence and the durable Audit chain. Verified across two
   real Gateway processes sharing one PostgreSQL database, not just in-process
   tests. **Not** wired in:
   `atf-identity` (no endpoint to register an Agent's key yet — that's an
   Admin API concern, PRD §17.3), Simulation, Approval.
9. ~~Common Transaction Intent semantic validation.~~ Done in DS-009:
   financial/time/ULID/text invariants produce stable ordered codes, CLI
   failures exit non-zero, and Gateway integration proves invalid input leaves
   no Intent, Evaluation, Decision, or Audit row before Policy/Risk.
10. ~~Versioned Intent Profile dispatch and the supported Agent-Commerce
    Payment profile.~~ Done in DS-010: only
    `payment/purchase_api_resource` under `spec_version: "1.0"` is accepted;
    typed resource, CAIP-2 network, same-chain CAIP-19 asset and CAIP-10 payee
    relationships are enforced, fields belonging to contract/trading profiles
    are forbidden, and every other action pair fails closed before admission.
11. ~~Stable Gateway error and validation-order contract.~~ Done in DS-011:
    every business/Router failure returns fixed
    `{code,message,request_id,details}` JSON, every response carries a fresh
    server-owned request ID, internal diagnostics stay out of responses, and
    PostgreSQL tests prove all validation layers finish before any Intent,
    Evaluation, Decision, Audit, Policy or Risk result can become authoritative.
12. ~~Atomic durable idempotency reservation and evaluator fencing.~~ Done in
    DS-012: migration 0003 binds each organization/key to one Intent hash,
    admission and finalization include the reservation/result in their atomic
    transactions, concurrent callers produce one lease owner, renew/reclaim
    uses the database clock and generation fencing, and completed result rows
    are immutable.
13. ~~Exact completed retry and fenced Gateway recovery.~~ Done in DS-013:
    completed same-hash POSTs return the verified original Decision without
    Policy/Risk or new Audit events; active work returns bounded 409; normal
    evaluation renews its lease between stages; and an expired admission is
    conditionally reclaimed after restart and terminated once as
    `RECOVERY_CONTEXT_UNAVAILABLE` until Evaluation Context snapshots exist.
14. ~~Domain-separated Agent Identity Envelope.~~ Done in DS-014:
    `ATF_INTENT_V1` sorted canonical bytes bind organization, Agent, exact
    Key ID, Intent hash, a closed five-minute lifetime, nonce, audience and
    environment. Strict Ed25519 verification has no raw-hash/any-key fallback;
    a published vector and mutation tests lock the cross-language contract.

### Remaining before Phase 2 can close out

- ~~Restore the `cargo deny 0.20.2` baseline.~~ Done: reviewed and explicitly
  allowed the two new permissive transitive licenses, exact-versioned every
  local workspace dependency, retained wildcard/source denial, and pinned CI
  to the official cargo-deny 0.20.2 Action release commit.
- ~~PostgreSQL request-path persistence and restart/second-instance Decision
  recovery.~~ Done through DS-005 with no process-local Decision/Audit
  fallback. DS-012 adds evaluator leases/fencing and atomic idempotency result
  binding; DS-013 adds exact idempotent result return and request-driven,
  generation-fenced recovery of admitted-but-unfinalized work.
- ~~Stable lifecycle and typed Audit domain contract.~~ Done in DS-006: 21
  states, an exhaustively tested transition table, explicit `NOT_RUN` module
  outcomes, 27 canonical typed payloads, and a strict version-1 JSON Schema.
  DS-007 extends the active contract to 22 states/28 events with an explicit
  Shadow-only `IDENTITY_UNVERIFIED` branch.
- ~~Transactional lifecycle persistence and typed phase evidence.~~ Done in
  DS-007: migration 0002, optimistic versioning/row locking, typed event
  replay, atomic five-phase finalization, race/rollback/tamper tests, and
  explicit Policy/Risk `DECIDED_ERROR` evidence.
- ~~Close the Intent envelope and supported-version contract.~~ Done in
  DS-008: top-level and nested unknown core fields fail both Schema and direct
  Rust parsing, only `spec_version: "1.0"` is accepted, object-valued
  `context`/`metadata` remain hash-bound extension points, and the existing v1
  fixture has a locked golden canonical hash.
- ~~Common Rust semantic validation for financial, time, ULID, identifier and
  text invariants.~~ Done in DS-009 with deterministic structured violations
  and stable codes. The valid x402 fixture received a documented ULID/TTL
  migration and a new locked golden hash.
- ~~Versioned Intent Profiles for action-specific invariants.~~ Done for the
  supported Agent-Commerce Payment profile in DS-010; all other action pairs
  now fail closed. Protocol-specific x402, Safe, Hyperliquid and additional
  financial profiles remain Phase 3 work.
- ~~Stable safe API errors and validation-before-evaluation ordering.~~ Done
  in DS-011 with an exact documented JSON contract, server-generated request
  IDs, fixed status/code mappings, Router fallbacks, and durable zero-write
  evidence for structural/common/Profile rejection.
- ~~Concurrent durable idempotency reservation, evaluator fencing, and atomic
  result binding.~~ Done in DS-012. Same-hash result return/recovery is
  complete in DS-013; DS-014 defines the signed Envelope, while durable
  Key/Agent state and atomic Nonce replay protection remain DS-015/DS-016.
- Durable Agent/Key lifecycle and `atf-identity` Gateway wiring before
  Policy/Risk, including atomic Nonce consumption and Identity Audit evidence.
- Versioned `EvaluationContext`, Context Provenance, Policy/Risk hashes, and
  Original/Counterfactual Replay.
- Organization-scoped Audit Query API, metrics, safe tracing, and API
  security controls.
- The remaining history-dependent Risk rules after their PERMITTED,
  EXECUTED, or SETTLED accounting boundary is explicit.

The security-audit baseline and prioritized acceptance criteria are tracked
in [`docs/audit-gap-matrix.md`](docs/audit-gap-matrix.md); the phase-level
delivery view is in [`docs/roadmap.md`](docs/roadmap.md). The dependency-ordered
implementation plan and executable checklist are in
[`tasks/plan.md`](tasks/plan.md) and [`tasks/todo.md`](tasks/todo.md).

### Phased plan (PRD §31)

- **Phase 1 (done)**: Policy Kernel + Decision merge + conformance harness.
- **Phase 2 (Durable Shadow Mode, in progress)**: the PostgreSQL-backed
  Gateway foundation and core libraries exist; the remaining release gate is
  Gateway identity/nonce protection, deterministic replay, provenance,
  versioned bundles, Audit query/metrics, and security re-audit.
- **Phase 3 (reference scenarios)**: `atf-simulator` + the three reference
  Adapters (Hyperliquid, Safe, x402) + the Adapter Conformance Test Suite.
- **Phase 4 (Approval & Enforce Mode)**: `atf-approval` + `atf-reconciliation`
  + execution-hash binding + Kill Switch.
- **Phase 5 (community)**: TypeScript/Python SDKs + MCP middleware + docs
  site.

## Getting started

```bash
cargo build
ATF_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
  cargo test

# Apply/verify the embedded durable-state migration
DATABASE_URL=postgres://postgres:postgres@localhost:5432/atf \
  cargo run -p atf-store --bin atf-store-migrate

# Provision a development organization, then run the durable Gateway
psql postgres://postgres:postgres@localhost:5432/atf \
  -c "INSERT INTO organizations (organization_id) VALUES ('alpha-lab') ON CONFLICT DO NOTHING"
DATABASE_URL=postgres://postgres:postgres@localhost:5432/atf \
  ATF_POLICIES_DIR=policies/examples PORT=8080 cargo run -p atf-gateway

# Validate an intent against the JSON Schema + common/profile semantics + canonical hash
cargo run -p atf-cli -- validate-intent examples/x402-research-agent/intent.json

# Evaluate an intent against an example Cedar policy bundle
cargo run -p atf-cli -- evaluate examples/x402-research-agent/intent.json --policies policies/examples
```

## Repository layout

See [`docs/architecture.md`](docs/architecture.md) for the full component
breakdown, and PRD §20 for the target Rust workspace layout.

Picking up work here as an AI agent? Start with [`AGENTS.md`](AGENTS.md).

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

## Security

See [`SECURITY.md`](SECURITY.md) for how to report a vulnerability, and
[`docs/threat-model.md`](docs/threat-model.md) for the threat model this
project is designed against.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).
