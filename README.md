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
  canonical serialization and hashing. Unknown core fields are rejected;
  arbitrary extensions survive only inside object-valued `context` or
  `metadata` and are hash-bound.
- `crates/atf-identity` — Agent registration records and Ed25519
  identity-signature verification over an Intent's canonical hash.
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
  tables for organizations, Intents, Evaluations, Decisions, per-organization
  Audit heads/events, and schema metadata. It row-locks each organization's
  head for concurrent Audit append and can reload/verify canonical bytes,
  hashes, sequence, predecessor links, and the head after restart. Its two
  coarse repository transactions atomically commit canonical Intent +
  `RECEIVED/v1` + `IntentReceived`, then typed Identity/Policy/Risk/Simulation
  evidence + Evaluation + Decision + the final lifecycle state at `v6`.
  Migration 0002 stores state, optimistic version, contract version, update
  time, and the last state-producing Audit event pointer. Contract-v1 reads
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
closes the Intent envelope/version contract without changing the compatible
v1 fixture hash. Semantic validation is still incomplete; `DS-009` is next.

`schemas/` has `transaction-intent.schema.json` (enforced by `atf-intent`),
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
   verification (PRD §17.2).~~ Done as a library: an in-memory registry
   verifying a raw Ed25519 signature over `intent.canonical_hash()`, key
   rotation (multiple valid keys per Agent), and status gating
   (PAUSED/REVOKED/EXPIRED can't submit even with a valid signature). Still
   not called from `services/gateway` — see item 8.
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

### Remaining before Phase 2 can close out

- ~~Restore the `cargo deny 0.20.2` baseline.~~ Done: reviewed and explicitly
  allowed the two new permissive transitive licenses, exact-versioned every
  local workspace dependency, retained wildcard/source denial, and pinned CI
  to the official cargo-deny 0.20.2 Action release commit.
- ~~PostgreSQL request-path persistence and restart/second-instance Decision
  recovery.~~ Done through DS-005 with no process-local Decision/Audit
  fallback. Evaluator leases/fencing, exact idempotent retry, and recovery of
  admitted-but-unfinalized work remain.
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
- Rust semantic validation and versioned Intent Profiles for cross-field and
  action-specific invariants.
- Concurrent, durable idempotency plus signed-envelope Nonce replay
  protection.
- Domain-separated `atf-identity` Gateway wiring before Policy/Risk,
  including organization binding and key validity windows.
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
  recovery/idempotency, Gateway identity, deterministic replay,
  provenance, versioned bundles, Audit query/metrics, and security re-audit.
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

# Validate an intent against the JSON Schema + canonical hash
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
