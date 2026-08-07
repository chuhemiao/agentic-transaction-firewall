# Architecture (draft)

This is a working draft. The authoritative source is `docs/PRD.md`; this
document translates it into the current and target code layout.

## Target pipeline (PRD §1, §8.1)

```text
Agent Intent
  -> Canonical Transaction Intent   (atf-intent)
  -> Identity Verification          (atf-identity)
  -> Semantic Validation            (atf-intent profiles, planned)
  -> Versioned Evaluation Context   (planned)
  -> Policy Evaluation              (atf-policy, Cedar)
  -> Financial Risk Evaluation      (atf-risk)
  -> Simulation                     (atf-simulator)
  -> Bound Decision                 (atf-decision)
  -> Approval (if REVIEW)           (atf-approval)
  -> Single-use Execution Grant     (planned)
  -> Execution Adapter              (atf-adapter-*)
  -> Settlement Verification        (atf-reconciliation)
  -> Immutable Audit                (atf-audit)
```

## What exists today (Phase 2 in progress)

- **`atf-core`** — shared domain primitives: fixed-point `Amount`, `Timestamp`
  (RFC 3339), error types. *Implemented.*
- **`atf-intent`** — `TransactionIntent` type, JSON Schema validation,
  canonical serialization + SHA-256 hash. *Implemented.*
- **`atf-identity`** — Agent registration records (`AgentRecord`,
  `AgentStatus`) and an in-memory `IdentityRegistry` verifying a raw
  Ed25519 signature over `intent.canonical_hash()`, with key-rotation
  support (multiple valid keys per Agent) and status gating. *Implemented
  as a library — still not called from `services/gateway` (PRD §17.2): the
  gateway now exists, but there is no way to register an Agent's key
  through it yet, which is really an Admin API concern (PRD §17.3).*
- **`atf-policy`** — Cedar `PolicySet` parsing + minimal
  `evaluate(intent) -> cedar_policy::Response`. *Partially implemented: no
  Cedar Schema or versioned Bundle manifest yet.*
- **`atf-risk`** — deterministic, stateless MVP risk rules (request expiry,
  single-transaction cap, fee ratio, vendor price deviation, high-risk
  network/protocol) via `evaluate`, plus one history-dependent rule
  (duplicate purchase: same Organization + Agent + Resource within 24h) via
  `evaluate_with_history`, which reads only prior
  `DecisionRecorded(PERMIT)` events in an `atf_audit::AuditLedger`.
  *Implemented (partial — daily cumulative spend, first-time destination
  address, and order frequency, PRD §12.2, still need an explicit
  PERMITTED/EXECUTED/SETTLED accounting boundary).*
- **`atf-audit`** — `AuditEvent`/`EventType` (PRD §16.2 plus
  `DecisionRecorded`), a store-safe `NewAuditEvent` envelope, and an in-memory,
  append-only `AuditLedger` that hash-chains events and can `verify_chain()`
  to detect after-the-fact tampering (PRD §16.3). *Implemented as a
  library and called from `services/gateway`, but that request path still
  uses only the in-memory ledger; `atf-store`'s durable writer is not wired.*
- **`atf-decision`** — `Decision` type + the real PRD §10.1 merge algorithm,
  minus the Simulator branch (no `atf-simulator` yet). *Implemented
  (partial).*
- **`atf-store`** — one SQLx/PostgreSQL boundary with an embedded forward-only
  migration runner and fail-closed schema compatibility check. Migration 0001
  creates organization-scoped Intent/Evaluation/Decision records,
  per-organization Audit heads/events, canonical JSON plus exact bytes and
  SHA-256 hashes, composite tenant foreign keys, and append-only Audit
  triggers. It now serializes concurrent appends with a per-organization
  chain-head row lock and reloads/verifies the complete persisted chain under
  one consistent snapshot. DS-004 adds separate short admission and
  finalization repository transactions: immutable Intent + `IntentReceived`,
  then canonical Evaluation + Decision + foreign-key-bound
  `DecisionRecorded`. Read APIs expose only records whose canonical
  bytes/hashes and matching verified Audit evidence agree. *Implemented but
  unwired; Gateway cutover is DS-005.*
- **`cli/atf-cli`** — `atf validate-intent`, `atf evaluate`,
  `atf policy test`. *Implemented.*
- **`services/gateway`** (`atf-gateway`) — an Axum HTTP service:
  `POST /v1/intents` runs Intent validation -> Policy -> (if permitted)
  Risk (via `evaluate_with_history`, so duplicate-purchase detection is
  live) -> Decision merge, records four audit events per request including
  the resulting `DecisionRecorded`, and stores the Decision;
  `GET /v1/intents/{id}/decision` retrieves it;
  `/healthz`/`/readyz`. *Implemented — verified against a real bound
  socket, not just in-process tests (including the duplicate-purchase path:
  posting the same Agent+Resource twice really does turn `PERMIT` into
  `REVIEW` on the second request). Does not call `atf-identity` (see above)
  and has no persistent store (PRD §22): a process restart loses every
  recorded Decision and the whole audit ledger.*
- **Supply-chain baseline** — CI runs fmt, clippy, tests, and cargo-deny.
  cargo-deny is fixed at 0.20.2 in both local policy semantics and the pinned
  CI Action commit; local ATF crate dependencies carry exact `=0.1.0` version
  bounds as well as paths, while wildcard and unknown-source denial remain
  enabled. `Apache-2.0 WITH LLVM-exception` (Cedar build path) and `MIT-0`
  (JSON Schema path), plus ISC code and CDLA-Permissive-2.0 trust-anchor data
  on SQLx's Rustls path, are explicitly reviewed permissive licenses. Broader
  audit/secret/SAST/SBOM gates remain planned under GAP-CI-001.
- **Durable-state design** —
  [`ADR-0002`](decisions/0002-durable-state-contract.md) now fixes the
  PostgreSQL ownership boundary, per-organization Audit serialization, short
  admission/finalization transactions, and evaluator fencing/recovery rules.
  `atf-store`, the base migration, durable Audit writer/verifier, and the
  DS-004 admission/finalization transaction subset now exist. Gateway wiring,
  lifecycle/idempotency result state, leases/fencing, and typed Policy/Risk
  finalization events remain unimplemented.

Everything else under `crates/`, `sdk/`, `examples/`, `conformance/`,
`deploy/`, and `fuzz/` is a scaffolded directory with a
`README.md` describing what belongs there and which roadmap phase (PRD §31)
will fill it in. None of it is wired into the Cargo workspace yet.

## Accepted durable-state contract (partially implemented)

ADR-0002 makes PostgreSQL the only authoritative state for accepted Intents,
Evaluations, Decisions, idempotency, identity nonces, and Audit. The storage
crate owns cross-table transactions; the Gateway and domain crates must not
reconstruct them from table-level repositories.

Each organization has an independent Audit chain. Appenders lock that
organization's persisted chain-head row, allocate the next sequence/hash, add
the immutable event, and advance the head in one transaction. Store operations
lock Intent/idempotency/evaluation rows in stable order before locking the
single organization head, so no operation reverses the order or spans tenants.
The DS-003 implementation also validates the locked tail before extending it
and reloads a chain under a read-only repeatable snapshot, rejecting canonical
JSON/byte/hash disagreement, gaps, wrong predecessors, head mismatch, deletion,
mutation, or sequence reordering.
DS-004 reuses that writer as the last lock in both repository transactions. A
failed `IntentReceived` insert rolls back the new Intent; a failed
`DecisionRecorded` insert rolls back both Evaluation and Decision. Final reads
reverify the immutable Intent, Evaluation and Decision documents plus the
complete chain in one repeatable-read snapshot. Gateway traffic still does not
use this path.

The target request path has two critical atomic visibility boundaries:

1. admission commits the canonical Intent, idempotency binding, lifecycle
   state, evaluator reservation, and `IntentReceived` evidence together;
2. finalization verifies a lease-generation fencing token, then commits the
   Evaluation, Decision, typed Audit evidence, and idempotency result together.

Policy, Risk, and later external enrichment run between those transactions
without open database locks. Short lease/context-snapshot transactions are
allowed, but no final Decision is returned or queried until finalization
commits. Database or Audit failure rolls back the paired state transition and
fails closed; there is no in-memory or local-buffer write fallback. The exact
invariants, migration compatibility policy, rejected alternatives, and staged
implementation order are in ADR-0002.

## Data flow through today's skeleton

1. A caller constructs or receives a `TransactionIntent` JSON document
   matching `schemas/transaction-intent.schema.json`.
2. `atf-intent::validate` checks it against the JSON Schema.
3. `atf-intent::canonical_hash` produces a deterministic SHA-256 hash over a
   canonical (sorted-key, fixed-point) serialization — this is the value that
   will later bind Decisions and Approvals to a specific Intent (PRD §9.1,
   §14.2).
4. `atf-policy::evaluate` loads a Cedar policy set + schema and evaluates the
   Intent's principal/action/resource/context against it, returning a Cedar
   `Decision` (Allow/Deny) plus the policy IDs that fired.
5. If (and only if) Policy did not `forbid`, `atf-risk::evaluate` (or
   `evaluate_with_history`, if the caller has a ledger — see step 10) runs
   the MVP rule set and returns a `Vec<RiskFinding>` (PRD §10.1.2: a denied
   request never reaches Risk scoring).
6. `atf-decision::decide` merges the two into ATF's own `Decision` enum
   (`PERMIT`/`DENY`/`REVIEW`/`ERROR`) per PRD §10.1/§10.2: Cedar `forbid` (or
   default-deny) -> `DENY`; otherwise a `Critical` Risk Finding -> `DENY`, a
   `High` Risk Finding -> `REVIEW`, anything less -> `PERMIT`; any internal
   evaluation error -> `ERROR` (fail closed, never silently `PERMIT`). The
   Simulator branch of §10.1 is not implemented — there is no
   `atf-simulator` yet.
7. `atf-cli evaluate` drives steps 1-6 from the command line and prints the
   resulting `Decision` as JSON. It does not touch `atf-audit` — it's a
   one-shot local tool, not a long-running service with a ledger to keep.
8. `atf-cli policy test` runs the Policy Kernel in isolation (step 4 only)
   against a directory of conformance cases and reports pass/fail — see
   `conformance/policy-tests/README.md`.
9. `schemas/decision.schema.json` describes the shape `atf-decision::Decision`
   serializes to; `atf-decision`'s own test suite (`tests/schema_validation.rs`)
   validates real output of all four decision kinds against it in CI, so the
   schema can't silently drift from the type. `atf-audit` does the same for
   `schemas/audit-event.schema.json`.
10. `services/gateway`'s `POST /v1/intents` is the second caller of steps
    1-6, and the first thing in this repo that also writes to
    `atf-audit::AuditLedger`: it appends `IntentReceived` right after step 2
    with `agent_id`/`organization_id`/`resource_id`/`amount` in the event's
    `data` so the request boundary is auditable — `PolicyEvaluated` right
    after step 4, and `RiskEvaluated` right after step 5 (skipping the Risk
    call itself when Policy already denied, exactly like step 5 does), then
    appends `DecisionRecorded` with the decision kind, Intent hash, and
    organization-scoped history fields, then stores the final `Decision` in
    an in-memory map keyed by `intent_id` for
    `GET /v1/intents/{id}/decision` to return. Everything here is in-memory:
    a process restart loses both the ledger and every stored Decision.

No Adapter, execution path, wallet integration, or production secret exists
in this repository. Everything above only evaluates; it never signs or
submits a transaction.

## Why the control plane comes before Adapters (PRD §2.1, §35)

- Core types must stabilize before Adapters are built against them.
- Schema and policy semantics are the project's long-term public contract
  (PRD §37) — get the shape right before adding surface area.
- Shadow Mode (evaluate-only) is strictly simpler than Enforce Mode and
  carries no execution risk, so it comes first.
- Durable persistence, identity, idempotency, replay, provenance, and
  Decision binding must be complete and re-audited before any real execution
  authority is added; see
  `docs/decisions/0001-durable-shadow-before-enforce.md`.

## Open design gaps tracked for later phases

These are called out explicitly so nobody mistakes today's skeleton for a
complete Decision Engine:

- Decision merge algorithm (PRD §10.1) — implemented for Policy + Risk;
  the Simulator branch has no input to merge yet (no `atf-simulator`).
- Risk rules that need history/state (PRD §12.2) — duplicate purchase is
  done (`atf_risk::evaluate_with_history`, wired into `services/gateway`);
  daily cumulative spend, first-time destination address, and order
  frequency are not. `DecisionRecorded` now provides a reliable PERMIT
  signal and normalized fields, but each rule still needs an explicit
  lifecycle accounting boundary and deterministic evaluation time.
- Policy Bundle versioning/rollback and multi-bundle conflict resolution
  (PRD §11.3).
- Budget model and atomic reserve/commit/release (PRD §9.4).
- `atf-identity` is implemented but still unwired: nothing calls
  `IdentityRegistry::verify_intent_signature`, since there is still no way
  to register an Agent's key through `services/gateway` — that needs an
  Admin API (PRD §17.3), which doesn't exist. It also has no key-rotation
  *policy* (expiry windows, forced revocation) — only the mechanism to hold
  multiple keys at once (PRD §17.2.4).
- `services/gateway` has no persistent store: `atf-audit::AuditLedger` and
  the Decision-by-`intent_id` map are both plain in-memory state behind a
  `Mutex`, so a process restart loses everything (PRD §16.3's MVP design
  calls for PostgreSQL). There is also no rate limiting, no TLS termination
  config, and no multi-instance story — this is a reference wiring, not a
  production deployment target. ADR-0002 and migration 0001 resolve the
  target transaction and constrained table design, and DS-003 implements the
  Audit append guarantee, but the Gateway does not receive durable guarantees
  until DS-005 lands.
- `atf-core::sort_json_keys`/`sha256_hex` are shared by `atf-intent` and
  `atf-audit`'s canonical hashing; any future crate that needs a
  deterministic hash over JSON (e.g. a Policy Bundle hash for §11.3
  versioning) should reuse these rather than re-deriving the
  `preserve_order`-feature fix a second time.
