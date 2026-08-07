# Architecture (draft)

This is a working draft. The authoritative source is `docs/PRD.md`; this
document translates it into the current and target code layout.

## Target pipeline (PRD §1, §8.1)

```text
Agent Intent
  -> Canonical Transaction Intent   (atf-intent)
  -> Identity Verification          (atf-identity)
  -> Common Semantic Validation     (atf-intent, implemented)
  -> Action Profile Validation      (atf-intent, one profile implemented)
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
  (RFC 3339), shared Decision kind, 22 stable Intent lifecycle states, and an
  exhaustive fail-closed transition validator. *Implemented.*
- **`atf-intent`** — `TransactionIntent` type, closed JSON Schema plus
  matching `deny_unknown_fields` Rust parsing, explicit supported
  `spec_version` set (`1.0`), object-only hash-bound `context`/`metadata`
  extensions, canonical serialization + SHA-256 hash, and deterministic
  common semantic validation. It enforces positive amount/leverage,
  non-negative fees, slippage bounds, ordered millisecond timestamps with a
  24-hour maximum TTL, ULIDs, and bounded nonblank identifier/purpose text.
  Violations expose stable ordered codes and fields. Its closed dispatcher
  accepts exactly `atf.agent-commerce.payment` v1.0 for
  `payment/purchase_api_resource`, requires a typed resource, validates and
  same-chain binds CAIP-2/10/19 identifiers, and forbids contract/trading
  fields. Every other action pair returns `UNSUPPORTED_INTENT_PROFILE`.
  Structural, common-semantic, and the one supported Profile contract are
  *implemented*; additional profiles remain planned.
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
  `evaluate_with_history` or `evaluate_with_events`. The Gateway supplies the
  latter with the organization's verified durable Audit events and reads only
  prior `DecisionRecorded(PERMIT)` outcomes.
  *Implemented (partial — daily cumulative spend, first-time destination
  address, and order frequency, PRD §12.2, still need an explicit
  PERMITTED/EXECUTED/SETTLED accounting boundary).*
- **`atf-audit`** — `AuditEvent`/`EventType`, 28 canonical version-1 typed
  payload variants, explicit required/optional module outcomes, intent-scope
  checks, and event-to-lifecycle effects, plus an in-memory append-only
  `AuditLedger` with hash-chain verification (PRD §16.3). Its closed JSON
  Schema is tested against real output for every payload family. *Implemented
  as a domain library. The Gateway commits current admission/finalization
  events through typed constructors and persists them through `atf-store`; it
  does not use the in-memory ledger as a fallback.*
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
  one consistent snapshot. Migration 0002 adds lifecycle state, optimistic
  version, contract version, last-event pointer, update time, constraints, and
  an event foreign key. Admission commits immutable Intent + `RECEIVED/v1` +
  `IntentReceived`; finalization commits canonical Evaluation + Decision +
  five typed phase events + `DECIDED_*/v6`. Contract-v1 readers replay typed
  events and compare materialized state/version/pointer/time. Read APIs expose
  only records whose canonical bytes/hashes, lifecycle replay, and matching
  verified Audit evidence agree. It also exposes a live schema/connectivity
  readiness check. *Implemented and wired into the Gateway for admission,
  finalization, lifecycle/history reads, and readiness.*
- **`cli/atf-cli`** — `atf validate-intent`, `atf evaluate`,
  `atf policy test`. *Implemented.*
- **`services/gateway`** (`atf-gateway`) — an Axum HTTP service:
  `POST /v1/intents` runs Schema/type/common semantic/profile validation ->
  durable admission -> Policy -> (if permitted)
  Risk (via verified durable Audit history) -> Decision merge. PostgreSQL
  admission commits Intent + `IntentReceived`; finalization commits Evaluation,
  typed Identity/Policy/Risk/Simulation events, Decision, lifecycle state, and
  bound `DecisionRecorded`. `GET /v1/intents/{id}/decision`
  requires `X-ATF-Organization-ID` and returns only a fully verified durable
  Decision; `/readyz` checks live database/schema compatibility. *Implemented
  and verified through restart and two real Gateway processes. Does not call
  `atf-identity`; the organization header is an unauthenticated tenant hint,
  not an authorization boundary. Identity is explicitly recorded as skipped
  (`IDENTITY_UNVERIFIED`) and cannot authorize execution. Every response has a
  server-generated request ID; business/Router/Store errors use one fixed safe
  JSON envelope without returning raw Schema, SQL, policy or key/internal
  diagnostics. Exact idempotent retry, lifecycle recovery, configured limits,
  full trace/Audit correlation, and metrics remain absent.*
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
  DS-004 admission/finalization transaction subset and DS-005 Gateway cutover
  plus the DS-006 domain contract, DS-007 persisted/replayable lifecycle, and
  DS-008 closed Intent envelope/version contract plus DS-009 common semantic
  validator, DS-010 Agent-Commerce Payment profile, and DS-011 safe API
  error/validation-order contract now exist. Additional action profiles,
  idempotency result state, leases/fencing, and recovery remain unimplemented.

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
complete chain in one repeatable-read snapshot. DS-005 makes this the only
Gateway Decision/Audit path; there is no process-local fallback.
DS-007 adds the lifecycle materialization. New admission rows are contract-v1
`RECEIVED/v1`; finalization locks the Intent and rejects a stale expected
version before appending any evidence. It then emits
`IdentityVerificationSkipped -> PolicyEvaluated -> RiskEvaluated ->
SimulationCompleted -> DecisionRecorded` and advances to `DECIDED_*/v6` in
the same transaction as Evaluation and Decision. Readers replay every typed
state-producing event and compare state, version, last-event pointer, and
timestamp. Migrated historical rows remain explicit compatibility contract-v0
records; immutable canonical/Audit bytes are never rewritten.

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
2. `atf-intent::validate` checks it against the closed JSON Schema, accepts
   only `spec_version: "1.0"`, rejects unknown core fields, and then parses the
   same fail-closed Rust shape. Arbitrary extensions are accepted only under
   object-valued `context`/`metadata`. It then applies the common financial,
   time, ULID, identifier, and purpose invariants and returns deterministically
   ordered `SemanticViolation` codes without normalizing invalid input. The
   closed dispatcher then validates the supported Agent-Commerce Payment
   resource/CAIP relationships or rejects the action pair as unsupported.
3. `atf-intent::canonical_hash` produces a deterministic SHA-256 hash over a
   canonical (sorted-key, fixed-point) serialization — this is the value that
   will later bind Decisions and Approvals to a specific Intent (PRD §9.1,
   §14.2).
4. `atf-policy::evaluate` loads a Cedar policy set + schema and evaluates the
   Intent's principal/action/resource/context against it, returning a Cedar
   `Decision` (Allow/Deny) plus the policy IDs that fired.
5. If (and only if) Policy did not `forbid`, `atf-risk::evaluate` (or a
   history-aware variant when the caller has verified events — see step 10) runs
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
10. `services/gateway`'s `POST /v1/intents` is the durable caller of steps
    1-6. After validation, admission atomically stores canonical Intent plus
    `IntentReceived`. Policy runs next; when permitted, Risk reads the complete
    verified organization chain through `atf-store`. Because Identity and the
    Simulator are not wired yet, the Gateway records stable reason-coded
    `IdentityVerificationSkipped` and Simulation `NOT_RUN` outcomes.
    Finalization atomically stores typed Policy/Risk/Simulation evidence in an
    Evaluation, all intermediate events, the Decision, lifecycle state, and a
    foreign-key-bound typed `DecisionRecorded`. Only that committed Decision is
    returned. GET reads the same verified record by organization + Intent ID,
    so restart or a second process observes the original result. A crash after
    admission but before finalization remains visibly `RECEIVED` but can still
    strand work until leases and idempotent recovery are implemented in
    DS-012/DS-013.
11. `services/gateway` generates a fresh ULID at the HTTP boundary and returns
    it as `X-ATF-Request-ID` on every response. Business errors expose only the
    fixed `{code,message,request_id,details}` contract; validation details are
    server-owned semantic code/field pairs. Health/readiness keep minimal text
    bodies. See `docs/api.md` for the code/status and compatibility contract.

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
- Common Intent semantics and the versioned Agent-Commerce Payment Profile are
  implemented. Every other action category present in the common Schema is
  explicitly rejected until its own versioned Profile is implemented.
- Risk rules that need history/state (PRD §12.2) — duplicate purchase is
  done (`atf_risk::evaluate_with_events`, wired to verified PostgreSQL Audit
  history in `services/gateway`);
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
- `services/gateway` is durable but not production-ready. It requires an
  already migrated database and explicitly provisioned organizations; GET's
  organization header is not authenticated. It loads the full organization
  Audit chain for history rules, has no configured header/timeout/rate limits,
  and has no lifecycle recovery worker or exact retry semantics. A duplicate
  POST currently conflicts, and a failure between admission and finalization can leave an
  admitted Intent without a Decision. These are explicit DS-012 onward gaps,
  not reasons to reintroduce process-local state.
- `atf-core::sort_json_keys`/`sha256_hex` are shared by `atf-intent` and
  `atf-audit`'s canonical hashing; any future crate that needs a
  deterministic hash over JSON (e.g. a Policy Bundle hash for §11.3
  versioning) should reuse these rather than re-deriving the
  `preserve_order`-feature fix a second time.
