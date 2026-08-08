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
  `AgentStatus`) and the DS-014 `ATF_INTENT_V1` Identity Envelope. Explicitly
  sorted canonical JSON binds organization, Agent, exact Key ID, Intent hash,
  a five-minute time window, nonce, audience and environment. The in-memory
  `IdentityRegistry` checks Agent scope/status/lifetime, selects only the
  declared Key ID, performs strict Ed25519 verification and returns typed
  `VerifiedIdentity`; raw-hash and try-any-key verification paths no longer
  exist. `IdentityKeyRecord` adds explicit activation, expiry and irreversible
  revocation. *Implemented with DS-015 durable authority and wired into
  Gateway admission by DS-016 before Policy/Risk; PostgreSQL atomically binds
  and consumes hashed Nonces.*
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
- **`atf-audit`** — `AuditEvent`/`EventType`, 33 canonical version-1 typed
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
  an event foreign key. Migration 0003 adds one immutable
  `(organization_id,idempotency_key)` reservation per Intent, database-clock
  lease expiry, monotonically increasing fencing generations, and completed
  Evaluation/Decision/hash references protected against mutation/deletion.
  Admission commits reservation + immutable Intent + `RECEIVED/v1` +
  `IntentReceived`; finalization verifies the active generation and commits
  canonical Evaluation + Decision + five typed phase events + `DECIDED_*/v6`
  + completed idempotency result. Contract-v1 readers replay typed
  events and compare materialized state/version/pointer/time. Read APIs expose
  only records whose canonical bytes/hashes, lifecycle replay, and matching
  verified Audit evidence agree. Migration 0004 adds canonical Agent and exact
  Ed25519 public-key records, monotonic lifecycle versions, Audit event
  pointers and database guards against rebinding/deletion/truncate. Identity
  mutations and typed operator events commit atomically; repeatable-read loads
  reverify the full Audit chain and record hashes. Migration 0005 adds
  immutable organization/Agent-scoped Nonce hashes bound to the exact Key,
  Intent, idempotency reservation, lifecycle versions and
  `IdentityVerified` event. It also exposes a live schema/connectivity
  readiness check. *Implemented and wired into the Gateway for authenticated
  admission/finalization/lifecycle/history/readiness.*
- **`cli/atf-cli`** — `atf validate-intent`, `atf evaluate`,
  `atf policy test`, plus offline `atf identity` Agent/public-key
  provision/status/revoke commands. *Implemented (partial PRD command set).*
- **`services/gateway`** (`atf-gateway`) — an Axum HTTP service:
  `POST /v1/intents` runs Schema/type/common semantic/profile validation ->
  durable admission -> Policy -> (if permitted)
  Risk (via verified durable Audit history) -> Decision merge. PostgreSQL
  admission commits Intent + `IntentReceived`; finalization commits Evaluation,
  typed Identity/Policy/Risk/Simulation events, Decision, lifecycle state, and
  bound `DecisionRecorded`. `GET /v1/intents/{id}/decision`
  requires `X-ATF-Organization-ID` and returns only a fully verified durable
  Decision; `/readyz` checks live database/schema compatibility. *Implemented
  and verified through restart and two real Gateway processes. POST requires
  a canonical detached Identity Envelope/signature, verifies the current
  durable exact Key, and consumes its Nonce before Policy/Risk. The GET
  organization header remains an unauthenticated tenant hint, not an operator
  authorization boundary. Every response has a
  server-generated request ID; business/Router/Store errors use one fixed safe
  JSON envelope without returning raw Schema, SQL, policy or key/internal
  diagnostics. Completed same-hash POSTs return the verified original Decision
  without re-evaluation; active duplicates return bounded 409; normal
  evaluation renews its lease between Policy/Risk stages; and a request may
  conditionally reclaim an expired admission and terminate it as one fenced
  fail-closed `Decision(ERROR)`. Background recovery, operator authentication,
  configured limits, full trace/Audit correlation, and metrics remain absent.*
- **Supply-chain baseline** — CI runs fmt, clippy, tests, and cargo-deny.
  cargo-deny is fixed at 0.20.2 in both local policy semantics and the pinned
  CI Action commit; local ATF crate dependencies carry exact `=0.1.0` version
  bounds as well as paths, while wildcard and unknown-source denial remain
  enabled. BL-002 additionally denies every unreviewed duplicate dependency;
  the current Cedar/SQLx/JSON Schema/ULID/Ed25519 and target-only splits use
  exact-versioned, reasoned exceptions, and CI promotes every cargo-deny
  warning to an error so new duplicates and stale exceptions fail.
  `Apache-2.0 WITH LLVM-exception` (Cedar build path) and `MIT-0`
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
  error/validation-order contract plus DS-012 atomic idempotency/lease/fencing
  foundation, DS-013 exact retry/stage-heartbeat/request-driven recovery, and
  DS-014 domain-separated Identity Envelope and DS-015 durable Agent/Key
  lifecycle plus offline provisioning, and DS-016 authenticated Gateway/Nonce
  admission now exist. Additional action profiles and operator authorization
  remain unimplemented. Accepted
  [`ADR-0003`](decisions/0003-operator-authentication.md) fixes the intended
  operator trust boundary, but DS-018 has not implemented it yet.

Everything else under `crates/`, `sdk/`, `examples/`, `conformance/`,
`deploy/`, and `fuzz/` is a scaffolded directory with a
`README.md` describing what belongs there and which roadmap phase (PRD §31)
will fill it in. None of it is wired into the Cargo workspace yet.

## Accepted operator trust boundary (not implemented)

ADR-0003 requires that the Gateway act as an OAuth resource server and verify
short-lived RFC 9068 JWT access tokens from one configured HTTPS issuer and
audience. A verified external subject does not carry ATF authority by itself:
PostgreSQL maps its issuer/subject fingerprint to one internal operator and
reloads current organization-role bindings for every protected request.

The resulting `OperatorPrincipal` is disjoint from the existing
`AgentPrincipal`. Agent Envelopes authorize only Intent admission; operator
tokens authorize only the explicit role matrix. Organization values in
Headers, paths, or bodies remain selectors and must agree with the principal's
durable binding and the resource's organization. The Gateway ignores proxy
identity assertions and validates the token itself.

TLS terminates at a trusted ingress, while the ingress-to-Gateway hop must be
private and protected from observation, injection, and replay. DS-034 owns the
concrete proxy, Header/body/time/rate limits, and deployment tests. DS-018 owns
the subject/role migration, offline provisioning, JWT/JWKS verifier, typed
principals, Decision-read RBAC, and non-enumerating cross-tenant tests. The
accepted design must not be presented as implemented before DS-018 passes
those runtime checks.

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
`RECEIVED/v1`; its original Shadow compatibility writer emitted
`IdentityVerificationSkipped`. DS-016 supersedes that request writer: a new
accepted Intent atomically advances through `IntentReceived ->
IdentityVerified` to `IDENTITY_VERIFIED/v2` before Policy/Risk. Finalization
locks the Intent and rejects a stale expected version, then emits
`PolicyEvaluated -> RiskEvaluated -> SimulationCompleted -> DecisionRecorded`
and advances to `DECIDED_*/v6` in the same transaction as Evaluation and
Decision. Readers replay every typed state-producing event and compare state,
version, last-event pointer, and timestamp. Migrated historical rows and the
`IDENTITY_UNVERIFIED` state remain explicit compatibility contracts; immutable
canonical/Audit bytes are never rewritten or upgraded as authenticated.
DS-012 implements the two idempotency sides of those transactions. The
reservation row is inserted before the Intent under a deferred binding foreign
key and commits with admission evidence. Lease expiry is derived from the
database clock; renewal preserves its generation, while expired reclaim uses a
conditional update that increments it. Finalization locks and verifies the
reservation before the Intent, rejects stale/expired owners, and changes it to
immutable `COMPLETED` with Evaluation/Decision/hash references in the same
transaction as Audit and lifecycle state. Before provenance-bearing Context
snapshots exist, a reclaimed generation may only commit `Decision(ERROR)`.
DS-013 wires that boundary into the HTTP path. Completed same-hash admission
errors are resolved through `load_finalized_decision`, which re-verifies the
canonical Intent/Evaluation/Decision, lifecycle replay, Audit chain and
idempotency result before returning the original Decision. New evaluators
renew the same owner/generation in independent short transactions after Policy
and Risk. An `IN_PROGRESS` retry always attempts the database-conditional
reclaim: an active lease remains a 409, while an expired lease receives the
next generation, reloads the admitted evidence, renews once, and records
`RECOVERY_CONTEXT_UNAVAILABLE -> Decision(ERROR)` without rerunning current
Policy/Risk. Recovery is triggered by a retry request; there is no background
worker yet.
DS-016 places current durable Agent/exact-Key verification ahead of that
reservation boundary. A new coarse transaction locks and reverifies the
identity lifecycle, verifies the canonical signed Envelope, stores only the
Nonce/Envelope hashes, and atomically commits the Nonce, reservation, Intent,
`IntentReceived` and `IdentityVerified`. Exact retries add nothing; a fresh
valid assertion can bind a fresh Nonce to the existing idempotent request;
conflicting reuse commits organization-scoped `ReplayDetected` and fails 409.
Identity rejection commits only `IdentityRejected`. Nonce reads reverify their
Audit and historical lifecycle bindings, including after restart.

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
    1-6. After validation, it parses a bounded canonical detached Envelope and
    signature; authenticated admission atomically consumes the hashed Nonce
    and stores canonical Intent, `IntentReceived`, and `IdentityVerified`.
    Policy runs only after that commit; when permitted, Risk reads the complete
    verified organization chain through `atf-store`. The Simulator is not
    wired, so the Gateway records a stable reason-coded Simulation `NOT_RUN`.
    Finalization atomically stores typed Policy/Risk/Simulation evidence in an
    Evaluation, all intermediate events, the Decision, lifecycle state, and a
    foreign-key-bound typed `DecisionRecorded`. Only that committed Decision is
    returned. GET reads the same verified record by organization + Intent ID,
    so restart or a second process observes the original result. DS-013 also
    resolves completed same-hash POSTs through that verified read without
    rerunning Policy/Risk. A crash after admission remains visibly
    `RECEIVED` until a retry conditionally reclaims the expired lease; before
    Evaluation Context snapshots exist, that request records exactly one
    fenced fail-closed `Decision(ERROR)` rather than evaluating with current
    inputs. Active duplicates continue to receive bounded 409 responses.
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
- Agent Envelope verification, exact durable Key selection and atomic hashed
  Nonce consumption are wired before Policy/Risk. Process memory is not
  deployment authority. Operator/auditor authentication and authorization are
  still absent. ADR-0003 fixes the accepted DS-017 boundary; DS-018 is the next
  implementation task.
- `services/gateway` is durable but not production-ready. It requires an
  already migrated database and explicitly provisioned organizations; GET's
  organization header is not authenticated. It loads the full organization
  Audit chain for history rules, has no configured header/timeout/rate limits,
  and has no background lifecycle recovery worker. Completed same-hash POSTs
  now return the original verified Decision, an active same-hash duplicate
  stops before evaluation, and a different hash returns
  `IDEMPOTENCY_CONFLICT`. A failure between admission and finalization can
  leave a fenced admitted Intent without a Decision until a retry triggers
  DS-013 recovery. Operator authentication, deterministic Context-based
  recovery and operational scanning remain later gaps, not reasons to
  reintroduce process-local state.
- `atf-core::sort_json_keys`/`sha256_hex` are shared by `atf-intent` and
  `atf-audit`'s canonical hashing; any future crate that needs a
  deterministic hash over JSON (e.g. a Policy Bundle hash for §11.3
  versioning) should reuse these rather than re-deriving the
  `preserve_order`-feature fix a second time.
