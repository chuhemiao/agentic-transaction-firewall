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
  -> Versioned Evaluation Context   (atf-core/atf-store, implemented)
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
  exhaustive fail-closed transition validator. DS-022 adds the closed
  `EvidenceEnvelope`, typed source/kind/freshness, numeric-free bounded values,
  domain-separated canonical hash, optional strict Ed25519 proof, exact trust
  allowlists and non-constructible `VerifiedEvidence`. DS-023 adds a closed
  `EvaluationContext` contract with independently domain-separated Agent,
  context-snapshot and overall hashes. It binds the Intent/Profile, one time,
  Policy/Risk artifacts, sorted fresh verified Evidence and trust identity,
  an exact Audit-history prefix, external snapshot availability and explicit
  Simulation `NOT_RUN`. *Implemented.*
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
- **`atf-policy`** — DS-019 loads only closed v1 Policy Bundle manifests. The
  manifest binds bundle ID/version, organization/environment, active window,
  Cedar Schema and exact policy files into a domain-separated canonical hash.
  Loader checks JSON Schema, safe/sorted paths, file digests, unlisted Cedar
  files, Bundle hash and strict Cedar policy validation. DS-024's `evaluate`
  validates the persisted Context's Intent/Profile/environment/time and exact
  Bundle identity, validates the request against the same Cedar Schema,
  rejects runtime diagnostics and returns the exact bundle identity. DS-020
  adds a bounded exact-byte archive and detached Ed25519 proof over the
  domain-separated Key-ID/Bundle-Hash message; durable restore repeats all
  manifest/file/hash/Schema checks before strict signature verification.
  *Implemented for signed immutable Bundle identity and restore; multi-bundle
  merge/conflict resolution remains later work.*
- **`atf-risk`** — DS-021 loads a closed, bounded Rule Set JSON artifact whose
  format/engine versions, enabled rules, severities, thresholds, canonical
  deny lists, missing-data behavior, history windows and accounting boundaries
  form one domain-separated canonical hash. DS-024 replaces the former
  `evaluate*`/`*_at` family with one `evaluate_context` entry point returning
  `RiskEvaluation { rule_set_version, rule_set_hash, findings }`. It validates
  the exact Intent/Profile/Rule Set and verified Audit prefix named by the
  immutable Context and reads evaluation time and Evidence only from it.
  Stateless rules cover
  request expiry, single-transaction cap, fee ratio, vendor price deviation
  and high-risk network/protocol. Duplicate purchase reads verified durable
  Audit history using an explicit `PERMITTED` boundary; the engine can select
  `REQUESTED`, `PERMITTED`, `EXECUTED`, or `SETTLED` lifecycle facts.
  DS-022/DS-024 keep the internal typed Risk input restricted to Evidence
  already verified and persisted by `EvaluationContext`; raw Intent context is
  checked only as one hash and privileged keys are never inspected. Vendor
  median requires exact organization/resource/asset-bound ATF Evidence, and an
  enabled vendor rule cannot configure missing trusted data as not applicable.
  *Implemented (partial — production enrichment, durable bounded history
  queries, daily cumulative spend, first-time destination and frequency rules
  remain later work).*
- **`atf-audit`** — `AuditEvent`/`EventType`, 40 canonical version-1 typed
  payload variants, explicit required/optional module outcomes, intent-scope
  checks, and event-to-lifecycle effects, plus an in-memory append-only
  `AuditLedger` with hash-chain verification (PRD §16.3). Its closed JSON
  Schema is tested against real output for every payload family. *Implemented
  as a domain library. The Gateway commits current admission/finalization
  events through typed constructors and persists them through `atf-store`; it
  does not use the in-memory ledger as a fallback.*
- **`atf-decision`** — the real PRD §10.1 merge plus DS-025's closed Decision
  v1 envelope. The domain-separated canonical hash binds Intent/Profile,
  Policy/Risk artifacts, Evaluation Context/snapshot, explicit Simulation
  state, evaluation/expiry times, reasons, future Approval/Obligation fields
  and execution constraints. Module identity/order mismatch fails closed.
  *Implemented except for the Simulator branch (no `atf-simulator` yet).*
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
  readiness check. Migration 0006 adds immutable external Operator subject
  fingerprints and explicit organization-role rows, with canonical bytes,
  hashes, monotonic lifecycle versions, typed Audit pointers, mutation guards,
  and repeatable-read verification. Migration 0007 adds immutable signed
  Policy Bundle archives, publisher public-key/signature evidence and
  monotonic active pointers whose update always retains the previous installed
  version and references the same transaction's typed `PolicyChanged` event.
  Migration 0008 adds one immutable Evaluation Context per Intent, retains
  exact canonical JSON/bytes/hash, binds it to the admitted Intent and one
  typed `ContextEnriched` event, and requires final Evaluation rows to name
  the same context hash. Store readers rederive the Profile and Agent-context
  hash, verify the Audit-history prefix, reject row/Audit tampering and support
  restart-safe lookup by Intent or Evaluation ID.
  Migration 0009 adds immutable organization/environment Risk Rule Set
  archives with canonical bytes, artifact/domain hashes, installer identity
  and atomic `RiskRuleSetStored` evidence. Original Replay verifies every
  immutable input and exact history prefix, recomputes typed module evidence
  and canonical Decision bytes, and appends only a referenced
  `OriginalReplayCompleted` event after current Decision-read authorization.
  Migration 0010 stores Counterfactual Replay in a separate immutable table:
  original lineage, new Context/Evaluation/Decision IDs and canonical hashes,
  exact selected Policy/Risk foreign keys, changed-outcome relation and the
  authorized `CounterfactualReplayCompleted` event are verified together.
  These rows are permanently non-authoritative and never enter the one-per-
  Intent Evaluation/Decision authority path.
  *Implemented and wired into the Gateway
  for authenticated admission/finalization/lifecycle/history/readiness and
  Decision-read authorization.*
- **`cli/atf-cli`** — `atf validate-intent`, `atf evaluate`,
  `atf policy test/install/activate/rollback`, `atf risk install`,
  `atf replay original/counterfactual`, plus offline `atf identity` Agent/public-key
  provision/status/revoke and `atf operator` subject/status/role commands.
  *Implemented (partial PRD command set).*
- **`services/gateway`** (`atf-gateway`) — an Axum HTTP service:
  `POST /v1/intents` runs Schema/type/common semantic/profile validation ->
  durable admission -> immutable Evaluation Context -> Policy -> (if permitted)
  Risk (via verified durable Audit history) -> Decision merge. PostgreSQL
  admission commits Intent + `IntentReceived`; a short DS-023 transaction pins
  the selected Policy/Risk identities, evaluation time and verified history
  before module execution and appends `ContextEnriched`; finalization commits Evaluation,
  typed Identity/Policy/Risk/Simulation events, Decision, lifecycle state, and
  bound `DecisionRecorded`. `GET /v1/intents/{id}/decision`
  requires a canonical `X-ATF-Organization-ID`, one validated RFC 9068 Bearer
  JWT, and a current durable `auditor` or `org_admin` binding before returning
  a fully verified durable Decision; `/readyz` checks live database/schema and
  configured-JWKS readiness. *Implemented and verified through restart and two
  real Gateway processes. Startup requires a validated
  `ATF_RISK_RULE_SET_PATH` whose exact identity exists in the audited durable
  archive; POST persists its version/hash with Risk evidence.
  POST requires a canonical detached Identity
  Envelope/signature, verifies the current durable exact Key, and consumes its
  Nonce before Policy/Risk. The GET organization header remains only a tenant
  selector; JWT claims grant no ATF role. Every response has a
  server-generated request ID; business/Router/Store errors use one fixed safe
  JSON envelope without returning raw Schema, SQL, policy or key/internal
  diagnostics. Completed same-hash POSTs return the verified original Decision
  without re-evaluation; active duplicates return bounded 409; normal
  evaluation renews its lease between Policy/Risk stages; and a request may
  conditionally reclaim an expired admission, persist/reuse an explicit
  recovery context and terminate it as one fenced
  `RECOVERY_REPLAY_NOT_IMPLEMENTED -> Decision(ERROR)`. Original Replay is a
  separate authorized verification operation and never changes that recovery
  record. Agent/Operator credentials are disjoint and
  Decision absence, cross-tenant selection and insufficient read role share
  one 404. Background recovery, configured general request/rate limits, full
  trace/Audit correlation, and metrics remain absent.*
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
  lifecycle plus offline provisioning, DS-016 authenticated Gateway/Nonce
  admission, DS-018 durable Operator subjects/roles plus Gateway JWT/JWKS
  Decision-read RBAC, and DS-023 immutable Evaluation Context persistence now
  exist. Additional action profiles and Admin/Audit HTTP
  role matrices remain unimplemented. Accepted
  [`ADR-0003`](decisions/0003-operator-authentication.md) is implemented for
  the current Decision-read surface.

Everything else under `crates/`, `sdk/`, `examples/`, `conformance/`,
`deploy/`, and `fuzz/` is a scaffolded directory with a
`README.md` describing what belongs there and which roadmap phase (PRD §31)
will fill it in. None of it is wired into the Cargo workspace yet.

## Implemented operator trust boundary

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

DS-018 implements the application boundary: migration 0006 and `atf-store`
own subject/role lifecycle and verification; `atf operator` provisions it
offline; Gateway startup discovers and loads only the configured HTTPS issuer
and JWKS; `AgentPrincipal` and `OperatorPrincipal` are disjoint; every Decision
read reloads current local status/roles; and non-enumerating, revocation,
restart, redaction and real HTTP/PostgreSQL tests cover the role matrix.

TLS terminates at a trusted ingress, while the ingress-to-Gateway hop must be
private and protected from observation, injection, and replay. DS-034 still
owns the concrete proxy, general Header/body/time/rate limits, and deployment
tests. DS-018 therefore closes the application principal/RBAC gap, not the
shared-network production-hardening gate.

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
transaction as Audit and lifecycle state. A reclaimed generation may only
commit `Decision(ERROR)`; DS-023 requires an immutable context for that output.
DS-013 wires that boundary into the HTTP path. Completed same-hash admission
errors are resolved through `load_finalized_decision`, which re-verifies the
canonical Intent/Evaluation/Decision, lifecycle replay, Audit chain and
idempotency result before returning the original Decision. New evaluators
renew the same owner/generation in independent short transactions after Policy
and Risk. An `IN_PROGRESS` retry always attempts the database-conditional
reclaim: an active lease remains a 409, while an expired lease receives the
next generation, reloads the admitted evidence, renews once, and records
`RECOVERY_REPLAY_NOT_IMPLEMENTED -> Decision(ERROR)` without rerunning current
Policy/Risk. It reuses a pre-crash context when present or first persists a
context whose artifact/snapshot fields explicitly record unavailability.
Recovery is triggered by a retry request; there is no background worker yet.
DS-016 places current durable Agent/exact-Key verification ahead of that
reservation boundary. A new coarse transaction locks and reverifies the
identity lifecycle, verifies the canonical signed Envelope, stores only the
Nonce/Envelope hashes, and atomically commits the Nonce, reservation, Intent,
`IntentReceived` and `IdentityVerified`. Exact retries add nothing; a fresh
valid assertion can bind a fresh Nonce to the existing idempotent request;
conflicting reuse commits organization-scoped `ReplayDetected` and fails 409.
Identity rejection commits only `IdentityRejected`. Nonce reads reverify their
Audit and historical lifecycle bindings, including after restart.
DS-023 inserts a third short transaction between admission and evaluation. It
verifies the active fenced lease, immutable Intent/Profile/Agent-context hash
and exact Audit-history prefix, then atomically inserts one canonical immutable
Evaluation Context and its `ContextEnriched` evidence. Exact retries reuse it;
a second context, stale generation, update/delete/truncate or any canonical,
redundant-column, history or Audit mismatch fails closed. Finalization and
Decision reads require the Evaluation ID/time/context hash and Risk/Simulation
output identity to agree with that snapshot.
DS-025 closes final output integrity. Finalization verifies the Decision's
embedded `ATF_DECISION_V1` hash and every Intent/Context-derived binding before
insertion; the `decisions.decision_hash` column stores that same hash.
`DecisionRecorded.binding` mirrors Profile, artifact, snapshot, Simulation,
time, expiry, Approval/Obligation and execution-constraint values. Read paths
recompute the hash, recheck Context binding and require exact Audit equality.

The target request path has two critical atomic visibility boundaries:

1. admission commits the canonical Intent, idempotency binding, lifecycle
   state, evaluator reservation, and `IntentReceived` evidence together;
2. context capture verifies the same fencing token, then commits one immutable
   input snapshot and matching `ContextEnriched` evidence together;
3. finalization verifies a lease-generation fencing token, then commits the
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
4. `atf-policy::PolicyBundle::from_dir` validates the scoped, time-bounded
   manifest, exact files, Bundle hash, Cedar Schema and policies before use.
   After DS-023 persists an immutable input snapshot, DS-024's `evaluate`
   verifies its Intent/Profile/environment/time and exact Bundle binding,
   Schema-validates the Intent's principal/action/resource/context, then
   returns Cedar Permit/Forbid plus policy IDs and Bundle ID/version/hash.
   DS-020 installation additionally validates the detached publisher proof,
   persists the exact archive immutably, and makes only an audited active
   pointer selectable. Gateway requests resolve that pointer and revalidate
   the archive/signature in one repeatable-read snapshot before evaluation.
5. If (and only if) Policy did not `forbid`, `atf-risk::evaluate_context`
   validates the same Context's Intent/Profile/Rule Set and exact verified
   Audit prefix, then runs the rules using only its time and Evidence. It
   returns the exact Rule Set version/hash plus findings. A denied request
   never reaches Risk scoring, but its durable
   `NOT_RUN` evidence still names the selected Rule Set. DS-022 prevents raw
   Agent context from supplying privileged Risk inputs; the current vendor
   median consumes only fresh verified, scope-bound `ATF_ENRICHED` evidence.
6. `atf-decision::decide` validates the Policy/Risk output identities against
   the same Context and merges them into ATF's own `Decision` enum
   (`PERMIT`/`DENY`/`REVIEW`/`ERROR`) per PRD §10.1/§10.2: Cedar `forbid` (or
   default-deny) -> `DENY`; otherwise a `Critical` Risk Finding -> `DENY`, a
   `High` Risk Finding -> `REVIEW`, anything less -> `PERMIT`; any internal
   evaluation error -> `ERROR` (fail closed, never silently `PERMIT`). The
   Simulator branch of §10.1 is not implemented — there is no
   `atf-simulator` yet. It then seals Decision v1 with the Intent/Profile,
   artifact, Context/snapshot, Simulation, time/expiry and execution-
   constraint bindings under the `ATF_DECISION_V1` canonical hash.
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
    Gateway resolves the exact Policy, captures one evaluation time and loads
    the exact verified Audit prefix. It then persists one immutable
    `EvaluationContext` plus `ContextEnriched` before Policy runs. When
    permitted, Risk uses the same pinned time, Rule Set and history snapshot.
    The Simulator is not
    wired, so the Gateway records a stable reason-coded Simulation `NOT_RUN`.
    Finalization atomically stores typed Policy/Risk/Simulation evidence in an
    Evaluation, all intermediate events, the Decision, lifecycle state, and a
    foreign-key-bound typed `DecisionRecorded` carrying the same Decision v1
    bindings. Store verifies the embedded Decision hash and Context on both
    write and read. Only that committed Decision is returned. GET reads the
    same verified record by organization + Intent ID,
    so restart or a second process observes the original result. DS-013 also
    resolves completed same-hash POSTs through that verified read without
    rerunning Policy/Risk. A crash after admission remains visibly
    `RECEIVED` until a retry conditionally reclaims the expired lease. It then
    reuses an existing context or creates an explicit unavailable recovery
    context and records one fenced `RECOVERY_REPLAY_NOT_IMPLEMENTED ->
    Decision(ERROR)` rather than evaluating with current inputs. Active
    duplicates continue to receive bounded 409 responses.
11. `services/gateway` generates a fresh ULID at the HTTP boundary and returns
    it as `X-ATF-Request-ID` on every response. Business errors expose only the
    fixed `{code,message,request_id,details}` contract; validation details are
    server-owned semantic code/field pairs. Health/readiness keep minimal text
    bodies. See `docs/api.md` for the code/status and compatibility contract.
12. `atf replay original` authorizes the current Operator, reloads the exact
    immutable Intent/Context/signed Policy/Risk archive/Audit prefix, reruns
    Policy and Risk, and requires typed Evaluation evidence plus complete
    Decision bytes/hash to match. It then reauthorizes and appends only
    `OriginalReplayCompleted`; no authoritative Evaluation or Decision row is
    inserted or updated.

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
- Original and Counterfactual Replay are complete through DS-027. Exact
  Original reproduction and isolated selected-artifact lineage have restart,
  missing/tamper/authorization/non-overwrite tests; broader property/fuzz
  conformance remains DS-037.
- Common Intent semantics and the versioned Agent-Commerce Payment Profile are
  implemented. Every other action category present in the common Schema is
  explicitly rejected until its own versioned Profile is implemented.
- Risk rules that need history/state (PRD §12.2) — duplicate purchase is
  done (`atf_risk::evaluate_context`, wired to the Context-bound verified
  PostgreSQL Audit prefix in `services/gateway`);
  daily cumulative spend, first-time destination address, and order
  frequency are not. `DecisionRecorded` now provides a reliable PERMIT
  signal and normalized fields. DS-021 makes a lifecycle accounting boundary
  structurally mandatory and evaluates all rules at one explicit caller time;
  DS-022 removes the current vendor rule's untrusted Agent-context read, and
  DS-023 now durably pins the evaluation time, verified Evidence/trust
  selection and history boundary. DS-024 now makes both evaluators consume
  that Context, rejects mismatched artifacts/Intent/history and prevents later
  Audit events from entering the snapshot. DS-028 will replace full-chain
  loading with bounded durable snapshot queries.
- Multi-bundle merge and static conflict resolution (PRD §11.3) remain.
  DS-019/DS-020 now implement manifest/version/hash/scope/Schema validation,
  publisher proof, immutable persistence and atomic activation/rollback for
  one explicitly selected Bundle ID.
- Budget model and atomic reserve/commit/release (PRD §9.4).
- Agent Envelope verification, exact durable Key selection and atomic hashed
  Nonce consumption are wired before Policy/Risk. Process memory is not
  deployment authority. DS-018 implements ADR-0003 for Decision reads with
  Gateway-validated JWTs and current durable Operator roles. DS-020 adds the
  first Admin capability: Policy activation/rollback requires `policy_author`
  or `org_admin` and is reauthorized inside the mutation transaction. Other
  Admin and Audit routes still need their explicit endpoint matrices.
- `services/gateway` is durable but not production-ready. It requires an
  already migrated database, explicitly provisioned organizations/operators,
  and configured HTTPS issuer/JWKS. GET's organization header is a selector
  authorized against the current durable Operator role. It loads the full organization
  Audit chain for history rules, has no configured header/timeout/rate limits,
  and has no background lifecycle recovery worker. Completed same-hash POSTs
  now return the original verified Decision, an active same-hash duplicate
  stops before evaluation, and a different hash returns
  `IDEMPOTENCY_CONFLICT`. A failure between admission and finalization can
  leave a fenced admitted Intent without a Decision until a retry triggers
  DS-013 recovery. Operator authentication, deterministic Context-based
  recovery and operational scanning remain later gaps, not reasons to
  reintroduce process-local state.
- `atf-core::sort_json_keys`/`sha256_hex` are shared by `atf-intent`,
  `atf-audit`, DS-019 Policy Bundle hashing and DS-021 Risk Rule Set hashing.
  Any future deterministic JSON hash must reuse them rather than re-deriving
  the `preserve_order`-feature fix again.
