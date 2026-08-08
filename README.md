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
(v1.3, Authenticated Durable Shadow revision).

## Status

This repository is in **Phase 2: Durable Shadow Mode**. Phase 1 is complete;
the current release gate requires persistence, lifecycle/idempotency,
Gateway identity, deterministic replay, context provenance, versioned bundles,
and observability before any real execution work begins (PRD §31–32).
Only the following crates are implemented so far:

- `crates/atf-core` — shared domain primitives, stable Intent lifecycle states,
  the fail-closed pure transition validator, DS-022 provenance-bearing
  Evidence envelopes, the DS-023/DS-024 immutable `EvaluationContext`
  evaluator boundary, and DS-025 shared Decision-binding types. Evidence uses
  closed typed source/kind enums, bounded
  numeric-free values, canonical hashes, explicit freshness, source/kind
  allowlists and optional strict Ed25519 verification. Evaluation Context binds
  the exact Intent/Profile, one evaluation time, Policy/Risk artifacts,
  verified Evidence/trust identity, Audit-history boundary, external snapshot
  availability and Simulation `NOT_RUN` into one domain-separated canonical
  hash.
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
  never tries every key and returns typed verified identity facts. DS-015 adds
  validated key activation/expiry/revocation metadata; PostgreSQL is now the
  durable Agent/Key authority. DS-016 wires the same verifier into Gateway
  admission and makes PostgreSQL the atomic, immutable Nonce authority.
- `crates/atf-policy` — validated Policy Bundles: a closed manifest binds
  bundle ID/version, exact organization/environment scope, activation/expiry,
  Cedar Schema and every policy-file digest into a domain-separated canonical
  hash. Strict Cedar policy validation happens at load; Schema-backed request
  validation, scope/expiry rechecks and runtime-diagnostic rejection happen
  on every evaluation. DS-024 requires the exact persisted Context binding
  for Intent/Profile, environment, time and Bundle identity; no Policy entry
  point samples the clock. Successful output names the exact bundle
  ID/version/hash. DS-020 adds a detached, domain-separated strict Ed25519
  publisher proof and a bounded exact-byte archive for durable revalidation.
- `crates/atf-risk` — a closed Risk Rule Set artifact binds format/engine and
  Rule Set versions, enabled states, severities, thresholds, canonical deny
  lists, missing-data behavior, history windows and accounting boundaries into
  a domain-separated canonical hash. Every `RiskEvaluation` returns the exact
  version/hash with findings. The current rules cover request expiry,
  single-transaction cap, fee ratio, vendor price deviation, high-risk
  network/protocol and duplicate purchase. Gateway evaluates the latter over
  the verified PostgreSQL Audit chain using the artifact's explicit
  `PERMITTED` boundary. DS-024 exposes only `evaluate_context`: it validates
  the exact Intent/Profile, Rule Set and hash-chain prefix named by the
  persisted Context, derives time and trusted Evidence solely from that
  snapshot, and rejects later history. Raw Intent context is hash-bound but
  never inspected for privileged values. Vendor median requires persisted,
  fresh, hash-verified, allowlisted, scope-bound `ATF_ENRICHED` evidence;
  enabled Rule Sets must emit a restrictive finding when it is absent.
- `crates/atf-audit` — the Audit Ledger domain logic: hash-chained events,
  append-only tamper detection (`verify_chain`), and version-1 typed payloads
  for all canonical PRD lifecycle/administrative events. Event-to-state
  effects reuse `atf-core`'s transition table; malformed, mismatched, unknown,
  or post-terminal evidence fails closed. Its standalone `AuditLedger` remains
  an in-memory domain utility; the Gateway uses `atf-store` as the persistent
  writer/verifier and has no in-memory Audit fallback.
- `crates/atf-decision` — the real PRD §10.1 Policy/Risk merge plus the closed
  DS-025 Decision v1 envelope. It binds Intent/Profile, exact Policy/Risk
  artifact references, Evaluation Context/snapshot, explicit Simulation
  state, evaluation/expiry times, future Approval/Obligation sets and closed
  execution constraints under a domain-separated canonical hash. The
  Simulator branch remains unwired.
- `crates/atf-store` — the SQLx/PostgreSQL persistence boundary, embedded
  migration runner, schema compatibility check, and initial constrained
  tables for organizations, Intents, Evaluations, Decisions, idempotency
  reservations, per-organization Audit heads/events, and schema metadata. It row-locks each organization's
  head for concurrent Audit append and can reload/verify canonical bytes,
  hashes, sequence, predecessor links, and the head after restart. Its two
  coarse repository transactions now authenticate the current durable Agent
  and exact Key, consume the signed Nonce, and atomically commit canonical
  Intent + `IntentReceived` + `IDENTITY_VERIFIED/v2`; finalization commits
  typed Policy/Risk/Simulation evidence + Evaluation + Decision + the final
  lifecycle state at `v6`. DS-025 persists the Decision's embedded canonical
  hash, verifies its Intent/Context binding on write/read and mirrors the same
  binding values into current `DecisionRecorded` evidence.
  Migration 0002 stores state, optimistic version, contract version, update
  time, and the last state-producing Audit event pointer. Migration 0003 adds
  immutable organization/key -> Intent-hash bindings, database-clock evaluator
  leases, monotonically increasing fencing generations, and completed
  Evaluation/Decision/hash references. Admission creates the reservation,
  Intent and `IntentReceived` atomically; finalization verifies the active
  lease and completes the reservation with the Decision transaction. Expired
  leases can be conditionally reclaimed, but generation >1 can only finalize
  a fail-closed `ERROR`; DS-023 now persists or reuses an immutable recovery
  context before that terminal result. Contract-v1 reads
  replay typed events and reject any materialized-state mismatch; concurrent
  finalizers cannot both advance the same Intent. The Gateway uses this
  boundary for all accepted Intents, Evaluations, Decisions, Audit writes, and
  Decision reads. Migration 0004 adds immutable organization-scoped Agent and
  Ed25519 public-key lifecycle rows; every version points to the typed Audit
  event committed atomically with it, and verified reads recompute canonical
  bytes/hashes after restart.
  Migration 0005 adds immutable organization/Agent-scoped Nonce hashes bound
  by composite foreign keys to the exact Key, Intent, idempotency reservation
  and `IdentityVerified` evidence. Reads reverify those bindings and their
  historical Agent/Key lifecycle facts. Migration 0006 adds immutable external
  Operator subject fingerprints and explicit organization-role lifecycle rows;
  their canonical records, versions, status and last-event pointers are bound
  to typed Audit evidence and protected against rebinding/deletion/truncate.
  Migration 0007 persists only signed immutable Policy Bundle archives and
  publisher public keys, plus monotonic organization/environment/Bundle active
  pointers retaining the immediately prior signed version for rollback. Every
  install, activation and rollback is atomically bound to `PolicyChanged`.
  Migration 0008 adds immutable, one-per-Intent Evaluation Context snapshots;
  exact canonical bytes/hash and redundant columns are bound to the admitted
  Intent, selected Profile/artifacts, verified Audit-history prefix and one
  `ContextEnriched` event. Final Evaluations foreign-key the snapshot hash.
- `cli/atf-cli` — `atf validate-intent`, `atf evaluate`, `atf policy test`,
  `atf policy install/activate/rollback`,
  offline `atf identity` provision/register/status/revoke commands, and
  offline `atf operator` subject/status/role commands. Lifecycle commands read
  `DATABASE_URL`; Operator provisioning reads the raw external subject only
  from stdin and persists only its domain-separated fingerprint.
- `services/gateway` (`atf-gateway`) — an HTTP service wiring Policy, Risk
  (including the history-dependent duplicate-purchase check), Decision, and
  Audit into one request path: `POST /v1/intents` and
  `GET /v1/intents/{id}/decision`, authenticated Policy activation/rollback,
  plus `/healthz`/`/readyz`. PostgreSQL is
  required at startup, `/readyz` verifies live storage/schema compatibility
  and fresh usable configured JWKS, and restart/second-instance reads return
  the committed Decision. GET requires one validated RFC 9068 Bearer JWT plus
  a current PostgreSQL `auditor` or `org_admin` role for the canonical
  `X-ATF-Organization-ID` selector. JWT role/organization/email claims and the
  selector itself grant no authority. POST requires one canonical detached
  `X-ATF-Identity-Envelope` and exact Ed25519 signature, rechecks the current
  durable Agent/Key, and consumes the Nonce before Policy/Risk. Rejections and
  conflicting replay produce typed durable evidence without admitting an
  Intent. Agent and Operator credentials form disjoint typed principals:
  either credential on the wrong business route fails generically. The
  configured HTTPS issuer/discovery/JWKS boundary uses exact issuer/audience,
  asymmetric algorithm and `at+jwt` checks with bounded key refresh; every
  protected read reloads current local subject status and roles so disable or
  revoke takes effect on the next request. Missing/invalid credentials return
  one safe 401 challenge; absent, cross-tenant and wrong-role Decision reads
  are indistinguishable 404 responses.
  Each new evaluation loads and fully revalidates the current signed durable
  active pointer in one repeatable-read snapshot, so an audited activation or
  rollback applies to the next request without restarting the Gateway.
  Startup also loads one required closed Risk Rule Set artifact; each Risk
  result and durable `RiskEvaluated` evidence carries its exact version/hash.
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
  retry. DS-023 persists the exact context before Policy/Risk, pins and reuses
  its evaluation time, Policy/Risk identities and Audit history, and records
  `ContextEnriched` before module output. Recovered work reuses an existing
  context or creates an explicit unavailable recovery context, then records
  `RECOVERY_REPLAY_NOT_IMPLEMENTED -> Decision(ERROR)` until DS-026 replay.
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
domain-separated Identity Envelope and exact-key verification. `DS-015` adds
durable Agent/key lifecycle, atomic operator Audit evidence and offline
provisioning. `DS-016`, Gateway verification plus atomic Nonce consumption, is
complete. `DS-017` accepted the operator authentication trust boundary in
ADR-0003 on 2026-08-08. `DS-018` implements that boundary with migration 0006,
offline Operator/role lifecycle, typed principals, Gateway JWT/JWKS validation,
and organization-scoped non-enumerating Decision-read RBAC. `DS-019` replaces
raw Cedar directory loading with Schema-backed, scoped, time-bounded Policy
Bundle manifests and deterministic file-bound bundle identities. `DS-020`
adds detached publisher proof, migration 0007 immutable archives and active
pointers, authorized install/activation/rollback, and per-request Gateway
resolution of the exact current signed version. `DS-021` adds the closed
versioned Risk Rule Set, stable canonical hash, executable missing-data and
accounting-boundary semantics, and Rule Set identity in durable Risk evidence.
`DS-022` adds the closed Evidence contract, canonical hash/freshness/signature
verification and the Risk privileged-context firewall; the Gateway no longer
uses Agent-provided vendor median as trusted financial data.
`DS-023` adds the closed Evaluation Context schema/type, migration 0008
immutable snapshot store and typed Audit evidence. Gateway pins the resolved
Policy, Risk Rule Set, evaluation time, Agent-context hash, verified Evidence
set/trust identity, market/Simulation availability and exact Audit-history
prefix before evaluation; final Evaluation rows bind that context hash.
`DS-024` removes all Policy/Risk clock-sampling and separately supplied
privileged-input entry points. Both engines now validate and consume the
persisted Context; Risk additionally verifies the exact Audit prefix and
rejects Agent vendor values and post-snapshot history.
`DS-025` replaces the four-field Decision with a closed, strongly bound v1
envelope and domain-separated canonical hash. Store finalization and reads
verify it against the immutable Intent/Context, while current
`DecisionRecorded` payloads mirror the same bindings.

`schemas/` has `transaction-intent.schema.json` (enforced by `atf-intent`),
`profiles/payment-intent-v1.schema.json` (the structural companion to the
Rust profile validator),
`policy-bundle.schema.json` (enforced by `atf-policy` while loading manifests),
`policy-bundle-signature.schema.json` (the detached Ed25519 proof contract),
`risk-rule-set.schema.json` (the closed DS-021 Risk artifact contract),
`evidence.schema.json` (the closed DS-022 provenance envelope contract),
`evaluation-context.schema.json` (the closed DS-023 input snapshot contract),
`decision.schema.json` (the closed DS-025 envelope, validated in CI against
all four real `atf-decision` outcomes),
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
   `atf_risk::evaluate_context` adds a duplicate-purchase check over the exact
   Context-bound verified Audit prefix
   (same Organization + Agent + Resource within 24h, reading only prior
   `DecisionRecorded(PERMIT)` events) — verified end-to-end through
   `services/gateway`; a prior DENY does not poison a later valid request,
   and one organization's history cannot affect another. Daily cumulative
   spend, first-time destination address, and order frequency are still
   not implemented. DS-021 makes the current rule's `PERMITTED` boundary
   explicit and requires every future history rule to declare `REQUESTED`,
   `PERMITTED`, `EXECUTED`, or `SETTLED`.
5. ~~`atf-identity` — Agent registration + Ed25519 identity-signature
   verification (PRD §17.2).~~ Done as a library and hardened in DS-014: its
   in-memory registry verifies only the declared Key ID over canonical
   domain-separated Envelope bytes, supports explicit rotation overlap, and
   gates Agent status, organization, environment and lifetime. DS-016 now
   calls it from `services/gateway` against durable Agent/Key lifecycle and
   atomic Nonce state; lifecycle provisioning remains offline.
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
   tests. **Not** wired in: Simulation or Approval. DS-020 adds only the first
   Admin HTTP subset (Policy activate/rollback); Agent/Operator/Policy
   installation lifecycle provisioning remains an offline CLI. Agent identity
   is wired on POST and Operator RBAC is wired on Decision GET and Policy
   mutation routes.
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
    conditionally reclaimed after restart, given an immutable explicit-
    unavailable recovery context, and terminated once as
    `RECOVERY_REPLAY_NOT_IMPLEMENTED` until Original Replay exists.
14. ~~Domain-separated Agent Identity Envelope.~~ Done in DS-014:
    `ATF_INTENT_V1` sorted canonical bytes bind organization, Agent, exact
    Key ID, Intent hash, a closed five-minute lifetime, nonce, audience and
    environment. Strict Ed25519 verification has no raw-hash/any-key fallback;
    a published vector and mutation tests lock the cross-language contract.
15. ~~Durable Agent/Key lifecycle and offline provisioning.~~ Done in DS-015:
    migration 0004 stores canonical organization-scoped Agent and exact
    Ed25519 public-key records with lifecycle versions/event pointers;
    registration, status and irreversible revocation commit typed Audit in the
    same transaction. Restart, bounded rotation overlap, concurrency,
    rollback, tenant isolation, tamper and real CLI tests pass without storing
    private keys.
16. ~~Gateway identity verification and atomic Nonce consumption.~~ Done in
    DS-016: strict detached identity Headers, required trusted
    audience/environment, current Agent/exact-Key verification, immutable
    hashed Nonce bindings and typed verified/rejected/replay evidence all land
    before Policy/Risk. Exact retries add no evidence; conflicting concurrent
    reuse has one winner; restart, tenant isolation and privileged-tamper tests
    fail closed without storing raw Nonces, Envelopes or signatures.
17. ~~Operator authentication trust boundary.~~ Done: accepted
    [`ADR-0003`](docs/decisions/0003-operator-authentication.md): the Gateway
    validates short-lived RFC 9068 access tokens, while PostgreSQL binds the
    external subject to current organization roles. Agent and operator
    principals are disjoint; selectors and proxy Headers grant no authority.
    Acceptance closes DS-017 only; it does not claim runtime protection.
18. ~~Organization-scoped operator RBAC.~~ Done in DS-018: migration 0006 and
    `atf-store` persist immutable external-subject fingerprints plus explicit
    organization roles with typed Audit; offline CLI provisioning never stores
    the raw subject; the Gateway validates configured HTTPS issuer/JWKS RFC
    9068 tokens into disjoint typed principals and requires a freshly loaded
    `auditor`/`org_admin` role for non-enumerating Decision reads. Revocation,
    disable, restart, cross-tenant, confused-deputy, redaction and real HTTP/
    PostgreSQL paths are covered.
19. ~~Validated Policy Bundle identity.~~ Done in DS-019: the closed manifest,
    Cedar Schema, exact file digests, organization/environment scope and active
    window are domain-separated into one deterministic Bundle hash; load and
    per-request validation fail closed, and Policy output carries the exact
    bundle ID/version/hash.
20. ~~Signed durable Policy activation and rollback.~~ Done in DS-020:
    migration 0007 stores immutable exact-byte archives, strict detached
    Ed25519 proof and publisher public-key evidence; monotonic active pointers
    atomically retain the previous version and bind install/activate/rollback
    to typed `PolicyChanged`. JWT-authenticated Admin routes recheck current
    `policy_author`/`org_admin`, and Gateway evaluation resolves the signed
    pointer per request.
21. ~~Versioned Risk Rule Set.~~ Done in DS-021: the closed artifact and
    engine compatibility version bind enabled rules, severities, thresholds,
    deny lists, missing-data behavior and all four lifecycle accounting
    boundaries into a deterministic domain-separated hash. Every Risk result
    and current Gateway Risk evidence names the exact Rule Set version/hash.
22. ~~Provenance-bearing evidence.~~ Done in DS-022: the closed numeric-free
    envelope binds typed source/kind, source ID, observation/expiry times,
    value and confidence into a canonical hash; exact trust allowlists,
    optional strict Ed25519 proof and explicit freshness produce only
    `VerifiedEvidence`. Risk rejects Agent privileged context, stale/tampered/
    unsigned/wrong-scope evidence and ambiguous matching values fail closed.
23. ~~Immutable Evaluation Context.~~ Done in DS-023: migration 0008 persists
    one canonical, hash-verified, immutable snapshot before Policy/Risk and
    atomically appends matching `ContextEnriched` evidence. Gateway pins one
    time, Profile, signed Policy identity, Risk identity, Agent-context hash,
    verified Evidence/trust selection, Audit-history prefix and explicit
    unavailable/`NOT_RUN` inputs; restart readers and finalization reverify all
    bindings and reject stale leases, conflicts and tampering.
24. ~~Context-only Policy/Risk.~~ Done in DS-024: the public evaluators accept
    the immutable Context instead of separate time/Evidence inputs, validate
    exact Intent/Profile/artifact/history bindings, reject history after the
    snapshot, never read Agent vendor fields, and produce byte-equivalent
    Policy/Risk output for repeated evaluation.
25. ~~Strongly bound canonical Decision.~~ Done in DS-025: the closed v1
    envelope binds Intent, Profile, Policy/Risk references, Evaluation
    Context/snapshot, explicit Simulation state, evaluation/expiry times,
    future Approval/Obligation fields and execution constraints under one
    domain-separated hash. Store and `DecisionRecorded` enforce the same
    values; mutation and four-outcome Schema tests lock the contract.
26. **NEXT — Original Replay:** reload the immutable inputs named by the
    original Decision, reproduce its exact hash and append replay evidence
    without overwriting the authoritative result.

### Remaining before Phase 2 can close out

- ~~Restore the `cargo deny 0.20.2` baseline.~~ Done: reviewed and explicitly
  allowed the two new permissive transitive licenses, exact-versioned every
  local workspace dependency, retained wildcard/source denial, and pinned CI
  to the official cargo-deny 0.20.2 Action release commit. BL-002 closes the
  remaining warning-only hole: all new duplicates are denied, and the current
  duplicate families (including the reviewed SQLx/reqwest trust-anchor split)
  are represented by exact-versioned, reasoned exceptions,
  and local/CI checks use `-D warnings` so stale exceptions also fail.
- ~~PostgreSQL request-path persistence and restart/second-instance Decision
  recovery.~~ Done through DS-005 with no process-local Decision/Audit
  fallback. DS-012 adds evaluator leases/fencing and atomic idempotency result
  binding; DS-013 adds exact idempotent result return and request-driven,
  generation-fenced recovery of admitted-but-unfinalized work.
- ~~Stable lifecycle and typed Audit domain contract.~~ Done in DS-006: 21
  states, an exhaustively tested transition table, explicit `NOT_RUN` module
  outcomes, 27 canonical typed payloads, and a strict version-1 JSON Schema.
  DS-007 extends the active contract to 22 states/28 events with a retained
  Shadow-only `IDENTITY_UNVERIFIED` compatibility branch; DS-015 adds four
  typed Agent/Key operator events, DS-016 adds `ReplayDetected`, and DS-018 adds
  four Operator subject/role events, for 37 typed events without changing the
  state set.
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
  complete in DS-013; DS-014 defines the signed Envelope and DS-015 persists
  exact Agent/Key authority. DS-016 completes atomic signed-Nonce replay
  protection at Gateway admission.
- ~~Durable Agent/Key lifecycle and offline provisioning.~~ Done in DS-015
  with restart-safe verification, typed mutation Audit and no private-key
  storage.
- ~~Wire `atf-identity` into Gateway admission before Policy/Risk.~~ Done in
  DS-016 with atomic Nonce consumption and request Identity/replay evidence.
- ~~Organization-scoped operator authentication/RBAC following accepted
  ADR-0003.~~ Done in DS-018 for current Decision reads; Admin/Audit HTTP role
  matrices remain future endpoint-specific work.
- ~~Make Policy/Risk consume only the persisted `EvaluationContext` and
  strongly bind canonical Decisions to it.~~ Done in DS-024/DS-025. Add
  Original/Counterfactual Replay next.
- Organization-scoped Audit Query API, metrics, safe tracing, and API
  security controls.
- The remaining history-dependent Risk rules, each using the now-required
  explicit lifecycle accounting boundary.

The security-audit baseline and prioritized acceptance criteria are tracked
in [`docs/audit-gap-matrix.md`](docs/audit-gap-matrix.md); the phase-level
delivery view is in [`docs/roadmap.md`](docs/roadmap.md). The dependency-ordered
implementation plan and executable checklist are in
[`tasks/plan.md`](tasks/plan.md) and [`tasks/todo.md`](tasks/todo.md).

### Phased plan (PRD §31)

- **Phase 1 (done)**: Policy Kernel + Decision merge + conformance harness.
- **Phase 2 (Durable Shadow Mode, in progress)**: the PostgreSQL-backed
  Gateway foundation and core libraries exist; the remaining release gate is
  deterministic replay, stateful Risk, Audit query/metrics, operational
  hardening, and security re-audit. Strongly bound Decisions are complete in
  DS-025.
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
  ATF_IDENTITY_AUDIENCE=atf-gateway \
  ATF_DEPLOYMENT_ENVIRONMENT=development \
  ATF_POLICY_ORGANIZATION_ID=alpha-lab \
  ATF_POLICY_BUNDLE_ID=atf-example-payments \
  ATF_RISK_RULE_SET_PATH=risk-rules/default.json \
  PORT=8080 cargo run -p atf-gateway

# Provision Agent/public-key authority first; see docs/identity.md. POST then
# requires the detached signed Header contract in docs/gateway-identity.md.
# Install and activate a signed Policy Bundle first; see docs/policy-model.md.

# Validate an intent against the JSON Schema + common/profile semantics + canonical hash
cargo run -p atf-cli -- validate-intent examples/x402-research-agent/intent.json

# Evaluate an intent against an example Cedar policy bundle
cargo run -p atf-cli -- evaluate examples/x402-research-agent/intent.json \
  --policies policies/examples --environment development \
  --risk-rule-set risk-rules/default.json
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
