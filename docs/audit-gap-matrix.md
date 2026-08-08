# Security Audit Baseline and Gap Matrix

Baseline date: 2026-08-05. Baseline commit: `f0a2a3d` plus the
`DecisionRecorded` change documented in `CHANGELOG.md`. Source of truth:
`docs/PRD.md`, `docs/architecture.md`, `docs/threat-model.md`, actual
workspace code and routes, and the audit requirements supplied for this
review.

The original audit-baseline verification was clean for
`cargo fmt --all -- --check`, `cargo clippy --all-targets --all-features -- -D
warnings`, `cargo test --workspace --all-targets --all-features`, and `cargo
deny check`. GitHub has no open or closed Issues or Pull Requests at this
baseline.

Planning revalidation on 2026-08-05 at `d112e7e` passed fmt, clippy and all 80
tests, but `cargo deny 0.20.2 check` initially failed: the dependency graph
contained unreviewed `Apache-2.0 WITH LLVM-exception` and `MIT-0` licenses, and
the current tool rejected unversioned local workspace path dependencies under
`wildcards = "deny"`.

BL-001 repaired that regression on 2026-08-07: local workspace dependencies
now carry exact versions, both new licenses were reviewed from their packaged
license texts, unused license allowances were removed, and CI is pinned to the
official v2.1.1 Action commit for cargo-deny 0.20.2. Wildcard and unknown-source
denial remain enabled; `cargo deny check -D warnings` passes. BL-002 followed
on 2026-08-08 after the graph accumulated 23 upstream-constrained duplicate
families:
new duplicates are now denied, current exceptions are exact-versioned with
upstream-path reasons, target coverage remains unrestricted, and CI rejects
all other warnings plus stale exceptions.

DS-001 fixed the missing persistence design contract on 2026-08-07 in
ADR-0002. It selects one PostgreSQL storage boundary, per-organization
row-locked Audit chains, atomic admission/finalization, evaluator fencing, and
forward-only migration compatibility. This reduces design ambiguity only;
the remaining admission/finalization and Gateway runtime guarantees stay open.

DS-002 added the `atf-store` boundary and migration 0001 on 2026-08-08. The
schema stores canonical JSON/bytes and hashes for tenant-scoped Intents,
Evaluations, Decisions, and Audit events; composite foreign keys reject
cross-tenant references; database triggers reject Audit UPDATE, DELETE, and
TRUNCATE. CI now exercises those constraints on PostgreSQL 17.10.
DS-003 added the row-locked per-organization writer and full-chain reload
verifier on 2026-08-08. PostgreSQL 17.10 tests cover 32 same-organization
writers without forks, independent organization genesis/head state, restart
verification, corruption/deletion/sequence-reordering detection, and refusing
to extend a corrupt tail. Gateway persistence and request-path restart behavior
remain open.
DS-004 added short admission/finalization repository transactions on
2026-08-08. Real PostgreSQL tests inject failures at both Audit insert points,
prove the paired business rows roll back, reject immutable Intent/idempotency
conflicts and stale Intent hashes, and refuse to expose a Decision without its
matching canonical Evaluation and foreign-key-bound verified Audit evidence.
DS-005 cut the Gateway over on 2026-08-08. PostgreSQL is now the only
Decision/Audit path; real integration and socket tests prove restart and
second-instance reads, durable Risk history, tenant-keyed lookup, and 503
readiness/request behavior when storage is unavailable. DS-006 added the
21-state fail-closed lifecycle contract, typed/versioned payloads for all 27
canonical Audit events, a closed JSON Schema, and typed current store
producers. DS-007 extends that contract to 22 states/28 events, persists
state/version/event pointers, emits all current phase events, replays them on
reads, rejects stale finalizers, and rolls back injected partial batches.
Fenced idempotency completion is now implemented by DS-012; authenticated
tenant binding remains open.
DS-008 then closed the Intent envelope/version contract. DS-009 adds
deterministic common semantics on 2026-08-08: financial/time/ULID/text
violations have stable codes and fixed order, the CLI fails non-zero, and a
real Gateway/PostgreSQL test proves invalid input produces no durable business
or Audit record before Policy/Risk. DS-010 then adds a closed versioned Profile
dispatcher and the protocol-neutral Agent-Commerce Payment v1.0 contract:
typed resources, strict CAIP-2/10/19 syntax, exact asset/payee chain binding,
forbidden contract/trading fields, and unsupported-action rejection all occur
before admission. Protocol-specific and other financial Profiles remain later
work. DS-011 then fixes one safe business-error envelope, adds a fresh
server-owned request ID to every response, maps Router/validation/Store errors
without exposing internal diagnostics, and proves Schema/common/Profile
rejection leaves the reservation plus all four durable business tables empty.
DS-012 then adds
migration 0003, atomically binds each organization/key to one canonical Intent
hash, grants exactly one database-clock evaluator lease, supports renewal and
expired-lease reclaim with monotonically increasing fencing generations, and
atomically binds an immutable completed result to its Evaluation/Decision/Audit
evidence. Real PostgreSQL tests cover races, restart through a second Store,
rollback, stale-owner rejection, fail-closed recovered work and result
tampering. DS-013 then wires exact completed retry, stage-boundary heartbeat,
barrier-tested concurrent convergence and request-driven fail-closed recovery
after restart. DS-014 replaces raw-hash signatures with the canonical
domain-separated Identity Envelope and exact-key verification. DS-015 adds
migration 0004, durable Agent/Key lifecycle, atomic typed operator Audit and
public-key-only offline provisioning. DS-016 completes Gateway verification
and atomic signed-Nonce consumption with
migration 0005, strict detached identity Headers, current exact-Key
verification and typed rejection/replay evidence.
DS-018 adds migration 0006, durable Operator subjects/organization roles,
offline typed-Audit provisioning, Gateway JWT/JWKS validation, disjoint typed
principals and non-enumerating Decision-read RBAC.

## Module inventory

| Module | State | Evidence |
|---|---|---|
| `atf-core` | `IMPLEMENTED_AND_WIRED` | Fixed-point `Amount`, timestamps, ULIDs, canonical JSON sorting, SHA-256, shared Decision kind, and the exhaustive 22-state lifecycle transition contract; used throughout the workspace. |
| `atf-intent` | `PARTIALLY_IMPLEMENTED` | Closed Schema/type parsing, canonical hash, common financial/time/ULID/text semantics, and the versioned Agent-Commerce Payment Profile are wired with stable ordered errors; every other action pair fails closed until its Profile exists. |
| `atf-identity` | `IMPLEMENTED_AND_WIRED` | DS-014 canonical `ATF_INTENT_V1` bytes, bounded scope/time validation, exact Key ID strict Ed25519 verification, stable errors and a published vector exist. DS-015 adds validated key windows and PostgreSQL-backed Agent/Key authority. DS-016 requires it before Policy/Risk and atomically consumes hashed Nonces. |
| `atf-policy` | `PARTIALLY_IMPLEMENTED` | Cedar evaluation is wired; bundle manifest/version/hash/signature/scope and Cedar schema validation are missing. |
| `atf-risk` | `PARTIALLY_IMPLEMENTED` | Five stateless rules and one history rule are wired; the Gateway supplies verified PostgreSQL Audit events, while trusted context, versioning, deterministic time, bounded history queries, and most PRD rules are missing. |
| `atf-audit` | `PARTIALLY_IMPLEMENTED` | The domain library provides the event envelope, in-memory verifier, 37 canonical typed/versioned payloads, scope validation, event effects, and a strict Schema verified against real output. DS-015 adds four Agent/Key events, DS-016 adds `ReplayDetected`, and DS-018 adds four Operator/Role events; the Gateway and offline lifecycle commands persist/verify current evidence through `atf-store`. Queries and checkpoints remain. |
| `atf-decision` | `PARTIALLY_IMPLEMENTED` | Policy/Risk merge and the closed strongly bound Decision v1 envelope are wired; the Simulator branch remains absent. |
| `atf-store` | `PARTIALLY_IMPLEMENTED` | Embedded migrations/schema checks, constrained tenant tables, append-only triggers, row-locked per-org Audit append, authenticated atomic admission/finalization, persisted/replayed Intent, Agent/Key and Operator/Role lifecycle, immutable hashed Nonce bindings, evidence-gated reads, evaluator lease/fencing, immutable completed idempotency results, exact completed-result reads, request-driven fail-closed recovery, and live readiness exist. Background scanning and provenance-pinned deterministic recovery remain absent. |
| `atf-cli` | `PARTIALLY_IMPLEMENTED` | `validate-intent`, `evaluate`, `policy test`, offline `identity` provision/register/status/revoke, and offline `operator` subject/status/role commands exist; most PRD §21 commands are missing. |
| `services/gateway` | `PARTIALLY_IMPLEMENTED` | Four live routes use durable admission/finalization and verified history; POST requires current durable Agent identity and atomic Nonce protection, while Decision GET requires a Gateway-validated JWT plus current durable organization read role. Restart/second-instance reads, database/JWKS readiness, stable safe errors, validation ordering, exact retry, conflicting replay, concurrency, local role revocation, confused-deputy behavior and retry-driven fail-closed recovery are tested. Background recovery, general configured limits, full correlation, metrics, and Audit/Admin query APIs are missing. |
| Simulator, Approval, Reconciliation, Adapter crates | `SCAFFOLD_ONLY` | Each contains only a README and is not a workspace member. |
| Policy/Audit/Approval/Reconciliation services | `SCAFFOLD_ONLY` | Each contains only a README and is not runnable. |
| `conformance/policy-tests` | `IMPLEMENTED_AND_WIRED` | Three cases run through `atf policy test`. |
| Adapter/replay conformance, fuzz, deploy | `SCAFFOLD_ONLY` | README placeholders only. |
| SDKs and most target documentation | `MISSING` | No SDK implementation; `policy-model.md`, quickstart, and adapter manifest Schema are absent. `intent-spec.md` fixes the DS-010 Payment Profile, `identity-envelope.md` plus the published vector fix DS-014 signing bytes, `api.md` fixes the DS-011 live route/error contract, and `audit-model.md` defines the DS-007 transactional lifecycle/payload contract. |
| README/Architecture/Threat Model | `IMPLEMENTATION_DOCUMENTATION_DRIFT` | Several stale claims were corrected in this change; ongoing schema/API/status checks are still needed. |

## Gap matrix

### GAP-INT-001 — Intent Schema Validation

- **module:** `atf-intent`, `schemas/transaction-intent.schema.json`
- **current_state:** `PARTIALLY_IMPLEMENTED` — DS-008 structural contract and the DS-010 Agent-Commerce Payment companion Schema are complete; additional Action Profile Schemas remain release-specific work.
- **evidence:** top-level and nested core objects are closed in both JSON Schema and direct Serde parsing; only `spec_version: "1.0"` is accepted. `context`/`metadata` must be objects, remain open inside, survive typed round trips, and are included in the canonical hash. The x402 v1 fixture has a golden hash and mutation tests cover every mutable v1 field. `schemas/profiles/payment-intent-v1.schema.json` fixes the supported selector and structural field ownership, with cross-field rules enforced by Rust.
- **security_impact:** structural data is not silently dropped; an extension remains hash-bound but untrusted and cannot select or override the derived Payment Profile. Other action pairs are rejected rather than accepted under an incomplete shape.
- **financial_impact:** Payment fee denomination, resource/payee presence and field ownership are explicit. A qualifier placed only in `context`/`metadata` remains evidence and cannot change financial semantics; additional behavior requires a new versioned Profile.
- **severity:** `HIGH`
- **recommended_change:** keep the closed core and derived-profile convention; add a companion Schema, Rust validator and conformance fixtures together whenever another action is enabled.
- **required_tests:** unknown-core-field rejection, context/metadata hash sensitivity, Schema/Rust round-trip, supported-profile metadata, structural compatibility and unsupported-selector rejection are implemented.
- **dependencies:** final semantics for each future action and Adapter capability.
- **target_release:** Durable Shadow Mode, immediately after persistence semantics are fixed.
- **acceptance_criteria:** no unvalidated core field is silently ignored; every accepted field affecting intent meaning is present in the canonical hash.

### GAP-INT-002 — Cross-field Semantic Validation

- **module:** `atf-intent`
- **current_state:** `PARTIALLY_IMPLEMENTED` — DS-009 common invariants and DS-010 closed dispatch/Agent-Commerce Payment semantics are complete; additional action Profiles remain unsupported.
- **evidence:** after closed Schema and typed parsing, `validate` rejects common financial/time/ULID/text violations, then derives exactly `atf.agent-commerce.payment` v1.0 for `payment/purchase_api_resource`. It requires a typed resource, strict CAIP-2/19/10 IDs with exact chain equality, and forbids contract/calldata/slippage/leverage fields. Errors are stable and deterministic without coercion. CLI conformance and a PostgreSQL route test prove semantic or unsupported-profile rejection leaves Intent, Evaluation, Decision and Audit state empty. Transfer, Contract Call, Token Approval, Exchange, Treasury and other actions return `UNSUPPORTED_INTENT_PROFILE`.
- **security_impact:** malformed common fields, cross-chain payment confusion, action-field smuggling and every semantically unimplemented action fail before durable admission or Policy/Risk. Namespace-specific address/asset validity remains a later protocol/Adapter responsibility.
- **financial_impact:** common bounds and the supported Payment resource/asset/payee/fee relationships are enforced. Allowance, order, swap and other financial semantics remain unavailable rather than ambiguously accepted.
- **severity:** `HIGH`
- **recommended_change:** retain closed dispatch; enable a new action only with versioned semantics, stable codes, a companion Schema and protocol conformance tests.
- **required_tests:** common and profile boundary/order tests, profile metadata/Schema tests, all-category unsupported checks, CLI smoke and Gateway/PostgreSQL pre-admission tests are implemented.
- **dependencies:** final field shapes and trusted namespace/protocol validation for future approval, exchange, prediction-market and Adapter profiles.
- **target_release:** Durable Shadow Mode P0.
- **acceptance_criteria:** achieved for the advertised surface: common invalid combinations and unsupported actions never reach admission or Policy/Risk, and the one accepted Payment profile enforces its cross-field contract. The inventory remains partial because additional product actions have no implemented semantics.

### GAP-IDN-001 — Agent Identity Verification

- **module:** `atf-identity`, `services/gateway`
- **current_state:** `CLOSED_CURRENT_SCOPE`
- **evidence:** DS-014 removes the raw Intent-hash/try-any-key verifier. DS-015 migration 0004 persists exact Agent/public-key lifecycle and Audit pointers. DS-016 requires bounded canonical detached Headers and trusted audience/environment, locks and reverifies the current durable Agent/exact Key, and atomically commits hashed Nonce + idempotency + Intent + `IntentReceived` + `IdentityVerified` before Policy/Risk. Invalid proof commits only `IdentityRejected`; conflicting reuse commits `ReplayDetected`. Restart, concurrent one-winner, tenant isolation, lifecycle, rollback, mutation guards, privileged tamper, exact retry and wrong signature/audience/environment tests pass.
- **security_impact:** current POST admission no longer accepts Agent impersonation or conflicting signed-Nonce replay; operator/read authentication is tracked separately by GAP-API-001.
- **financial_impact:** an unverified Agent request cannot enter Policy/Risk or poison accepted Intent history.
- **severity:** `CLOSED` (formerly `HIGH`)
- **recommended_change:** retain the DS-014..DS-016 canonical/exact-key/atomic-Nonce invariants and the disjoint DS-018 Operator principal while adding edge hardening.
- **required_tests:** implemented for the current scope; keep in PostgreSQL and Gateway regression suites.
- **dependencies:** PostgreSQL, Admin provisioning/RBAC, idempotency nonce store.
- **target_release:** Durable Shadow Mode P0.5.
- **acceptance_criteria:** identity failure records `IdentityRejected`, returns fail-closed, and Policy/Risk are not called.

### GAP-API-001 — Authentication and Authorization

- **module:** `services/gateway`
- **current_state:** `CLOSED_CURRENT_SCOPE`
- **evidence:** DS-018 migration 0006 persists immutable issuer/subject
  fingerprints, local Operator status and explicit organization roles with
  canonical records, typed Audit pointers and mutation guards. Offline CLI
  provisioning stores no raw subject. Gateway startup loads only configured
  HTTPS discovery/JWKS, validates asymmetric RFC 9068 `at+jwt` issuer,
  audience, signature, time, subject and key, then reloads current local status
  and roles for every Decision read. Agent and Operator principals are
  disjoint; selector/JWT role claims grant nothing; missing/cross-tenant/
  wrong-role resource reads do not enumerate. PostgreSQL/Gateway tests cover
  restart, role revoke/regrant, subject disable, token failures, redaction and
  confused-deputy cases, with a real authenticated HTTP smoke.
- **security_impact:** the current POST and Decision GET surfaces require
  route-appropriate typed principals; local revocation is immediate on the
  next request. Future Admin/Audit routes and edge deployment controls remain
  separate gaps.
- **financial_impact:** Decision contents are no longer anonymously readable
  through a forged organization selector; this route remains read-only.
- **severity:** `CLOSED` (formerly `CRITICAL`)
- **recommended_change:** preserve disjoint principals and current durable-role
  reload when adding explicit capability matrices for future routes.
- **required_tests:** implemented for the current route matrix; retain token,
  cross-tenant, role, revocation, restart, tamper, redaction and confused-deputy
  regressions.
- **dependencies:** identity envelope, durable Operator/Role lifecycle and
  configured HTTPS issuer/JWKS are complete; DS-034 still owns edge hardening.
- **target_release:** Durable Shadow Mode before any shared deployment.
- **acceptance_criteria:** met for current non-health routes; new routes must
  add an explicit principal/capability contract before exposure.

### GAP-RPL-001 — Idempotency and Replay Protection

- **module:** Gateway persistence and identity envelopes
- **current_state:** `CLOSED_CURRENT_SCOPE`
- **evidence:** DS-012/DS-013 implement immutable organization/idempotency/Intent-hash binding, evaluator lease/fencing, completed result evidence, exact retry and restrictive recovery. DS-016 migration 0005 adds immutable `(organization_id,agent_id,nonce_hash)` binding to the exact Key, Envelope hash, Intent/idempotency tuple, lifecycle versions and `IdentityVerified` event. Exact retries add nothing; fresh valid retries consume a new Nonce; conflicting concurrent/post-restart reuse emits `ReplayDetected` and returns 409. Database guards and verified reads reject mutation/tamper.
- **design evidence:** ADR-0002 plus `docs/gateway-identity.md` define the implemented transaction and retry/replay semantics.
- **security_impact:** concurrent evaluation, stale completion, completed-response loss, stranded admission and signed request replay are fenced at the current durable Gateway boundary.
- **financial_impact:** one signed Nonce cannot authorize another binding; completed retries return the original result after restarts or Policy changes.
- **severity:** `CLOSED` (formerly `CRITICAL`)
- **recommended_change:** retain DS-012..DS-016 invariants; future execution/payment proof Nonces require their own single-use stores.
- **required_tests:** implemented for different-hash conflict, exact/fresh retry, active work, concurrency, restart, restrictive recovery, rollback, immutable rows and tamper.
- **dependencies:** PostgreSQL transaction boundary and Identity envelope.
- **target_release:** Durable Shadow Mode P0.4.
- **acceptance_criteria:** met: exactly one evaluator wins, conflicts return stable durable codes, completed duplicates return the original Decision, and authenticated Nonce replay is rejected or classified as that exact original binding.

### GAP-POL-001 — Policy Bundle Validation

- **module:** `atf-policy`
- **current_state:** `PARTIALLY_IMPLEMENTED`
- **evidence:** DS-019 replaces raw concatenation with a closed manifest that
  binds bundle ID/version, organization/environment, millisecond active window,
  Cedar Schema and exact file digests into a domain-separated canonical hash.
  Strict Cedar policy validation runs at load; Schema-backed request validation,
  scope/expiry rechecks and runtime-diagnostic rejection run per evaluation.
  DS-020 adds a domain-separated strict Ed25519 publisher proof, immutable
  exact-byte archive/public-key evidence, unique version enforcement,
  monotonic active pointers, atomic rollback and typed `PolicyChanged`. JWT
  Admin routes and the Store both recheck current Policy roles; Gateway reloads
  and verifies the active artifact per request. Multi-Bundle resolution and
  multi-Bundle resolution remains open. DS-023 pins the resolved Bundle in
  immutable Evaluation Context and final Evaluation input; DS-025 carries the
  same exact identity into canonical Decision/Audit evidence.
- **security_impact:** the selected Bundle is now provenance-checked and
  rollback-safe, but future multi-Bundle composition could still omit or mix a
  required scope until resolver/binding work is complete.
- **financial_impact:** a current evaluation and Decision use one exact
  authorized Bundle; future multi-Bundle resolution still needs explicit
  composition evidence.
- **severity:** `MEDIUM`
- **recommended_change:** retain DS-019/DS-020/DS-023/DS-025 invariants and
  add replay verification plus explicit future multi-Bundle composition.
- **required_tests:** implemented for bad signature/schema/scope/version/
  expiry, duplicate/conflict, concurrent activation, restart, rollback,
  privileged tamper, authenticated RBAC API and real CLI.
- **dependencies:** Admin RBAC, persistence, canonical hashing.
- **target_release:** Durable Shadow Mode P0.9.
- **acceptance_criteria:** bundle load failures are fail-closed and every Decision/Audit event names the exact validated bundle hash/version.

### GAP-RSK-001 — Financial Risk Validation

- **module:** `atf-risk`
- **current_state:** `PARTIALLY_IMPLEMENTED`
- **evidence:** five stateless rules and one duplicate-purchase rule execute
  under a closed DS-021 artifact whose version/hash binds enabled state,
  severity, thresholds, deny lists, explicit missing-data behavior and all
  lifecycle accounting-boundary choices. Gateway evidence records that exact
  identity. Most PRD §12 rules, durable Rule Set selection and trusted inputs
  do not exist.
- **security_impact:** common split-order, allowance, withdrawal, leverage, concentration, and velocity threats are unchecked.
- **financial_impact:** budget, market, protocol, and execution-risk losses are not bounded.
- **severity:** `HIGH`
- **recommended_change:** add rules only against provenance-bearing immutable
  context/snapshots and require their decision inputs plus accounting boundary
  to remain inside the Rule Set identity.
- **required_tests:** independent unit/boundary/missing-data/property tests per rule and fail-closed integration tests.
- **dependencies:** EvaluationContext, provenance, persistence, lifecycle state.
- **target_release:** Durable Shadow Mode and reference scenarios incrementally.
- **acceptance_criteria:** each enabled rule has a stable code, recorded inputs/version, deterministic result, and explicit missing-data outcome.

### GAP-CTX-001 — Context Provenance and Freshness

- **module:** `atf-intent`, `atf-risk`, future enrichers
- **current_state:** `PARTIALLY_IMPLEMENTED`
- **evidence:** DS-022 adds a closed public Evidence Schema and Rust envelope
  with typed source/kind, source ID, observation/expiry, numeric-free value,
  confidence, canonical hash, optional strict Ed25519 proof and derived
  freshness. Exact source/kind allowlists alone construct `VerifiedEvidence`.
  DS-024's Context-only Risk entry point separates nine privileged Agent input
  classes without inspecting their raw values; the current vendor rule accepts
  only a fresh, hash-verified, exact-scope `ATF_ENRICHED` median persisted in
  Context. Agent overrides and cross-Intent/artifact/history reuse fail closed;
  stale/tampered/unsigned Evidence cannot enter Context, and ambiguous or
  wrongly scoped values produce restrictive findings. Real Gateway and
  PostgreSQL coverage proves Agent median cannot preserve Permit. DS-023
  persists the exact verified
  envelopes, trust-policy identity, Agent-context hash, evaluation time and
  Audit-history prefix in one immutable canonical Evaluation Context before
  Policy/Risk, with typed Audit, fencing, restart and tamper verification.
- **security_impact:** the requester no longer controls the current vendor
  comparison input, and persisted snapshots cannot be silently substituted.
  Production enrichers are absent. DS-024 now ensures every evaluator uses
  only the typed snapshot boundary and rejects Intent/artifact/history
  substitution before rule execution.
- **financial_impact:** current price-context manipulation becomes REVIEW;
  balance/position/spend/reputation/simulation rules remain unimplemented.
- **severity:** `HIGH`
- **recommended_change:** retain the DS-024 context-only evaluator boundary;
  production enrichers must never reconstruct authority from Agent fields.
- **required_tests:** source allowlist, stale/missing evidence, hash/signature mismatch, Agent override rejection.
- **dependencies:** production enrichment; DS-024 evaluator cutover is complete.
- **target_release:** Durable Shadow Mode P0.8.
- **acceptance_criteria:** every decision-affecting external value has recorded provenance/freshness and untrusted sources cannot overwrite it.

### GAP-RPY-001 — Deterministic Replay

- **module:** Core evaluation pipeline and replay conformance
- **current_state:** `MISSING`
- **evidence:** DS-023 now records the exact Policy/Risk identities, evaluation
  time, verified Evidence and history snapshot before evaluation. Legacy
  Policy/Risk convenience APIs still sample `Timestamp::now()` or accept
  separately supplied inputs; replay conformance remains a README only.
- **security_impact:** original decisions cannot be independently reproduced or investigated.
- **financial_impact:** disputes and regressions cannot prove which inputs caused an authorization.
- **severity:** `HIGH`
- **recommended_change:** versioned `EvaluationContext`, immutable snapshots, original/counterfactual replay APIs, and non-overwriting results.
- **required_tests:** same-input repeatability, wall-clock independence, missing-version fail-closed, counterfactual isolation.
- **dependencies:** persistence, policy/risk versioning, provenance.
- **target_release:** Durable Shadow Mode P0.6-P0.7.
- **acceptance_criteria:** original replay reproduces the Decision hash exactly; counterfactual replay creates a distinct evaluation.

### GAP-BUD-001 — Budget Concurrency

- **module:** Budget domain/store (absent)
- **current_state:** `MISSING`
- **evidence:** PRD §9.4 budget objects and reserve/commit/release do not exist.
- **security_impact:** parallel Agents can exceed shared limits through check-then-act races or split orders.
- **financial_impact:** organization, Agent, strategy, and task budgets can be overspent.
- **severity:** `CRITICAL`
- **recommended_change:** hierarchical budgets with atomic PostgreSQL reservations and lifecycle audit events.
- **required_tests:** concurrent reservation, parent/child contention, expiry release, retry/idempotency, invariant property tests.
- **dependencies:** PostgreSQL, lifecycle, idempotency, reconciliation.
- **target_release:** after Durable Shadow persistence, before Enforce Mode.
- **acceptance_criteria:** no interleaving can make committed+reserved exceed any active ancestor limit.

### GAP-SIM-001 — Simulation

- **module:** `atf-simulator`
- **current_state:** `SCAFFOLD_ONLY`
- **evidence:** only a README exists and Decision merge has no Simulator input.
- **security_impact:** reverts, malicious calldata, allowance changes, and unexpected state diffs are unchecked.
- **financial_impact:** authorized requests may have materially different effects than intended.
- **severity:** `HIGH`
- **recommended_change:** deterministic Mock Simulator and typed result/hash before protocol simulators.
- **required_tests:** success/revert/unavailable/stale, hash binding, fail-closed merge, conformance.
- **dependencies:** EvaluationContext and action profiles.
- **target_release:** Reference Simulation/Adapters phase.
- **acceptance_criteria:** required simulation failure cannot result in `PERMIT`, and every result is versioned and hash-bound.

### GAP-DEC-001 — Decision Binding

- **module:** `atf-decision`, `schemas/decision.schema.json`
- **current_state:** `IMPLEMENTED_AND_WIRED`
- **evidence:** DS-025's closed Decision v1 binds Intent/Profile, exact
  Policy/Risk references, Evaluation Context/snapshot, explicit Simulation
  state, evaluation/expiry times, future Approval/Obligation fields and closed
  execution constraints under `ATF_DECISION_V1`. Store write/read verification
  compares the embedded hash and authoritative Intent/Context; current
  `DecisionRecorded.binding` mirrors the same fields.
- **security_impact:** changing a bound field invalidates the Decision hash;
  mismatched module identity, Context or persisted/Audit evidence fails closed.
- **financial_impact:** a future execution grant can bind one exact immutable
  Decision instead of trusting a mutable ID or stale module selection.
- **severity:** `CLOSED` (formerly `HIGH`)
- **recommended_change:** retain DS-025/DS-026 invariants; Original Replay now
  reproduces the exact hash, and future Counterfactual/Simulator/Approval work
  must create explicit lineage or a new version rather than weakening v1.
- **required_tests:** implemented mutation sensitivity, deterministic bytes,
  all-four-outcome closed Schema, module mismatch, PostgreSQL persistence/
  Audit equality, Gateway integration and live API smoke.
- **dependencies:** EvaluationContext, policy/risk versions, simulator.
- **target_release:** Durable Shadow Mode before replay completion.
- **acceptance_criteria:** changing any bound input invalidates the Decision hash and future execution authorization.

### GAP-APR-001 — Approval

- **module:** `atf-approval`, approval service
- **current_state:** `SCAFFOLD_ONLY`
- **evidence:** no approval types, storage, routes, identity, nonce, expiry, or audit transitions exist.
- **security_impact:** `REVIEW` has no controlled resolution path; future ad-hoc approvals would be replay-prone.
- **financial_impact:** high-value operations cannot obtain enforceable human authorization.
- **severity:** `HIGH`
- **recommended_change:** hash-bound, expiring, role/multi-party approvals with single-use nonce and separation of duties.
- **required_tests:** tampered Intent, replay, expiry, partial quorum, self-approval, Kill Switch.
- **dependencies:** auth/RBAC, persistence, Decision binding.
- **target_release:** Approval & Enforce Mode.
- **acceptance_criteria:** no approval applies to a changed/expired Decision and quorum rules are transactionally enforced.

### GAP-EXE-001 — Execution Authorization

- **module:** Execution Grant (absent)
- **current_state:** `MISSING`
- **evidence:** no execution route or grant type exists; this safely prevents execution today.
- **security_impact:** adding an Adapter without a bound single-use grant would create a critical bypass.
- **financial_impact:** modified, replayed, or duplicate transactions could move funds.
- **severity:** `CRITICAL`
- **recommended_change:** keep execution disabled until a signed/hashed, expiring, single-use grant binds Intent, Decision, Approval, Adapter, and request hashes.
- **required_tests:** every-field mutation, nonce race, expiry, wrong Adapter/version, unknown execution state.
- **dependencies:** all Durable Shadow gaps, Approval, Adapter SDK.
- **target_release:** Approval & Enforce Mode.
- **acceptance_criteria:** an Adapter accepts exactly one matching authorized request and rejects all variants/replays.

### GAP-ADP-001 — Adapter Validation

- **module:** Adapter SDK and adapters
- **current_state:** `SCAFFOLD_ONLY`
- **evidence:** README placeholders only; adapter-manifest Schema and conformance harness are absent.
- **security_impact:** capability, secret, timeout, retry, response, and partial-execution behavior has no enforceable contract.
- **financial_impact:** unsafe retries or mismatched venues/assets can duplicate or misroute transactions.
- **severity:** `HIGH`
- **recommended_change:** typed SDK, signed/versioned manifest, Mock Adapter, capability and conformance gates.
- **required_tests:** unsupported capability, timeout/retry safety, idempotency, partial/unknown execution, response validation.
- **dependencies:** Simulator, Execution Grant, action profiles.
- **target_release:** Reference Simulation/Adapters phase.
- **acceptance_criteria:** only manifest-declared, conformance-tested capabilities can receive an Execution Grant.

### GAP-REC-001 — Settlement and Reconciliation

- **module:** `atf-reconciliation`
- **current_state:** `SCAFFOLD_ONLY`
- **evidence:** no settlement proof, delivery proof, reconciliation worker, or lifecycle state exists.
- **security_impact:** payment-proof replay and execution/Intent divergence cannot be detected.
- **financial_impact:** paid-but-undelivered, partial, failed, or unknown outcomes remain unresolved.
- **severity:** `HIGH`
- **recommended_change:** immutable settlement records, proof replay protection, and reconciliation against bound execution results.
- **required_tests:** proof replay, partial execution, unknown settlement, delivery failure, recovery retry.
- **dependencies:** Adapter results, persistence, lifecycle, Execution Grant.
- **target_release:** Approval & Enforce Mode.
- **acceptance_criteria:** every submitted execution reaches a terminal reconciled/explicitly-failed state without overwriting original evidence.

### GAP-AUD-001 — Audit Integrity

- **module:** `atf-audit`, Gateway
- **current_state:** `PARTIALLY_IMPLEMENTED`
- **evidence:** append-only domain API, hash chain, tamper test, and `DecisionRecorded` exist. Migration 0001 adds per-organization PostgreSQL event/head tables and immutable-row triggers. DS-003 row-locks each organization head, assigns sequence/predecessor/hash server-side, checks the locked tail, and reloads/verifies the full chain under one repeatable snapshot. DS-004/DS-005 make atomic admission/finalization authoritative for Gateway and durable Risk history. DS-006 defines typed/versioned payloads and lifecycle effects. DS-007 adds migration 0002 lifecycle materialization, optimistic version locking, typed intermediate events, event-pointer foreign keys, replay verification, compatibility backfill, and fail-closed Policy/Risk errors. Real tests cover all 484 state pairs, every terminal successor, all typed payload/Schema pairs, no-fork concurrency, organization isolation, restart, deletion, mutation, reordering, corrupt-tail refusal, finalizer races, partial-batch rollback, state tampering, migration compatibility, and second-instance Decision reads. Checkpoints, query/retention, and independent verification remain missing.
- **security_impact:** lifecycle evidence has unambiguous versioned semantics and state/event races fail closed; database/operator compromise or missing external checkpoints can still destroy evidence.
- **financial_impact:** transaction authorization history may be incomplete or unverifiable.
- **severity:** `HIGH`
- **recommended_change:** add query APIs/indexes, verification jobs, and external Merkle checkpoints without weakening atomic lifecycle enforcement.
- **required_tests:** concurrent append, organization chain isolation, restart verification, tamper/delete/reorder, checkpoint recovery.
- **dependencies:** PostgreSQL persistence and lifecycle model; the chain scope and lock-order prerequisite is complete in ADR-0002.
- **target_release:** Durable Shadow Mode P0.1-P0.3, checkpoints later.
- **acceptance_criteria:** accepted events survive restart, chain verification is deterministic per declared scope, and deletion/reordering is detectable.

### GAP-PER-001 — Persistence

- **module:** Gateway state, Audit store, migrations/deploy
- **current_state:** `PARTIALLY_IMPLEMENTED`
- **evidence:** `atf-store`, embedded migrations, schema metadata checks, tenant constraints, canonical JSON/bytes/hash columns, append-only triggers, a concurrent per-organization Audit writer/verifier, atomic admission/finalization, persisted/replayed lifecycle, and DS-012 idempotency reservation/result plus evaluator fencing are implemented and wired. Evidence-gated reads reject canonical/hash/lifecycle/idempotency-result mismatches and Decisions lacking matching Evaluation/Audit evidence. DS-013 adds exact completed-response recovery and request-driven restrictive recovery for expired admissions. The Gateway has no Decision/Audit `Mutex` fallback; real tests prove restart/second-instance reads, changed-Policy exact retry, durable duplicate-purchase history, tenant-keyed lookup, unavailable-store readiness, concurrent single-result admission, renewal/reclaim, stale-owner rejection, finalizer race rejection, transaction rollback and completed-result tamper rejection. A crash after admission remains visibly `RECEIVED` until a retry reclaims it; no background scanner exists.
- **security_impact:** accepted final Decisions survive restart, instances converge, concurrent work is single-owner, stale completion is fenced and retry recovers stranded work without current-input re-evaluation; authenticated replay guarantees remain incomplete.
- **financial_impact:** final Decisions no longer disappear, duplicate concurrent evaluation is prevented, and a stranded admission reaches one explicit fail-closed terminal result when retried.
- **severity:** `CRITICAL`
- **recommended_change:** preserve the DS-012/DS-013 durable-only boundary while adding Identity/nonce protection, deterministic Context snapshots and operational recovery scanning.
- **required_tests:** migration, restart recovery, rollback, concurrent append/idempotency, database-unavailable fail-closed behavior.
- **dependencies:** transaction boundary, organization chain policy, base schema, Audit writer, repositories, Gateway cutover, DS-006/DS-007 lifecycle enforcement and DS-012/DS-013 idempotency/recovery are complete.
- **target_release:** Durable Shadow Mode P0.1.
- **acceptance_criteria:** service restart or second instance returns the same accepted Intent/Decision and preserves a valid Audit chain.

### GAP-SEC-001 — API Security

- **module:** `services/gateway`
- **current_state:** `PARTIALLY_IMPLEMENTED`
- **evidence:** DS-011 gives every response a fresh server-generated `X-ATF-Request-ID`; business, Router and Store failures use the exact `{code,message,request_id,details}` JSON envelope with fixed safe code/status/message mapping. Semantic details contain only server-owned code/field pairs, and Store/readiness warnings emit stable error codes instead of underlying database diagnostics. Contract tests cover UTF-8/JSON/Schema/common/Profile/header/not-found/conflict/404/405/database-unavailable paths and prove raw input/database text is absent. DS-018 adds bounded Bearer parsing, token/JWKS validation, durable RBAC, generic credential errors, non-enumerating resource reads and JWKS readiness. Health/readiness retain text bodies. General explicit header/body/timeout/rate configuration, full trace/Audit propagation and a captured-log redaction policy remain absent.
- **security_impact:** ambiguous/reflected/internal/credential error disclosure and anonymous Decision enumeration are reduced and failures are client-correlatable; resource exhaustion and incomplete incident traceability remain.
- **financial_impact:** availability loss remains possible; a client can now correlate one failed HTTP response with local Store/readiness logs, but not yet with full traces or durable Audit evidence for a disputed action.
- **severity:** `CRITICAL`
- **recommended_change:** retain the DS-011/DS-018 envelope and principal boundary while adding finite configurable limits, full trace/Audit propagation and captured-log redaction through DS-033/DS-034.
- **required_tests:** structured error and local request-ID tests are implemented; oversized/slow/rate-limited requests, timeout, cross-service correlation and captured-log redaction remain.
- **dependencies:** Authentication/Authorization and observability.
- **target_release:** Durable Shadow Mode before shared deployment.
- **acceptance_criteria:** every business request is bounded, attributable, scoped, safely logged, and returns a stable code.

### GAP-OBS-001 — Observability

- **module:** Gateway and all evaluators
- **current_state:** `PARTIALLY_IMPLEMENTED`
- **evidence:** DS-011 creates one server request ID per HTTP response and includes it with stable codes (not raw Store diagnostics) in Store/readiness failure logs. Tracing text initialization exists, but the ID is not yet propagated into general spans or Audit; no `/metrics`, counters, histograms, trace context, captured-log redaction test, or audit-write alert exists.
- **security_impact:** attacks, fail-closed spikes, and audit failures are hard to detect.
- **financial_impact:** latency/error regressions and abnormal transaction patterns remain invisible.
- **severity:** `MEDIUM`
- **recommended_change:** safe structured tracing plus Prometheus/OpenTelemetry metrics from PRD §25.
- **required_tests:** metric increments, labels without sensitive/high-cardinality data, trace correlation, audit-failure alert path.
- **dependencies:** request identity/correlation model.
- **target_release:** Durable Shadow Mode P0.10.
- **acceptance_criteria:** required counters/latencies/failures are observable without logging secrets or full financial payloads.

### GAP-CI-001 — CI and Supply-chain Security

- **module:** `.github/workflows`, `fuzz`, release pipeline
- **current_state:** `PARTIALLY_IMPLEMENTED`
- **evidence:** fmt/clippy/test jobs run; BL-001 restored cargo-deny 0.20.2 by
  exact-versioning path dependencies, reviewing the Cedar/JSON Schema
  transitive licenses, and pinning the official Action release commit. BL-002
  denies unreviewed duplicate versions, documents exact current exceptions,
  and promotes every cargo-deny warning to a CI error. cargo
  audit/nextest/fuzz, secret/SAST/container scanning, SBOM, signing, migration
  and Compose E2E are still absent.
- **security_impact:** vulnerable code, secrets, images, or artifacts can escape current gates.
- **financial_impact:** compromised dependencies/builds can alter financial control behavior.
- **severity:** `HIGH`
- **recommended_change:** add staged security/release jobs with pinned actions and generated attestations.
- **required_tests:** intentional gate-failure fixtures, fuzz smoke, migration E2E, artifact verification.
- **dependencies:** persistence/container packaging for later jobs.
- **target_release:** BL-001/BL-002 deny repair is complete; remaining
  dependency/secret/SAST gates land during Durable Shadow Mode.
- **acceptance_criteria:** every PR runs declared gates and every release has verifiable SBOM, checksum, and signature/attestation.

### GAP-DOC-001 — Documentation Consistency

- **module:** README, architecture, threat model, Schemas, missing specs
- **current_state:** `IMPLEMENTATION_DOCUMENTATION_DRIFT`
- **evidence:** pre-audit Threat Model said no Gateway/Audit/Risk; Audit Schema said no producer; required standalone specs and roadmap/changelog were absent.
- **security_impact:** operators may deploy based on mitigations that are only designed, not implemented.
- **financial_impact:** misunderstood guarantees can place real funds behind incomplete controls.
- **severity:** `MEDIUM`
- **recommended_change:** keep Status/Roadmap/Threat mitigations evidence-linked and add schema/API/example drift tests.
- **required_tests:** documentation examples, live route inventory, Schema producer validation, broken-link/status checks.
- **dependencies:** each feature owner updates docs in the same commit.
- **target_release:** ongoing; corrected per vertical feature.
- **acceptance_criteria:** no document claims a control is wired without an executable test/evidence path.

### GAP-PRD-001 — Production Readiness

- **module:** whole system/deploy/operations
- **current_state:** `DOCUMENTED_ONLY`
- **evidence:** no TLS/deployment, HA database, backups, migration/rollback, SLOs, runbooks, retention, tenant/auth boundary, or Enforce feature flag; execution is correctly absent.
- **security_impact:** current service is unsafe for internet-exposed multi-tenant or real-funds use.
- **financial_impact:** state loss, unauthorized access, and unrecoverable incidents are plausible if deployed beyond local evaluation.
- **severity:** `CRITICAL`
- **recommended_change:** keep explicit Shadow-only status; finish and re-audit Durable Shadow Mode before Mock/Enforce work, then add operational controls.
- **required_tests:** Compose E2E, restart/failover/backup restore, load/DoS, tenant isolation, incident and rollback drills.
- **dependencies:** all critical/high gaps above.
- **target_release:** production readiness is not claimed in the current roadmap.
- **acceptance_criteria:** production documentation names tested guarantees, residual risks, recovery procedures, and a default-disabled execution path.

## Next vertical feature

`DS-027` is next: use explicitly selected replacement Policy/Risk artifacts to
create separately identified, non-authoritative Counterfactual Evaluation/
Decision lineage without overwriting the original records.
