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
denial remain enabled; `cargo deny check` passes.

## Module inventory

| Module | State | Evidence |
|---|---|---|
| `atf-core` | `IMPLEMENTED_AND_WIRED` | Fixed-point `Amount`, timestamps, ULIDs, canonical JSON sorting, SHA-256; used throughout the workspace. |
| `atf-intent` | `PARTIALLY_IMPLEMENTED` | Schema parsing and canonical hash are wired; semantic/cross-field validation and action profiles are missing. |
| `atf-identity` | `IMPLEMENTED_BUT_UNWIRED` | In-memory Agent records and raw-hash Ed25519 verification exist; Gateway never calls them. |
| `atf-policy` | `PARTIALLY_IMPLEMENTED` | Cedar evaluation is wired; bundle manifest/version/hash/signature/scope and Cedar schema validation are missing. |
| `atf-risk` | `PARTIALLY_IMPLEMENTED` | Five stateless rules and one history rule are wired; trusted context, versioning, deterministic time, and most PRD rules are missing. |
| `atf-audit` | `PARTIALLY_IMPLEMENTED` | In-memory append-only hash chain and `DecisionRecorded` are wired; persistence, queries, checkpoints, and full lifecycle are missing. |
| `atf-decision` | `PARTIALLY_IMPLEMENTED` | Policy/Risk merge is wired; Simulator input and strong Decision binding fields are missing. |
| `atf-cli` | `PARTIALLY_IMPLEMENTED` | `validate-intent`, `evaluate`, and `policy test` exist; most PRD §21 commands are missing. |
| `services/gateway` | `PARTIALLY_IMPLEMENTED` | Four live routes and Policy/Risk/Decision/Audit wiring exist; identity, persistence, idempotency, auth, metrics, and query APIs are missing. |
| Simulator, Approval, Reconciliation, Adapter crates | `SCAFFOLD_ONLY` | Each contains only a README and is not a workspace member. |
| Policy/Audit/Approval/Reconciliation services | `SCAFFOLD_ONLY` | Each contains only a README and is not runnable. |
| `conformance/policy-tests` | `IMPLEMENTED_AND_WIRED` | Three cases run through `atf policy test`. |
| Adapter/replay conformance, fuzz, migrations, deploy | `SCAFFOLD_ONLY` | README placeholders only. |
| SDKs and most target documentation | `MISSING` | No implementation; `intent-spec.md`, `policy-model.md`, `audit-model.md`, quickstart, SDKs, and adapter manifest Schema are absent. |
| README/Architecture/Threat Model | `IMPLEMENTATION_DOCUMENTATION_DRIFT` | Several stale claims were corrected in this change; ongoing schema/API/status checks are still needed. |

## Gap matrix

### GAP-INT-001 — Intent Schema Validation

- **module:** `atf-intent`, `schemas/transaction-intent.schema.json`
- **current_state:** `PARTIALLY_IMPLEMENTED`
- **evidence:** top-level `additionalProperties` is `true`; Serde ignores unknown envelope fields, so an unrecognized field can validate and then disappear from the typed canonical hash.
- **security_impact:** callers can believe an extension is integrity-bound when ATF silently drops it.
- **financial_impact:** an amount qualifier, fee asset, or destination constraint in an unknown field could be omitted from the evaluated request.
- **severity:** `HIGH`
- **recommended_change:** close the core envelope, add versioned extension namespaces, and add per-action profile Schemas.
- **required_tests:** unknown-core-field rejection, context/metadata hash sensitivity, Schema/Rust round-trip, profile compatibility.
- **dependencies:** semantic version policy and profile design.
- **target_release:** Durable Shadow Mode, immediately after persistence semantics are fixed.
- **acceptance_criteria:** no unvalidated core field is silently ignored; every accepted field affecting intent meaning is present in the canonical hash.

### GAP-INT-002 — Cross-field Semantic Validation

- **module:** `atf-intent`
- **current_state:** `MISSING`
- **evidence:** `validate` performs JSON Schema validation then deserializes; it does not reject non-positive amount/leverage, negative fee, invalid slippage, reversed times, invalid ULID, whitespace IDs, unsupported versions, or incomplete action-specific fields.
- **security_impact:** malformed financial intents reach Policy and may receive `PERMIT`.
- **financial_impact:** negative/zero values and incomplete operations can bypass threshold logic or be interpreted differently by downstream systems.
- **severity:** `HIGH`
- **recommended_change:** add a Rust semantic validator with stable machine-readable codes and versioned action profiles.
- **required_tests:** table/boundary/property tests for every invariant; Gateway and CLI fail-closed tests.
- **dependencies:** final field shapes for approval, exchange, and prediction-market profiles.
- **target_release:** Durable Shadow Mode P0.
- **acceptance_criteria:** invalid cross-field combinations never reach Policy/Risk and return stable structured error codes.

### GAP-IDN-001 — Agent Identity Verification

- **module:** `atf-identity`, `services/gateway`
- **current_state:** `IMPLEMENTED_BUT_UNWIRED`
- **evidence:** Gateway has no identity dependency or signature header; registry signs only the hex Intent hash and does not enforce organization match, key ID, key validity windows, audience, environment, nonce, or envelope expiry.
- **security_impact:** any network caller can impersonate any Agent; signatures are replayable across contexts.
- **financial_impact:** policies and histories can be evaluated under a victim Agent identity.
- **severity:** `HIGH`
- **recommended_change:** persist Agent/key records and verify a domain-separated signed envelope before Policy/Risk.
- **required_tests:** wrong-org, wrong-audience/environment, stale envelope, nonce replay, key overlap/revocation, paused/revoked Agent, and audit tests.
- **dependencies:** PostgreSQL, Admin provisioning/RBAC, idempotency nonce store.
- **target_release:** Durable Shadow Mode P0.5.
- **acceptance_criteria:** identity failure records `IdentityRejected`, returns fail-closed, and Policy/Risk are not called.

### GAP-API-001 — Authentication and Authorization

- **module:** `services/gateway`
- **current_state:** `MISSING`
- **evidence:** all routes are anonymous; `GET /v1/intents/{id}/decision` has no organization scope or RBAC.
- **security_impact:** decision data can be enumerated or submitted under arbitrary tenant identifiers.
- **financial_impact:** attackers can pollute risk history and expose transaction decisions.
- **severity:** `CRITICAL`
- **recommended_change:** separate Agent auth from Admin/auditor auth, enforce organization isolation and least-privilege RBAC.
- **required_tests:** cross-tenant denial, role matrix, invalid/expired credential, confused-deputy tests.
- **dependencies:** identity envelope, Admin auth model, persistence.
- **target_release:** Durable Shadow Mode before any shared deployment.
- **acceptance_criteria:** every non-health route authenticates and authorizes an organization-scoped principal.

### GAP-RPL-001 — Idempotency and Replay Protection

- **module:** Gateway persistence and identity envelopes
- **current_state:** `MISSING`
- **evidence:** `idempotency_key` is stored only in an in-memory event payload; there is no uniqueness constraint, conflict response, nonce, or concurrency guard.
- **security_impact:** duplicate and concurrent requests are re-evaluated; signed requests can be replayed.
- **financial_impact:** repeated payment authorization and inconsistent decisions after policy/history changes.
- **severity:** `CRITICAL`
- **recommended_change:** unique `(organization_id,idempotency_key)` reservation with stored Intent hash/Decision and single-use nonce tables.
- **required_tests:** same-key/same-hash return, same-key/different-hash 409, concurrent race, restart recovery, replay audit.
- **dependencies:** PostgreSQL transaction boundary and Identity envelope.
- **target_release:** Durable Shadow Mode P0.4.
- **acceptance_criteria:** exactly one evaluator wins; duplicates return the original Decision and conflicts return `IDEMPOTENCY_CONFLICT` durably.

### GAP-POL-001 — Policy Bundle Validation

- **module:** `atf-policy`
- **current_state:** `PARTIALLY_IMPLEMENTED`
- **evidence:** files are concatenated and parsed as `PolicySet`; there is no Cedar Schema, manifest, version/hash/signature, organization/environment scope, expiry, rollback, or multi-bundle resolution.
- **security_impact:** stale, malformed-scope, or unauthorized policy bundles can be loaded without provenance.
- **financial_impact:** transactions may be evaluated under the wrong organization or policy version.
- **severity:** `HIGH`
- **recommended_change:** signed manifest plus Cedar Schema validation, immutable bundle hash/version, activation/rollback, and change audit.
- **required_tests:** bad signature/schema/scope/version/expiry, conflict, rollback, deterministic bundle hash.
- **dependencies:** Admin RBAC, persistence, canonical hashing.
- **target_release:** Durable Shadow Mode P0.9.
- **acceptance_criteria:** bundle load failures are fail-closed and every Decision/Audit event names the exact validated bundle hash/version.

### GAP-RSK-001 — Financial Risk Validation

- **module:** `atf-risk`
- **current_state:** `PARTIALLY_IMPLEMENTED`
- **evidence:** five stateless rules and permitted-decision duplicate purchase exist; most PRD §12 rules, rule-set version/hash, missing-data handling, and action-specific rules do not.
- **security_impact:** common split-order, allowance, withdrawal, leverage, concentration, and velocity threats are unchecked.
- **financial_impact:** budget, market, protocol, and execution-risk losses are not bounded.
- **severity:** `HIGH`
- **recommended_change:** implement versioned deterministic rules only after trusted context and lifecycle accounting boundaries exist.
- **required_tests:** independent unit/boundary/missing-data/property tests per rule and fail-closed integration tests.
- **dependencies:** EvaluationContext, provenance, persistence, lifecycle state.
- **target_release:** Durable Shadow Mode and reference scenarios incrementally.
- **acceptance_criteria:** each enabled rule has a stable code, recorded inputs/version, deterministic result, and explicit missing-data outcome.

### GAP-CTX-001 — Context Provenance and Freshness

- **module:** `atf-intent`, `atf-risk`, future enrichers
- **current_state:** `MISSING`
- **evidence:** arbitrary Agent-provided `context.historical_vendor_median` directly affects `VENDOR_PRICE_DEVIATION`; no source, observation time, expiry, evidence hash, or confidence exists.
- **security_impact:** the requester controls data used to judge its own risk.
- **financial_impact:** manipulated price/account/protocol context can suppress review or create false alerts.
- **severity:** `HIGH`
- **recommended_change:** typed provenance envelopes and trusted enrichment; reject Agent-provided privileged fields from decision context.
- **required_tests:** source allowlist, stale/missing evidence, hash/signature mismatch, Agent override rejection.
- **dependencies:** EvaluationContext and persistent context snapshots.
- **target_release:** Durable Shadow Mode P0.8.
- **acceptance_criteria:** every decision-affecting external value has recorded provenance/freshness and untrusted sources cannot overwrite it.

### GAP-RPY-001 — Deterministic Replay

- **module:** Core evaluation pipeline and replay conformance
- **current_state:** `MISSING`
- **evidence:** Risk and history rules call `Timestamp::now()`; policy/risk versions and context snapshots are not recorded; replay conformance is a README only.
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
- **current_state:** `PARTIALLY_IMPLEMENTED`
- **evidence:** `Decision` contains only ID, Intent ID, kind, and reasons; Gateway Audit now records Intent hash externally, but Decision lacks policy/risk/context/simulation hashes, evaluation time, expiry, constraints, and decision hash.
- **security_impact:** a Decision object alone cannot prove exactly which request and evaluator inputs it authorizes.
- **financial_impact:** stale or mismatched Decisions may be reused by future execution code.
- **severity:** `HIGH`
- **recommended_change:** add the complete binding envelope and canonical Decision hash.
- **required_tests:** mutation sensitivity, Schema compatibility, expiry, version/hash mismatch, deterministic hash.
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
- **evidence:** append-only API, hash chain, tamper test, and `DecisionRecorded` exist; chain is process-local/global, event payloads are mostly untyped, and no checkpoint/query/retention controls exist.
- **security_impact:** restart, privileged process memory, or database design mistakes can erase or fork evidence.
- **financial_impact:** transaction authorization history may be incomplete or unverifiable.
- **severity:** `HIGH`
- **recommended_change:** per-organization transactional chains, typed lifecycle payloads, query indexes, verification jobs, and external Merkle checkpoints.
- **required_tests:** concurrent append, organization chain isolation, restart verification, tamper/delete/reorder, checkpoint recovery.
- **dependencies:** PostgreSQL persistence and lifecycle model.
- **target_release:** Durable Shadow Mode P0.1-P0.3, checkpoints later.
- **acceptance_criteria:** accepted events survive restart, chain verification is deterministic per declared scope, and deletion/reordering is detectable.

### GAP-PER-001 — Persistence

- **module:** Gateway state, Audit store, migrations/deploy
- **current_state:** `MISSING`
- **evidence:** `Mutex<AuditLedger>` and `Mutex<HashMap<...Decision>>`; `migrations/` contains only a README.
- **security_impact:** restart erases accepted requests and anti-replay/history state; multiple instances diverge.
- **financial_impact:** Decisions disappear, duplicate/budget controls reset, and recovery is impossible.
- **severity:** `CRITICAL`
- **recommended_change:** PostgreSQL migrations and a transactional repository for Intent, evaluation, Decision, and Audit append.
- **required_tests:** migration, restart recovery, rollback, concurrent append/idempotency, database-unavailable fail-closed behavior.
- **dependencies:** lifecycle transaction boundary and organization chain policy.
- **target_release:** Durable Shadow Mode P0.1 (next vertical feature).
- **acceptance_criteria:** service restart or second instance returns the same accepted Intent/Decision and preserves a valid Audit chain.

### GAP-SEC-001 — API Security

- **module:** `services/gateway`
- **current_state:** `PARTIALLY_IMPLEMENTED`
- **evidence:** health/readiness and two business routes exist; no body limit, timeout, rate limit, correlation/trace ID, structured code, safe logging policy, or versioned response envelope.
- **security_impact:** memory/CPU abuse, enumeration, ambiguous errors, and weak incident traceability.
- **financial_impact:** availability loss and inability to correlate disputed financial actions.
- **severity:** `CRITICAL`
- **recommended_change:** Tower/Axum security middleware and a uniform typed error/response contract after auth/persistence boundaries are set.
- **required_tests:** oversized/slow/rate-limited requests, timeout, correlation propagation, log redaction, structured errors.
- **dependencies:** Authentication/Authorization and observability.
- **target_release:** Durable Shadow Mode before shared deployment.
- **acceptance_criteria:** every business request is bounded, attributable, scoped, safely logged, and returns a stable code.

### GAP-OBS-001 — Observability

- **module:** Gateway and all evaluators
- **current_state:** `MISSING`
- **evidence:** tracing text initialization exists; no `/metrics`, structured spans, counters, histograms, trace IDs, or audit-write alerts.
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
  transitive licenses, and pinning the official Action release commit. cargo
  audit/nextest/fuzz, secret/SAST/container scanning, SBOM, signing, migration
  and Compose E2E are still absent.
- **security_impact:** vulnerable code, secrets, images, or artifacts can escape current gates.
- **financial_impact:** compromised dependencies/builds can alter financial control behavior.
- **severity:** `HIGH`
- **recommended_change:** add staged security/release jobs with pinned actions and generated attestations.
- **required_tests:** intentional gate-failure fixtures, fuzz smoke, migration E2E, artifact verification.
- **dependencies:** persistence/container packaging for later jobs.
- **target_release:** BL-001 deny repair is complete; remaining
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

P0.1 PostgreSQL persistence is next: define the lifecycle transaction
boundary, add migrations, persist accepted Intents/Decisions/Audit events,
and prove restart plus concurrent append behavior. Identity, idempotency,
replay, and budget work must build on that durable boundary rather than add
more process-local state.
