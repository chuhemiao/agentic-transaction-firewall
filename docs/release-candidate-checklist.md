# Durable Shadow Release Candidate Checklist

- Review date: 2026-08-09
- Audit input commit: `a0cc1a6`; ADR-0004 remediation: current DS-040 closure change
- Scope: source and the supported single-host local Durable Shadow topology
- Execution authority: absent
- Production readiness: not claimed

GitHub coordination check: the repository had no open Issue or Pull Request at
the review time, so there was no external fix or review state to merge into
this candidate.

## Verdict

**C4 TECHNICAL CONTROLS: PASS; CHECKPOINT: BLOCKED.** DS-040 and the accepted
ADR-0004 remediation now satisfy the current-scope executable criteria. This
does not authorize C4, RA-001, a tagged release, an internet-exposed
deployment, or any real-funds path until the independent sign-off below.

Blocking conditions:

1. `C4-SIGNOFF-001`: the independent human security reviewer required by
   DS-040 and Checkpoint C4 has not approved this candidate.

`C4-GAP-001` is closed. [ADR-0004](decisions/0004-authenticated-operations-metrics.md)
is accepted and implemented as a separate mTLS-authenticated Operations
Principal, TLS listener and Unix-socket-only Metrics Router. The typed
principal has only `METRICS_READ`, is independent of PostgreSQL/JWKS per
scrape, and is structurally absent from business routes. Live evidence rejects
missing, wrong-CA, expired, future, wrong-EKU and unapproved identities,
preserves authorized Metrics during database loss and rotates the local trust
pool without an anonymous interval.

## PRD §32.1 functional evidence

| ID | Result | Executable evidence |
|---|---|---|
| 32.1.1 | PASS | `services/gateway/tests/routes.rs`: Schema, semantic and unsupported-Profile rejection tests prove zero durable admission before Policy/Risk; `crates/atf-intent/tests/semantic.rs` locks stable codes. |
| 32.1.2 | PASS | `services/gateway/tests/identity.rs` covers unsigned, invalid, scope/time and restarted Nonce rejection; `crates/atf-store/tests/nonce.rs` covers atomic consumption and concurrent replay. |
| 32.1.3 | PASS | `crates/atf-store/tests/repository.rs`, `services/gateway/tests/postgres_routes.rs` and `services/gateway/tests/multi_instance.rs` cover atomic finalization, restart and a second instance. |
| 32.1.4 | PASS | Gateway `completed_same_hash_retry...`, `concurrent_same_hash_posts...` and Store idempotency tests cover original result, conflict, one evaluator and fencing. |
| 32.1.5 | PASS | `crates/atf-decision/tests/binding.rs`, `properties.rs` and `schema_validation.rs` bind every current Decision input, including explicit Simulation `NOT_RUN`, time and expiry. |
| 32.1.6 | PASS | `scripts/test-conformance.sh`, `crates/atf-store/tests/replay.rs` and the fixed vectors prove exact Original Replay and isolated non-authoritative Counterfactual lineage. |
| 32.1.7 | PASS | `crates/atf-risk/tests/provenance.rs`, daily-spend tests and Gateway trusted-context tests prove Agent context cannot supply privileged evidence and missing evidence is restrictive. |
| 32.1.8 | PASS | `services/gateway/tests/audit_query.rs` and `crates/atf-store/tests/audit_postgres.rs` cover all declared filters, tenant authorization, stable pages and restart/tamper chain verification. |
| 32.1.9 | PASS | `services/gateway/tests/telemetry.rs` covers the fixed-label metrics, durable Replay counts, correlation and captured credential/signature/payload redaction contract. |
| 32.1.10 | PASS | Router inventory has no Approval, execution or Adapter route; unsupported Profiles fail before admission; README/PRD/operations docs remain Shadow-only and non-production. |

## PRD §32.2 security evidence

| ID | Result | Executable evidence or blocker |
|---|---|---|
| 32.2.1 | PASS | Fresh Gitleaks history/current-tree scan passed; first-party Rust has no `f32`/`f64` or `unsafe`; `Amount` serialization/property tests require lossless JSON strings; the core has no LLM dependency. |
| 32.2.2 | PASS | Body/Header limits, timeouts, source/principal rates, stable errors and business-route Agent/Operator RBAC are tested in `security_limits.rs`, route tests and `audit_query.rs`. `operations_metrics.rs` proves the isolated closed assertion, typed `METRICS_READ` principal, route/method matrix and bounds; the clean Compose drill proves the mTLS/UDS boundary and business/direct-port isolation. |
| 32.2.3 | PASS | Policy Bundle, Risk Rule Set, Evaluation Context and Evidence canonical hash/version/tamper/freshness tests pass; dependency-failure tests prove unavailable or corrupt state cannot return a new Permit. |
| 32.2.4 | PASS | `scripts/test-persistence.sh` ran twice against PostgreSQL 17.10; restart, two-instance, lock timeout, real deadlock, Audit append and Decision/Nonce convergence passed. |
| 32.2.5 | PASS | fmt, Clippy/SAST, workspace tests, deny, dependency/Secret/SAST, persistence, Replay/conformance, pinned 15-second Fuzz and clean Compose operations passed. |
| 32.2.6 | PASS_WITH_SIGNOFF | The CRITICAL/HIGH disposition below is evidence-linked. No technical current-scope contradiction remains; independent human sign-off is still mandatory and future-phase/production gaps are not relabeled closed. |

## CRITICAL/HIGH gap disposition

| Gap | Severity | C4 disposition |
|---|---|---|
| GAP-INT-001/002 | HIGH | Current supported Payment Profile meets the Shadow acceptance tests; every other Profile fails closed. Broader profile coverage remains a Phase 3 gap. |
| GAP-RSK-001 | HIGH | The configured Rule Set and its eight current rules are versioned, bounded and executable. Missing future financial rules forbid broader profile/production claims. |
| GAP-CTX-001 | HIGH | Closed Context/Evidence contracts meet current acceptance; production enrichers remain absent and missing data stays restrictive. |
| GAP-BUD-001 | CRITICAL | Phase 4 blocker. No Budget reservation or execution authority exists; current Shadow decisions must not be used as spend authorization. |
| GAP-SIM-001 | HIGH | Phase 3 blocker for the affected Profiles. Current Payment Decision explicitly binds `NOT_RUN`; no execution follows it. |
| GAP-APR-001 | HIGH | Phase 4 blocker. No Approval or execution route exists. |
| GAP-EXE-001 | CRITICAL | Phase 4/production blocker. Absence of an execution route is a current C4 safety property, not a completed execution control. |
| GAP-ADP-001 | HIGH | Phase 3 blocker. Adapter crates and conformance remain scaffolded and cannot move funds. |
| GAP-REC-001 | HIGH | Phase 4 blocker. No settlement is initiated, so reconciliation is not claimed. |
| GAP-AUD-001 | HIGH | Current restart/query/tamper acceptance is met. Independent checkpoints, retention and sublinear verification remain production availability/integrity work. |
| GAP-PER-001 | CRITICAL | Current restart/second-instance/local backup-restore acceptance is met. Background scanner, HA/failover and production RPO/RTO remain production blockers. |
| GAP-CI-001 | HIGH | Source/PR security gates pass; the supported local operations gate is manual. Container scan, SBOM, provenance and signing are required before distributing release artifacts. |
| GAP-PRD-001 | CRITICAL | Explicit production blocker. C4 reviews local Durable Shadow only and cannot close production readiness. |

## STRIDE review of the current route surface

| Threat | Result and residual |
|---|---|
| Spoofing | Agent envelopes bind exact tenant/key/nonce/audience/environment; Operator RFC 9068 JWTs map to current durable roles. Metrics requires the dedicated mTLS chain and approved SPKI before the UDS Router forms `OperationsPrincipal(METRICS_READ)`. |
| Tampering | Canonical hashes, signed Policy, immutable Context/Decision rows and the append-only Audit chain reject changed bytes, row rebinding and reordered evidence. |
| Repudiation | Typed durable events bind admission, identity, module results, Decision and administrative mutations. Independent off-database checkpoints are still absent. |
| Information disclosure | Stable errors, non-enumerating reads, fixed telemetry labels and captured canaries pass. Aggregate metrics expose no tenant IDs/payloads and are available only through the authenticated operations listener. |
| Denial of service | Finite body/Header/time/rate bounds, bounded history queries and dependency timeouts exist. Rates are process-local and full-chain Audit verification remains O(chain). |
| Elevation of privilege | Agent, Operator and Operations principals are disjoint; selectors/token claims/assertion Headers grant no cross-surface role. The Operations capability is structurally limited to `METRICS_READ`; no Approval/execution privilege exists. |

## Verification record

Commands are run from the repository root on 2026-08-09. PostgreSQL-dependent
workspace tests require `ATF_TEST_DATABASE_URL`; running them without it fails
closed instead of silently skipping two real CLI/database tests.

| Gate | Result |
|---|---|
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --all-targets --all-features -- -D warnings` | PASS |
| `ATF_TEST_DATABASE_URL=... cargo test --workspace --all-targets --all-features` | PASS |
| `cargo deny check -D warnings` | PASS |
| `ATF_PERSISTENCE_TEST_REPETITIONS=2 ./scripts/test-persistence.sh` | PASS |
| `./scripts/test-conformance.sh` | PASS |
| `./scripts/test-security.sh` with a fresh RustSec database | PASS: 1197 advisories loaded; root/fuzz locks, 60-commit/current-tree Gitleaks and negative fixtures passed |
| `./scripts/test-rust-sast.sh` | PASS: full workspace clean and unsafe fixture rejected |
| `./scripts/test-fuzz.sh` | PASS: pinned `nightly-2026-08-01` / `cargo-fuzz 0.13.2`; 731,672 executions, 5,208 new units, zero crash, 623 MiB peak RSS |
| clean `./scripts/test-local-ops.sh` | PASS: empty-volume provision; mTLS/UDS Metrics isolation, six invalid-identity cases, database-outage scrape and PKI rotation; signed submit/restart/Replay; backup/isolated restore with equal sequence 17 / hash `23e0e4d812bfc876bb44993a194cb24f17b74070ec6d9c4b6e005d0169af61d0` and `1:1:1:17` counts; signed Policy rollback/forward; 50/50 load with P95 111 ms and 52.742 evaluations/s |

## Five-axis release assessment

- Functional completeness: PASS for the single advertised Durable Shadow
  Payment evaluation path; no other Profile or execution capability is
  implied.
- Security: PASS for the current Durable Shadow technical scope after
  `C4-GAP-001`; production edge, KMS and artifact controls remain explicitly
  outside this candidate.
- Reliability: PASS for tested single-database restart, second-instance,
  contention and local backup/restore; HA and production RPO/RTO are absent.
- Observability: PASS for safe current-component telemetry and its authenticated,
  database-independent scrape path.
- Release readiness: BLOCKED until an independent human reviewer signs.

PRD §32.4 documentation residual: current Intent, Identity, Policy, Audit,
API, operations and quickstart documents exist, but a standalone Replay
specification and the future Adapter manifest specification do not. This does
not widen current authority, but must close before claiming the third-party
implementation documentation gate.

## Rollback and sign-off

The remediation changes the Gateway routing/server boundary and the supported
local edge/PKI topology but no database schema. Roll back as one vertical slice;
never restore the anonymous business `/metrics` route as a compatibility
fallback. Runtime restore, certificate rotation and signed Policy rollback
procedures remain in `docs/quickstart.md` and `docs/operations.md`.

- Technical review author: Codex, evidence collector; **not independent**
- Independent human security reviewer: **PENDING**
- Human decision: **PENDING — C4 NOT APPROVED**
