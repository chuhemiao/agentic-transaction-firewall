# Threat Model

This model covers the threats enumerated in `docs/PRD.md` §18.2, annotated
against the current Phase 2 Shadow Mode implementation. The gateway has a
real network request path, but no execution path or production secret.
DS-040 revalidated it on 2026-08-09 against input commit `a0cc1a6` and the
accepted ADR-0004 remediation closes the discovered Metrics access gap. C4
remains blocked only for independent human sign-off as documented in
`docs/release-candidate-checklist.md`.

## Security principles (PRD §18.1)

1. Fail Closed — any indeterminate error denies, never permits.
2. Least privilege.
3. Agents are isolated from signing authority.
4. Policy and Risk decisions are replayable.
5. Intent and execution request are strongly bound.
6. All external input is untrusted.
7. Every Adapter is independently sandboxed.
8. The core kernel never depends on an LLM for Permit/Deny.
9. Secrets are never written to logs.
10. Production keys never enter the ATF core process.

## Threat catalog (PRD §18.2)

| # | Threat | Status in this repo |
|---|---|---|
| 1 | Prompt injection causing an Agent to overstep authorization | Partially constrained on the Shadow Gateway path by authenticated Agent identity, common semantics, a closed Profile dispatcher, mandatory Policy/Risk evaluation, and no LLM in Permit/Deny. Only the Agent-Commerce Payment profile is supported and execution enforcement remains absent |
| 2 | Agent tool-call parameters tampered with | Addressed at current Shadow admission: `atf-intent` supplies a tamper-evident canonical hash; DS-014's `ATF_INTENT_V1` Envelope binds that hash plus organization, Agent, exact Key ID, time, Nonce, audience and environment under strict Ed25519; DS-015 persists exact public-key lifecycle; DS-016 requires and reverifies that proof before Policy/Risk |
| 3 | Intent and final transaction diverge | Partially addressed: DS-025's closed Decision v1 binds the exact Intent hash, Profile, artifacts, Context/snapshot, Simulation state, time/expiry and execution constraints under a canonical hash. No execution path or execution-request hash binding exists yet, so Phase 4 must enforce these constraints rather than merely record them |
| 4 | Policy bypass | The Gateway has one Agent-authenticated Policy-first evaluation path and no execution route. DS-019 rejects unmanifested, mis-scoped, inactive, hash/digest-mismatched or Cedar-Schema-invalid Bundles. DS-020 additionally requires strict detached publisher proof, immutable durable installation and an audited active pointer reloaded per request; Policy mutation requires current `policy_author`/`org_admin`. Multi-Bundle conflict resolution and production edge controls remain absent, so this is not yet a deployable enforcement boundary |
| 5 | Approval replay | Not applicable yet — no Approval Engine (Phase 4) |
| 6 | Payment proof replay | Not applicable yet — no Adapter (Phase 3) |
| 7 | Nonce replay | Mitigated for Gateway Agent admission: DS-016 atomically stores an organization/Agent-scoped Nonce hash bound to the exact Key, Envelope, Intent and idempotency tuple. Exact retry adds nothing; fresh valid retry consumes a new Nonce; conflicting concurrent or post-restart reuse emits `ReplayDetected` and fails 409. Raw Nonces/signatures are not stored and privileged row tampering is detected on verified reads |
| 8 | TOCTOU between decision and execution | Addressed by design via execution-hash binding (Phase 4); not applicable while there is no execution path |
| 9 | Malicious Adapter | Addressed by design via Adapter isolation + Conformance Tests (Phase 3); no Adapter exists yet |
| 10 | Supply-chain dependency attack | Partially addressed: pinned cargo-deny 0.20.2 checks all features/targets and DS-038 adds exact cargo-audit/Gitleaks plus pinned Clippy SAST on every PR. Both locks, complete Git history/current source and first-party unsafe code fail closed; negative fixtures prove each path. Advisory/fingerprint exceptions are exact, code-owned, reachability-checked where applicable and expire within 90 days. DS-039 digest-pins every supported local external base and builds locked source, but container scanning/SBOM/provenance/artifact signing remain future release controls |
| 11 | Admin privilege abuse | DS-018 implements ADR-0003's disjoint Agent/Operator principals and PostgreSQL-authoritative explicit roles. DS-020's first Admin routes authenticate RFC 9068 JWTs and transactionally recheck `policy_author`/`org_admin` for non-enumerating Policy activation/rollback. Other Admin capabilities and high-risk multi-party controls remain absent |
| 12 | Audit log deletion | Partially addressed: migration 0001 rejects Audit UPDATE/DELETE/TRUNCATE, DS-003 row-locks per-organization append and restart-verifies canonical bytes/hash/order/head, DS-004/DS-005 make atomic durable evidence authoritative, DS-007 binds Intent lifecycle state/version/event pointers, DS-015 applies the same rule to Agent/Key lifecycle, DS-016 binds Nonce rows to verified Audit/lifecycle evidence, and DS-018 binds Operator/Role lifecycle to typed events. DS-032 exposes only pages from a complete reverified declared-organization chain and fails closed on deletion, mutation, reorder or head mismatch. Independent checkpoints, retention, and privileged-database threat controls remain later work |
| 13 | Price oracle manipulation | Partially mitigated: DS-022 stops reading Agent `historical_vendor_median`, accepts only fresh/hash-verified/allowlisted/exact-scope `ATF_ENRICHED` evidence, and turns stale/tampered/unsigned/ambiguous or Agent-provided inputs into explicit restrictive findings. DS-023 durably binds the exact verified Evidence and trust-policy identity before evaluation; DS-024 makes Risk consume only that closed Context. DS-029 applies the same authority to direct asset quotes: a missing, ambiguous, wrong-scope or inexact quote produces a High/Critical finding and cannot convert daily spend. Production enrichers remain future work |
| 14 | Exchange API key leakage | Not applicable yet — no Adapter holds any credential in this repo |
| 15 | Unlimited token approval | Fail closed at admission: Token Approval has no implemented Profile and returns `UNSUPPORTED_INTENT_PROFILE`. A safe spender/allowance model and unlimited-approval rule still do not exist |
| 16 | Malicious contract call | Fail closed at admission: Contract Call has no implemented Profile, and the Payment profile forbids contract/calldata fields. Simulator-backed Contract Call semantics remain Phase 3 work |
| 17 | Payment settled but service not delivered | Not applicable yet — no Reconciliation (Phase 4) |
| 18 | Duplicate purchase | Partially mitigated: DS-028 uses an indexed, repeatable-read, organization/Agent/resource/time/sequence-bounded query over prior `DecisionRecorded(PERMIT)` evidence, records its exact inputs/result, and reproduces it across restart, instances and Replay. DS-030 similarly detects organization-wide first-time Payment destinations through a versioned EIP-155 normalizer |
| 19 | Multi-agent collusion to bypass budget | Not applicable yet — Budget model is specced (PRD §9.4) but not implemented |
| 20 | High-frequency small-order splitting to bypass per-transaction limits | Partially mitigated for one Agent in the current Payment profile: DS-029 sums the current Intent plus prior same-organization/Agent `DecisionRecorded(PERMIT)` amounts, while DS-031 counts accepted `IntentReceived` events over exact organization/Agent/Profile/action scope at a `REQUESTED` boundary. The inclusive window and threshold are Rule-Set-bound; concurrent accepted requests cannot all pass a limit of one, completed retries do not inflate the count, and unresolved legacy scope is restrictive. There is no organization-wide budget or colluding-Agent aggregation, so EN-001/EN-002 remain open |
| 21 | Destination aliasing or first-use evasion | Partially mitigated for Payment EIP-155 destinations: DS-030 leaves signed CAIP-10 bytes unchanged but derives a versioned lowercase key from legacy lowercase or valid EIP-55 checksum case. Store scopes familiarity to one organization and exact Profile/normalizer, accepts only prior verified `DecisionRecorded(PERMIT)` evidence, and re-verifies the selected Decision/Intent binding. Invalid checksum, unsupported namespace, prior DENY and cross-tenant history are restrictive or ignored as appropriate. Other namespaces and ownership/allowlist intelligence remain future Profile/Adapter work |

## What this repo's current attack surface actually is

There is a network service but no Adapter, execution route, or production
secret. The realistic attack surface today includes:

- **Disjoint Agent writes and Operator reads.** POST
  requires a canonical signed Envelope and current durable exact Key, with
  atomic hashed-Nonce consumption before Policy/Risk. GET requires a
  Gateway-validated configured-issuer JWT and a current durable
  `auditor`/`org_admin` role for its organization selector. This protects both
  Decision reads and DS-032 Audit reads. DS-018 ignores
  token role/organization claims, makes current local disable/revoke immediate,
  rejects credential type confusion and prevents cross-tenant/wrong-role
  resource enumeration. A caller with the exact valid Agent proof can still
  trigger that request's post-expiry fail-closed recovery; this cannot produce
  Permit but can terminate the Intent as ERROR. DS-034 now bounds application
  body/Header/count, total request and evaluator cost, then rate-limits direct
  socket sources and verified domain-hashed Agent/Operator principals. The
  isolated Metrics Router adds a separately domain-hashed Operations
  principal and never accepts it on business routes. A forged
  Agent proof cannot consume another Agent's quota. DS-039's supported local
  topology supplies loopback TLS and direct-port isolation, but a shared
  deployment still requires production ingress TLS, firewalling, shared quota
  and parser/handshake limits, so the Gateway is not production-ready on an
  untrusted network.

- **Observability exfiltration and cardinality exhaustion.** DS-033 maps HTTP
  requests only to closed route templates/method/status classes and maps
  financial results only to closed outcome/severity enums. Organization,
  Agent, Operator, Intent, Decision, request and replay IDs never become metric
  labels; raw paths/query strings, error text, Policy/Rule IDs, credentials,
  identity envelopes, Nonces, signatures and payloads are not recorded.
  Captured canaries prove these exclusions. JSON spans retain the server
  Request ID and allowlisted Audit event IDs only for incident correlation;
  PostgreSQL Audit remains authoritative. Replay counts are aggregated from
  typed durable events without tenant labels. Accepted ADR-0004 removes
  `/metrics` from the business Router, exposes a metrics-only Router through a
  protected Unix socket and requires a dedicated mTLS client chain plus exact
  approved public key at a separate loopback operations listener. The edge
  overwrites the only accepted assertion Headers; Gateway converts the
  canonical DER SPKI into `OperationsPrincipal(METRICS_READ)` and strips the
  assertion before the handler. Missing, wrong-CA, expired, future,
  wrong-EKU and unapproved identities fail live tests; business credentials or
  forged Headers do not form this principal. PostgreSQL/JWKS outages do not
  disable authentication or the bounded process metrics.

- **Malformed/adversarial JSON input** to `atf-intent::validate` and
  `atf-cli` — DS-008 closes core objects in both JSON Schema and direct Rust
  parsing, rejects unsupported Intent versions, and retains arbitrary data
  only in object-valued hash-bound `context`/`metadata`. DS-009 rejects common
  financial/time/ULID/text violations with stable ordered codes before durable
  admission and Policy/Risk; it does not trim, truncate, round, or downgrade
  precision to make an invalid value pass. DS-010 accepts only the versioned
  Agent-Commerce Payment selector, requires a typed resource, checks strict
  CAIP-2/10/19 syntax and same-chain asset/payee binding, forbids fields owned
  by other profiles, and rejects all unsupported action pairs before durable
  admission. DS-037 now runs valid and adversarial seeds through this public
  boundary under a bounded nightly libFuzzer smoke, and properties prove
  string-only Amount round trips plus canonical Decision binding rejection.
  Namespace-specific address/asset validation and corresponding fuzz/property
  expansion remain owned by future Adapter profiles. DS-011 returns only fixed
  error codes/messages and server-owned semantic code/field details; raw
  request values, Schema diagnostics and internal Store/SQL/policy/key text do
  not cross the HTTP response boundary. PostgreSQL tests prove all validation
  rejection classes leave Idempotency Reservation, Intent, Evaluation,
  Decision and Audit counts at zero.
- **Malicious or malformed Cedar Policy Bundles** fed to `atf-policy` — DS-019
  closes the manifest shape, direct filenames and file counts; bounds Manifest,
  per-file and total bytes; rejects traversal/symlinks/unlisted files; verifies
  exact digests plus a domain-separated Bundle hash; and validates both Policy
  and Request against one Cedar Schema. Scope/expiry and Cedar runtime
  diagnostics fail closed on every evaluation. DS-020 signs the exact Bundle
  Hash plus publisher Key ID, stores a bounded exact-byte archive/public-key
  proof immutably, and permits only an audited active pointer. Gateway no
  longer evaluates a startup directory; each request revalidates the current
  durable artifact. Offline installation remains a privileged deployment
  boundary, and dedicated publisher-key revocation plus multi-Bundle conflict
  analysis remain open.
- **Malicious or ambiguous Risk configuration** — DS-021 requires one bounded
  regular closed JSON artifact, rejects unknown keys, unsupported format/engine
  versions, invalid thresholds/windows and non-canonical deny lists, then
  domain-separates a canonical hash over every decision-affecting field.
  Gateway startup fails if the configured artifact cannot validate, and Risk
  evidence records its exact version/hash. DS-026 archives that artifact
  immutably by organization/environment with typed installer evidence, and
  startup/replay require the exact archived hash. DS-022 enforces provenance
  for the current vendor-price consumer, and DS-023 durably snapshot-binds the
  selected artifact, trust-policy identity and verified Evidence before evaluation.
  DS-024 rejects any Rule Set other than that exact Context-bound artifact and
  prevents an enabled vendor-price rule from treating absent trusted data as
  not applicable.
- **Evidence source spoofing and price-context poisoning** — source labels do
  not grant authority. DS-022 requires an exact deployment-owned source/kind
  allowlist, canonical hash, explicit evaluation-time freshness and configured
  strict Ed25519 proof when required. `VerifiedEvidence` cannot be directly
  constructed. Agent privileged keys are isolated, and an exact trusted value
  wins regardless of Agent overrides or unrelated-scope evidence. DS-023
  persists those verified envelopes and the trust selection in one immutable,
  hash-checked context. DS-024 removes Risk's Agent-context fallback entirely;
  only the Context-persisted verified envelope can supply a trusted value.
  Production evidence acquisition is still absent.
- **Durable history cost and poisoning boundary** — denied and
  cross-organization requests cannot establish duplicate or destination
  familiarity, and restart no longer clears history. DS-028..DS-031 replace
  Risk's full-chain input with typed indexed queries bounded by their exact
  organization/Agent/Profile/resource/destination/time and repository scope.
  Duplicate and destination matches are capped at one prior `PERMITTED`
  result; daily spend is capped at 256 asset groups; request frequency is a
  bounded aggregate over immutable Profile/action-bound `IntentReceived`
  events. Query/result evidence plus
  the Context repository hash make later or substituted history fail closed in
  evaluation and Replay. Other Store
  integrity readers still verify complete organization chains. DS-034 bounds
  each application request, while retention/checkpoint work remains required
  to reduce the underlying growth cost.
- **Audit query isolation and traversal cost** — DS-032 authenticates before
  parsing query details, rechecks current local auditor/admin authority inside
  the Store snapshot, and avoids loading a target chain when no target role row
  exists. Filters are conjunctive and responses cap at 100. A canonical cursor
  binds tenant, filters and the verified prefix, preventing cross-filter reuse
  and append-driven page drift; it is not an authorization token. Every page
  still verifies the complete organization chain, so an authorized query over
  a very large chain is an O(chain) availability surface. DS-034 caps request
  time/rate; checkpoints and retention must still reduce the O(chain) work.
- **Decision substitution or field tampering** — DS-025 rejects Policy/Risk
  output identities that differ from the persisted Context, seals every
  decisive field under `ATF_DECISION_V1`, and makes Store reads require the
  embedded hash, canonical Decision row, immutable Context and mirrored
  `DecisionRecorded.binding` to agree. This proves what was decided; a future
  execution grant must still bind and enforce the exact Decision hash.
- **Evaluator crash and stale completion** — authenticated admission durably
  records `IDENTITY_VERIFIED/v2` and atomically creates a database-clock
  evaluator lease.
  Renewal preserves its generation; conditional expiry reclaim rotates the
  opaque owner and increments that generation. Finalization locks and verifies
  the reservation before the Intent, so a late predecessor cannot overwrite a
  recovered result. Generation greater than one can only finalize a
  fail-closed `Decision(ERROR)`. DS-013 renews the active generation between Policy/Risk
  stages, returns the verified original Decision after a completed-response
  loss, and makes a retry conditionally reclaim an expired admission. DS-023
  makes the retry reuse a pre-crash context or persist an explicit-unavailable
  recovery context; it does not run current Policy/Risk and records
  `RECOVERY_REPLAY_NOT_IMPLEMENTED`. Recovery is request-driven, so an
  abandoned Intent remains `RECEIVED` until a retry arrives; no background
  scanner or operational alert exists yet.
- **Dependency outage, lock exhaustion, or partial finalization** — DS-035
  separates process liveness from serving readiness: compatible live
  PostgreSQL, the configured signed active Policy and fresh Operator JWKS are
  all required before an instance is ready. Database/schema and bounded lock
  failures reject with a stable safe 503 and roll back the active transaction;
  corrupt history/Audit evidence fails with the stable integrity contract.
  Active Policy loss with healthy storage is explicitly bound into the
  Evaluation Context and can produce only an atomically finalized
  `Decision(ERROR)`. Store Finalization commits Evaluation, Decision,
  lifecycle and final Audit evidence together, and the Gateway responds only
  with the committed `FinalizedDecision`; injected `DecisionRecorded` failure
  proves no Permit or partial Evaluation/Decision escapes. Closed dependency
  labels expose the affected boundary without SQLSTATE, tenant, artifact or
  error-message cardinality. DS-036 repeats two-instance Decision/Nonce races,
  restart verification, lock timeout and real deadlock detection in local/CI
  PostgreSQL with external deadlines. DS-037 additionally runs the fixed-hash
  Replay vector, attacker-resealed binding properties, nine durable Replay
  scenarios and a bounded sanitizer-backed Intent fuzz job in CI. DS-039 adds
  a clean single-host submit/restart/Replay proof, PostgreSQL backup/isolated
  restore with identical Audit head, and audited Policy rollback/forward.
  Background recovery scanning, HA/failover, production RPO/RTO and
  cross-host incident drills remain open.
- **Supply-chain risk in source and Rust dependencies** — DS-038 supplements
  warning-free all-feature/all-target `cargo deny` with RustSec scans of both
  locks, complete-history/current-tree Gitleaks and `unsafe_code`-forbidden
  Clippy. Every Action is commit-pinned, tools are exact versioned, weekly
  Dependabot covers both workspaces and Actions, and safe fixtures prove each
  gate fails. Current lock-only RustSec and historical public-test exceptions
  are owner-bound and expire on 2026-11-07. Container/SBOM/provenance controls
  remain outside this source/PR boundary.

## DS-017/DS-018 operator boundary threat review

Accepted [`ADR-0003`](decisions/0003-operator-authentication.md) was reviewed
against the current Gateway routes and STRIDE/confused-deputy cases. DS-018 now
implements and tests the listed application-level fail-closed results, closing
GAP-API-001 for the current route surface. DS-034 adds the application ingress
and resource-limit controls without trusting proxy identity Headers.

| Abuse case | Required fail-closed result |
|---|---|
| Forge `X-ATF-Organization-ID`, path/body organization, or proxy identity Header | Selector grants no authority; Gateway-validated token plus matching durable organization role is required |
| Reuse an Agent signature as an operator credential, or use an operator token to submit as an Agent | Typed Agent and Operator principals are mutually exclusive at the route boundary |
| Present an ID token or JWT from the wrong issuer/audience | Explicit `at+jwt`, exact issuer, and configured audience checks reject before route logic |
| Use `alg=none`, algorithm confusion, embedded keys, `jku`, or `x5u` | Fixed asymmetric allowlist and configured JWKS only; no token-directed network lookup |
| Keep using a removed role with a still-valid token | Token role/group claims grant nothing; PostgreSQL subject/role status is checked on every request |
| Multi-organization operator selects another tenant's resource | Principal binding, selector, durable resource organization, and Audit organization must all agree |
| Probe whether another tenant's Decision exists | Missing, cross-tenant, and wrong-read-role cases return the same 404 contract |
| Probe another tenant's Audit chain, role membership, or corruption state | Authentication occurs first; no-role targets are not loaded, and absent/cross-tenant/wrong-role cases return the same `AUDIT_EVENTS_NOT_FOUND` contract |
| Rebind an Audit cursor to another organization/filter or append between pages | Canonical cursor binds organization, filter hash and verified prefix; every page reauthenticates and later appends do not change the traversal |
| Share a service credential to erase attribution | One external subject and internal operator ID per human/service principal; no shared or anonymous fallback |
| Replay a stolen access token or leak it through logs | TLS, exact audience, short lifetime, fixed redaction; sender-constrained tokens are reconsidered before Enforce |
| Force unbounded JWKS refresh with unknown `kid` values | At most one bounded configured-origin refresh; stale/unavailable keys fail authentication/readiness closed |

Residual risk remains explicit: disabling an external identity does not revoke
an already issued self-contained access token instantly. The accepted
reference limits that window to a short token lifetime and requires immediate
local subject disable for incidents. DS-034's process-local quotas do not
replace TLS ingress, firewall/direct-port isolation or shared edge limits;
production high-risk or Enforce authority also requires another
sender-constraint review.

## DS-040 C4 threat disposition

The complete STRIDE table and PRD acceptance mapping are in
`docs/release-candidate-checklist.md`. Spoofing, tampering, repudiation,
information disclosure, denial-of-service and elevation-of-privilege controls
were rechecked across the exact current Router, middleware, Store authority,
local Compose boundary and CI configuration.

The review found no execution route, float-backed financial type, first-party
unsafe Rust, core LLM dependency or plaintext production secret. Its one
current-scope access-control contradiction is now remediated by accepted
ADR-0004's disjoint mTLS/UDS boundary and closed `METRICS_READ` capability.
The clean Compose drill proves negative certificate cases, business-surface
non-reachability, database-outage telemetry and trust-pool rotation without an
anonymous interval. C4 remains blocked until an independent human reviewer
accepts this evidence and residual trusted-edge/local-PKI risk.

Future Budget, Simulator, Approval, Execution, Adapter and Reconciliation
threats remain non-applicable only because those capabilities and routes are
absent. Their CRITICAL/HIGH gaps are not closed and become mandatory before
the relevant later phase can expose authority.

## Secret management (PRD §18.3)

This repository does not integrate with any KMS, Vault, Fireblocks, Privy, or
Safe signer. DS-039 generates one local development Agent signing seed inside
the `atf-local_local-state` Docker volume; it is never committed or exposed to
the Gateway and is erased by the documented destructive reset. It is not a
production secret-management design. When
Adapters are added (Phase 3+), they must reference secrets by an external
handle (`secret_binding` in the Adapter Manifest, PRD §15.4) — never hold
plaintext key material in the ATF core process.
