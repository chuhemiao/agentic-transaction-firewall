# Threat Model (draft)

This draft covers the threats enumerated in `docs/PRD.md` §18.2, annotated
against the current Phase 2 Shadow Mode implementation. The gateway has a
real network request path, but no execution path or production secret.

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
| 3 | Intent and final transaction diverge | Not yet enforced — requires execution-hash binding (PRD §14.2, §18.1.5), Phase 4 |
| 4 | Policy bypass | The Gateway has one Agent-authenticated Policy-first evaluation path and no execution route. DS-018 protects Decision reads with current durable Operator roles; Policy bundle provenance and production edge controls are still absent, so this is not yet a deployable enforcement boundary |
| 5 | Approval replay | Not applicable yet — no Approval Engine (Phase 4) |
| 6 | Payment proof replay | Not applicable yet — no Adapter (Phase 3) |
| 7 | Nonce replay | Mitigated for Gateway Agent admission: DS-016 atomically stores an organization/Agent-scoped Nonce hash bound to the exact Key, Envelope, Intent and idempotency tuple. Exact retry adds nothing; fresh valid retry consumes a new Nonce; conflicting concurrent or post-restart reuse emits `ReplayDetected` and fails 409. Raw Nonces/signatures are not stored and privileged row tampering is detected on verified reads |
| 8 | TOCTOU between decision and execution | Addressed by design via execution-hash binding (Phase 4); not applicable while there is no execution path |
| 9 | Malicious Adapter | Addressed by design via Adapter isolation + Conformance Tests (Phase 3); no Adapter exists yet |
| 10 | Supply-chain dependency attack | Partially addressed: pinned cargo-deny 0.20.2 checks all features/targets in CI, denies advisories, unreviewed licenses/sources/wildcards and new duplicate versions, and fails on every warning; exact current duplicate exceptions carry dependency-path reasons. `cargo audit`, secret scanning, SAST, SBOM, and artifact signing are not configured |
| 11 | Admin privilege abuse | DS-018 implements ADR-0003's disjoint Agent/Operator principals and PostgreSQL-authoritative explicit roles for Decision reads. No Admin API exists; future administrative capabilities still require endpoint matrices and high-risk multi-party controls |
| 12 | Audit log deletion | Partially addressed: migration 0001 rejects Audit UPDATE/DELETE/TRUNCATE, DS-003 row-locks per-organization append and restart-verifies canonical bytes/hash/order/head, DS-004/DS-005 make atomic durable evidence authoritative, DS-007 binds Intent lifecycle state/version/event pointers, DS-015 applies the same rule to Agent/Key lifecycle, DS-016 binds Nonce rows to verified Audit/lifecycle evidence, and DS-018 binds Operator/Role lifecycle to typed events. Independent checkpoints, retention, and privileged-database threat controls remain later work |
| 13 | Price oracle manipulation | Exposed: the vendor-price rule currently trusts `context.historical_vendor_median` supplied in the Intent; provenance, freshness, and trusted enrichment are not implemented |
| 14 | Exchange API key leakage | Not applicable yet — no Adapter holds any credential in this repo |
| 15 | Unlimited token approval | Fail closed at admission: Token Approval has no implemented Profile and returns `UNSUPPORTED_INTENT_PROFILE`. A safe spender/allowance model and unlimited-approval rule still do not exist |
| 16 | Malicious contract call | Fail closed at admission: Contract Call has no implemented Profile, and the Payment profile forbids contract/calldata fields. Simulator-backed Contract Call semantics remain Phase 3 work |
| 17 | Payment settled but service not delivered | Not applicable yet — no Reconciliation (Phase 4) |
| 18 | Duplicate purchase | Partially mitigated: the Gateway reads verified durable Audit history across restarts/instances, and the 24-hour rule counts only prior same-organization `PERMIT` decisions; deterministic snapshot time plus execution- and settlement-based accounting do not exist yet |
| 19 | Multi-agent collusion to bypass budget | Not applicable yet — Budget model is specced (PRD §9.4) but not implemented |
| 20 | High-frequency small-order splitting to bypass per-transaction limits | Not applicable yet — cumulative-spend risk rules are Phase 2 |

## What this repo's current attack surface actually is

There is a network service but no Adapter, execution route, or production
secret. The realistic attack surface today includes:

- **Disjoint Agent writes and Operator reads.** POST
  requires a canonical signed Envelope and current durable exact Key, with
  atomic hashed-Nonce consumption before Policy/Risk. GET requires a
  Gateway-validated configured-issuer JWT and a current durable
  `auditor`/`org_admin` role for its organization selector. DS-018 ignores
  token role/organization claims, makes current local disable/revoke immediate,
  rejects credential type confusion and prevents cross-tenant/wrong-role
  resource enumeration. A caller with the exact valid Agent proof can still
  trigger that request's post-expiry fail-closed recovery; this cannot produce
  Permit but can terminate the Intent as ERROR. General timeout/rate limits and
  trusted ingress deployment remain incomplete, so the Gateway is still
  unsuitable for an untrusted shared network.

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
  admission. Namespace-specific address/asset validation and fuzz/property
  expansion remain Adapter-profile and DS-037 work. DS-011 returns only fixed
  error codes/messages and server-owned semantic code/field details; raw
  request values, Schema diagnostics and internal Store/SQL/policy/key text do
  not cross the HTTP response boundary. PostgreSQL tests prove all validation
  rejection classes leave Idempotency Reservation, Intent, Evaluation,
  Decision and Audit counts at zero.
- **Malicious or malformed Cedar policy files** fed to `atf-policy` —
  Cedar syntax parsing failures stop bundle loading, but Cedar Schema and
  signed Bundle validation are still missing.
- **Durable history cost and poisoning boundary** — denied and
  cross-organization requests cannot trigger the duplicate-purchase rule, and
  restart no longer clears history. The Gateway currently reloads and verifies
  the full organization chain for each permitted request; bounded snapshot
  queries and request/rate limits are still required to resist growth-based
  denial of service.
- **Evaluator crash and stale completion** — authenticated admission durably
  records `IDENTITY_VERIFIED/v2` and atomically creates a database-clock
  evaluator lease.
  Renewal preserves its generation; conditional expiry reclaim rotates the
  opaque owner and increments that generation. Finalization locks and verifies
  the reservation before the Intent, so a late predecessor cannot overwrite a
  recovered result. Until immutable Evaluation Context recovery exists,
  generation greater than one can only finalize a fail-closed
  `Decision(ERROR)`. DS-013 renews the active generation between Policy/Risk
  stages, returns the verified original Decision after a completed-response
  loss, and makes a retry conditionally reclaim an expired admission. Because
  pinned Evaluation Context does not exist, the recovered worker does not run
  current Policy/Risk; it records one explicit
  `RECOVERY_CONTEXT_UNAVAILABLE` error. Recovery is request-driven, so an
  abandoned Intent remains `RECEIVED` until a retry arrives; no background
  scanner or operational alert exists yet.
- **Supply-chain risk in Rust dependencies** — partially mitigated via
  warning-free, all-feature/all-target `cargo deny` in CI; the broader controls
  listed above remain open.

## DS-017/DS-018 operator boundary threat review

Accepted [`ADR-0003`](decisions/0003-operator-authentication.md) was reviewed
against the current Gateway routes and STRIDE/confused-deputy cases. DS-018 now
implements and tests the listed application-level fail-closed results, closing
GAP-API-001 for the current route surface. DS-034 still owns ingress and
resource-limit controls.

| Abuse case | Required fail-closed result |
|---|---|
| Forge `X-ATF-Organization-ID`, path/body organization, or proxy identity Header | Selector grants no authority; Gateway-validated token plus matching durable organization role is required |
| Reuse an Agent signature as an operator credential, or use an operator token to submit as an Agent | Typed Agent and Operator principals are mutually exclusive at the route boundary |
| Present an ID token or JWT from the wrong issuer/audience | Explicit `at+jwt`, exact issuer, and configured audience checks reject before route logic |
| Use `alg=none`, algorithm confusion, embedded keys, `jku`, or `x5u` | Fixed asymmetric allowlist and configured JWKS only; no token-directed network lookup |
| Keep using a removed role with a still-valid token | Token role/group claims grant nothing; PostgreSQL subject/role status is checked on every request |
| Multi-organization operator selects another tenant's resource | Principal binding, selector, durable resource organization, and Audit organization must all agree |
| Probe whether another tenant's Decision exists | Missing, cross-tenant, and wrong-read-role cases return the same 404 contract |
| Share a service credential to erase attribution | One external subject and internal operator ID per human/service principal; no shared or anonymous fallback |
| Replay a stolen access token or leak it through logs | TLS, exact audience, short lifetime, fixed redaction; sender-constrained tokens are reconsidered before Enforce |
| Force unbounded JWKS refresh with unknown `kid` values | At most one bounded configured-origin refresh; stale/unavailable keys fail authentication/readiness closed |

Residual risk remains explicit: disabling an external identity does not revoke
an already issued self-contained access token instantly. The accepted
reference limits that window to a short token lifetime and requires immediate
local subject disable for incidents. TLS/proxy hardening and resource limits
remain DS-034; production high-risk or Enforce authority requires another
sender-constraint review.

## Secret management (PRD §18.3)

Not yet applicable: this repository does not integrate with any KMS, Vault,
Fireblocks, Privy, or Safe signer, and holds no secret material. When
Adapters are added (Phase 3+), they must reference secrets by an external
handle (`secret_binding` in the Adapter Manifest, PRD §15.4) — never hold
plaintext key material in the ATF core process.
