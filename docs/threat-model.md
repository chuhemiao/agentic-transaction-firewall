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
| 1 | Prompt injection causing an Agent to overstep authorization | Partially constrained on the Shadow Gateway path by mandatory Policy/Risk evaluation and no LLM in Permit/Deny; identity, semantic validation, and execution enforcement are still absent |
| 2 | Agent tool-call parameters tampered with | Partially addressed: `atf-intent` canonical hash is tamper-evident and `atf-identity` can verify Ed25519 signatures, but identity is not wired into the gateway and the signed message still lacks domain separation |
| 3 | Intent and final transaction diverge | Not yet enforced — requires execution-hash binding (PRD §14.2, §18.1.5), Phase 4 |
| 4 | Policy bypass | The gateway has one Policy-first evaluation path and no execution route. It is still unauthenticated, so this is not yet a deployable enforcement boundary |
| 5 | Approval replay | Not applicable yet — no Approval Engine (Phase 4) |
| 6 | Payment proof replay | Not applicable yet — no Adapter (Phase 3) |
| 7 | Nonce replay | Unmitigated in code: `idempotency_key` is only schema-level and signed identity envelopes have no nonce. ADR-0002 fixes the target atomic reservation, nonce-consumption, lease, and fencing contract, but DS-012..DS-016 must implement it |
| 8 | TOCTOU between decision and execution | Addressed by design via execution-hash binding (Phase 4); not applicable while there is no execution path |
| 9 | Malicious Adapter | Addressed by design via Adapter isolation + Conformance Tests (Phase 3); no Adapter exists yet |
| 10 | Supply-chain dependency attack | Partially addressed: `cargo deny` is configured and runs in CI. `cargo audit`, secret scanning, SAST, SBOM, and artifact signing are not configured |
| 11 | Admin privilege abuse | Addressed by design via Admin API RBAC (PRD §17.3); no Admin API exists yet |
| 12 | Audit log deletion | Partially addressed: migration 0001 rejects Audit UPDATE/DELETE/TRUNCATE, DS-003 row-locks per-organization append and restart-verifies canonical bytes/hash/order/head, DS-004 atomically binds business rows to Audit evidence, and DS-005 makes that durable path authoritative for Gateway traffic. Independent checkpoints, retention, and privileged-database threat controls remain later work |
| 13 | Price oracle manipulation | Exposed: the vendor-price rule currently trusts `context.historical_vendor_median` supplied in the Intent; provenance, freshness, and trusted enrichment are not implemented |
| 14 | Exchange API key leakage | Not applicable yet — no Adapter holds any credential in this repo |
| 15 | Unlimited token approval | Unmitigated: the action category exists, but the Intent has no typed spender/allowance fields and no unlimited-approval rule |
| 16 | Malicious contract call | Not applicable yet — no Simulator (Phase 3) |
| 17 | Payment settled but service not delivered | Not applicable yet — no Reconciliation (Phase 4) |
| 18 | Duplicate purchase | Partially mitigated: the Gateway reads verified durable Audit history across restarts/instances, and the 24-hour rule counts only prior same-organization `PERMIT` decisions; deterministic snapshot time plus execution- and settlement-based accounting do not exist yet |
| 19 | Multi-agent collusion to bypass budget | Not applicable yet — Budget model is specced (PRD §9.4) but not implemented |
| 20 | High-frequency small-order splitting to bypass per-transaction limits | Not applicable yet — cumulative-spend risk rules are Phase 2 |

## What this repo's current attack surface actually is

There is a network service but no Adapter, execution route, or production
secret. The realistic attack surface today includes:

- **Unauthenticated HTTP input** to `POST /v1/intents` and tenant-selected
  reads from `GET /v1/intents/{id}/decision`. GET requires
  `X-ATF-Organization-ID`, but callers can forge it until authentication/RBAC
  lands. There is no request-size limit, rate limit, or completed idempotency.

- **Malformed/adversarial JSON input** to `atf-intent::validate` and
  `atf-cli` — mitigated by JSON Schema validation and Rust's memory safety;
  fuzz targets for the parser/normalizer are tracked in `fuzz/` (Phase 1+).
- **Malicious or malformed Cedar policy files** fed to `atf-policy` —
  Cedar syntax parsing failures stop bundle loading, but Cedar Schema and
  signed Bundle validation are still missing.
- **Durable history cost and poisoning boundary** — denied and
  cross-organization requests cannot trigger the duplicate-purchase rule, and
  restart no longer clears history. The Gateway currently reloads and verifies
  the full organization chain for each permitted request; bounded snapshot
  queries and request/rate limits are still required to resist growth-based
  denial of service.
- **Evaluator crash and stale completion** — admission is durable, but the
  running Gateway has no lifecycle reservation or recovery path. A crash
  before finalization can strand an Intent, and a retry currently conflicts.
  ADR-0002 requires finite leases with
  monotonically increasing fencing generations and immutable evaluation
  inputs, so a recovered worker cannot be overwritten by a late predecessor;
  implementation is still pending.
- **Supply-chain risk in Rust dependencies** — partially mitigated via
  `cargo deny` in CI; the broader controls listed above remain open.

## Secret management (PRD §18.3)

Not yet applicable: this repository does not integrate with any KMS, Vault,
Fireblocks, Privy, or Safe signer, and holds no secret material. When
Adapters are added (Phase 3+), they must reference secrets by an external
handle (`secret_binding` in the Adapter Manifest, PRD §15.4) — never hold
plaintext key material in the ATF core process.
