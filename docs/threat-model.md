# Threat Model (draft)

This is an initial draft covering the threats enumerated in `docs/PRD.md`
§18.2, annotated with what today's skeleton (Phase 0/1: `atf-core`,
`atf-intent`, `atf-policy`, `atf-decision`, `atf-cli`) does and does not yet
mitigate. This will be expanded as later phases land.

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
| 1 | Prompt injection causing an Agent to overstep authorization | Out of scope for `atf-policy`/`atf-decision` today — mitigated structurally once Policy Kernel + Risk Engine are mandatory in front of every execution path; no LLM is in the Permit/Deny path (principle 8) |
| 2 | Agent tool-call parameters tampered with | Partially addressed: `atf-intent` canonical hash gives a tamper-evident representation of the Intent; signature verification (identity binding) is Phase 2 (`atf-identity`, PRD §17.2) |
| 3 | Intent and final transaction diverge | Not yet enforced — requires execution-hash binding (PRD §14.2, §18.1.5), Phase 4 |
| 4 | Policy bypass | `atf-policy` is the only evaluation path in this skeleton; no alternate/legacy path exists yet because no execution path exists yet |
| 5 | Approval replay | Not applicable yet — no Approval Engine (Phase 4) |
| 6 | Payment proof replay | Not applicable yet — no Adapter (Phase 3) |
| 7 | Nonce replay | Intent has an `idempotency_key` field (schema-level); enforcement of uniqueness is a gateway/persistence concern (Phase 2) |
| 8 | TOCTOU between decision and execution | Addressed by design via execution-hash binding (Phase 4); not applicable while there is no execution path |
| 9 | Malicious Adapter | Addressed by design via Adapter isolation + Conformance Tests (Phase 3); no Adapter exists yet |
| 10 | Supply-chain dependency attack | `cargo deny` configured (`deny.toml`) for license + advisory checks; CI runs `cargo audit` |
| 11 | Admin privilege abuse | Addressed by design via Admin API RBAC (PRD §17.3); no Admin API exists yet |
| 12 | Audit log deletion | Not applicable yet — no Audit Ledger (Phase 2, `atf-audit`) |
| 13 | Price oracle manipulation | Not applicable yet — no Risk Engine data sources (Phase 2, PRD §12.3) |
| 14 | Exchange API key leakage | Not applicable yet — no Adapter holds any credential in this repo |
| 15 | Unlimited token approval | Schema supports representing `token_approval` actions; the risk rule that flags unlimited approvals is Phase 2 (`atf-risk`) |
| 16 | Malicious contract call | Not applicable yet — no Simulator (Phase 3) |
| 17 | Payment settled but service not delivered | Not applicable yet — no Reconciliation (Phase 4) |
| 18 | Duplicate purchase | Not applicable yet — Risk Engine rule (Phase 2) |
| 19 | Multi-agent collusion to bypass budget | Not applicable yet — Budget model is specced (PRD §9.4) but not implemented |
| 20 | High-frequency small-order splitting to bypass per-transaction limits | Not applicable yet — cumulative-spend risk rules are Phase 2 |

## What this repo's current attack surface actually is

Since there is no network service, no Adapter, and no secret in this
skeleton, the realistic attack surface today is limited to:

- **Malformed/adversarial JSON input** to `atf-intent::validate` and
  `atf-cli` — mitigated by JSON Schema validation and Rust's memory safety;
  fuzz targets for the parser/normalizer are tracked in `fuzz/` (Phase 1+).
- **Malicious or malformed Cedar policy files** fed to `atf-policy` —
  Cedar's own policy validator is used before evaluation; a policy that
  fails validation must not silently evaluate as Permit (fail closed).
- **Supply-chain risk in Rust dependencies** — mitigated via `cargo deny`
  and `cargo audit` in CI.

## Secret management (PRD §18.3)

Not yet applicable: this repository does not integrate with any KMS, Vault,
Fireblocks, Privy, or Safe signer, and holds no secret material. When
Adapters are added (Phase 3+), they must reference secrets by an external
handle (`secret_binding` in the Adapter Manifest, PRD §15.4) — never hold
plaintext key material in the ATF core process.
