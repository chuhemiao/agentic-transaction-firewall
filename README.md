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
  -> Policy Evaluation
  -> Financial Risk Evaluation
  -> Simulation
  -> Approval
  -> Execution Adapter
  -> Settlement Verification
  -> Immutable Audit
```

ATF does not create wallets, does not custody assets, does not invent a new
payment protocol, and does not replace exchanges, Fireblocks, Privy, Safe,
Coinbase CDP, or AWS AgentCore. It provides the shared control-plane semantics
those systems can sit behind.

Full product requirements: [`docs/PRD.md`](docs/PRD.md).

## Status

This repository is in the **skeleton / MVP bring-up** phase (PRD §36; Phase 1
done, Phase 2 in progress — see Roadmap below).
Only the following crates are implemented so far:

- `crates/atf-core` — shared domain primitives and error types.
- `crates/atf-intent` — canonical Transaction Intent type, JSON Schema
  validation, canonical serialization and hashing.
- `crates/atf-identity` — Agent registration records and Ed25519
  identity-signature verification over an Intent's canonical hash.
- `crates/atf-policy` — minimal Cedar policy evaluation over a Transaction
  Intent.
- `crates/atf-risk` — a first Financial Risk Engine pass: deterministic,
  stateless MVP rules (request expiry, single-transaction cap, fee ratio,
  vendor price deviation, high-risk network/protocol).
- `crates/atf-audit` — the Audit Ledger domain logic: hash-chained events,
  append-only, with tamper detection (`verify_chain`). In-memory only — no
  persistent store yet.
- `crates/atf-decision` — the Decision model and the real PRD §10.1 merge
  algorithm (Policy + Risk; no Simulator branch yet).
- `cli/atf-cli` — `atf validate-intent`, `atf evaluate`, and `atf policy test`.

`schemas/` has `transaction-intent.schema.json` (enforced by `atf-intent`),
`decision.schema.json` (validated in CI against real `atf-decision` output),
and `audit-event.schema.json` (validated in CI against real `atf-audit`
output).

Everything else in the workspace (simulator, approval engine, adapters,
gateway, SDKs) is scaffolded as an empty directory with a `README.md`
describing what belongs there and which roadmap phase will fill it in — see
PRD §31 for the phase plan.

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
4. Risk rules that need history/state — daily cumulative spend, first-time
   destination address, duplicate purchase, order frequency (PRD §12.2) —
   need `atf-risk` to query the ledger below; not wired up yet.
5. ~~`atf-identity` — Agent registration + Ed25519 identity-signature
   verification (PRD §17.2).~~ Done as a library: an in-memory registry
   verifying a raw Ed25519 signature over `intent.canonical_hash()`, key
   rotation (multiple valid keys per Agent), and status gating
   (PAUSED/REVOKED/EXPIRED can't submit even with a valid signature). Not
   yet wired into anything — there is no `services/gateway` request path to
   call it from yet.
6. ~~`schemas/decision.schema.json` and `schemas/audit-event.schema.json`.~~
   Done: both validated in CI against real output (`atf-decision` and
   `atf-audit` respectively).
7. ~~`atf-audit` — the Audit Ledger (PRD §16).~~ Done as a library:
   hash-chained `AuditEvent`s, append-only, `verify_chain()` detects
   after-the-fact tampering. In-memory only (no PostgreSQL, per the PRD's
   own MVP design) and not called from anywhere yet.

### Remaining before Phase 2 can close out

- Wire `atf-identity` and `atf-audit` into an actual request path
  (`services/gateway`) — both are implemented but unused today.
- Wire the state-dependent Risk rules (item 4) up against `atf-audit` once
  the gateway exists to drive both.

### Phased plan (PRD §31)

- **Phase 1 (done)**: Policy Kernel + Decision merge + conformance harness.
- **Phase 2 (Shadow Mode, in progress)**: `atf-identity` and `atf-audit`
  (both done as libraries, neither wired in) + `services/gateway` to
  connect them into one request path and unlock the state-dependent Risk
  rules above.
- **Phase 3 (reference scenarios)**: `atf-simulator` + the three reference
  Adapters (Hyperliquid, Safe, x402) + the Adapter Conformance Test Suite.
- **Phase 4 (Approval & Enforce Mode)**: `atf-approval` + `atf-reconciliation`
  + execution-hash binding + Kill Switch.
- **Phase 5 (community)**: TypeScript/Python SDKs + MCP middleware + docs
  site.

## Getting started

```bash
cargo build
cargo test

# Validate an intent against the JSON Schema + canonical hash
cargo run -p atf-cli -- validate-intent examples/x402-research-agent/intent.json

# Evaluate an intent against an example Cedar policy bundle
cargo run -p atf-cli -- evaluate examples/x402-research-agent/intent.json --policies policies/examples
```

## Repository layout

See [`docs/architecture.md`](docs/architecture.md) for the full component
breakdown, and PRD §20 for the target Rust workspace layout.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

## Security

See [`SECURITY.md`](SECURITY.md) for how to report a vulnerability, and
[`docs/threat-model.md`](docs/threat-model.md) for the threat model this
project is designed against.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md).
