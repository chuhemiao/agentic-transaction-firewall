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

This repository is in the **skeleton / MVP bring-up** phase (PRD §36, Phase 0-1).
Only the following crates are implemented so far:

- `crates/atf-core` — shared domain primitives and error types.
- `crates/atf-intent` — canonical Transaction Intent type, JSON Schema
  validation, canonical serialization and hashing.
- `crates/atf-policy` — minimal Cedar policy evaluation over a Transaction
  Intent.
- `crates/atf-decision` — the Decision model and merge skeleton.
- `cli/atf-cli` — `atf validate-intent` and `atf evaluate`.

Everything else in the workspace (risk engine, simulator, approval engine,
adapters, gateway, audit ledger, SDKs) is scaffolded as an empty directory with
a `README.md` describing what belongs there and which roadmap phase will fill
it in — see PRD §31 for the phase plan.

No real wallet, exchange, or production secret is wired into this repository.
Execution is not implemented; every code path defaults to **Shadow Mode**
semantics (evaluate only, never execute).

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
