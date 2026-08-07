# AGENTS.md

Orientation for any AI agent picking up work on this repo cold. This file
is a map, not the map — the files it points to are the actual source of
truth and change more often than this one does.

## What this project is

Agentic Transaction Firewall (ATF): an open-source Rust workspace
implementing a control layer that sits between AI Agents and
wallets/exchanges/payment networks, so that financial actions must pass
through Policy → Risk → Decision → Audit before anything executes. Full
spec: [`docs/PRD.md`](docs/PRD.md) (v1.2). One-paragraph pitch and the
target pipeline diagram: [`README.md`](README.md).

**Read `README.md`'s "Status" and "Roadmap" sections before doing anything
else.** That file is updated every iteration and is the live record of what
exists vs. what's still scaffolded. Do not trust your training data or any
summary (including this file) over what's actually in the repo right now —
run `git log --oneline -15` and re-read `README.md` first.

## How this repo gets built

Work proceeds one feature at a time, each verified and committed
separately (see git history — every commit is one self-contained feature).
If you're asked to "continue" or "keep going through the TODO list":

1. Pick the next unchecked item from `README.md`'s "Immediate TODO" /
   "Remaining before Phase N" sections.
2. Implement it.
3. Verify: `cargo fmt --all -- --check`, `cargo clippy --all-targets
   --all-features -- -D warnings`, `cargo test --workspace --all-targets
   --all-features` — all three must be clean.
4. If the change has runtime behavior (new HTTP route, new CLI command,
   etc.), smoke-test the real thing — run the actual binary and hit it
   (`curl`, `cargo run -p atf-cli -- ...`), don't stop at unit tests. This
   project's history includes cases where the real behavior differed
   subtly from what unit tests alone suggested (see the `preserve_order`
   gotcha below) — running the real thing is what caught it.
5. Update `README.md` (Status + Roadmap) and `docs/architecture.md` to
   reflect exactly what changed — strike through completed TODO items with
   a one-line "Done: ..." note, add any new gap you discovered.
6. One commit per feature, message explains *why*, not just what.
7. Stop. Don't chain multiple TODO items into one turn unless explicitly
   told to.

## Orientation: what's real vs. scaffolded

- `crates/atf-core`, `atf-intent`, `atf-identity`, `atf-policy`, `atf-risk`,
  `atf-audit`, `atf-decision`, `atf-store` and `cli/atf-cli`,
  `services/gateway`: real, tested Rust code. `atf-store` currently owns
  migration/schema compatibility, durable per-organization Audit append, and
  atomic admission/finalization repository operations; Gateway cutover begins
  at DS-005.
- Every other directory (`crates/atf-simulator`, `crates/atf-approval`,
  `crates/atf-adapter-*`, `services/policy-server`, `services/*-server`,
  `sdk/*`, etc.) is an empty stub with just a `README.md` saying what
  belongs there and which PRD phase will fill it in. Don't assume any code
  exists there without checking.
- `docs/architecture.md`'s "What exists today" section is the authoritative
  per-crate implemented/partial/stub breakdown, kept current every
  iteration.

## Hard-won gotchas (don't re-discover these the slow way)

- **Never assume `serde_json::Value::Object` preserves or sorts keys by
  default.** Cargo unifies features across the whole build; this workspace
  has dependencies (`jsonschema`/`cedar-policy` via `serde_with`) that turn
  on serde_json's `preserve_order` feature, which silently changes
  `Value::Object`'s iteration order for *every* crate in the workspace —
  including ones that never asked for it. Any code needing a deterministic
  hash over JSON must sort explicitly via `atf_core::sort_json_keys`, not
  rely on the default. This bit `atf-intent`'s canonical hash once already;
  don't reintroduce it in a new crate.
- **Cedar's `decimal` extension supports at most 4 fractional digits.**
  `atf-policy` maps `Amount` fields to Cedar `decimal(...)` values so
  policies can do range comparisons; an amount with finer precision fails
  to build a Cedar context (by design — fail closed, not silent
  truncation). See `crates/atf-policy/src/mapping.rs`.
- **No floating point anywhere in core domain types.** Money/quantities use
  `atf_core::Amount` (a `rust_decimal::Decimal` wrapper, string-only on the
  wire via the `serde-str` feature). This is a hard PRD requirement
  (§9.1.7, §35.8), not a style preference.
- **Fail closed, always.** Any indeterminate error (parse failure,
  evaluation error, missing key) must resolve to the most restrictive
  outcome (`DENY`/`ERROR`/rejection), never silently to permit/success.
  Every crate's error handling follows this; new code must too.

## Quick commands

```bash
cargo build
ATF_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres cargo test
DATABASE_URL=postgres://postgres:postgres@localhost:5432/atf cargo run -p atf-store --bin atf-store-migrate
cargo run -p atf-cli -- validate-intent examples/x402-research-agent/intent.json
cargo run -p atf-cli -- evaluate examples/x402-research-agent/intent.json --policies policies/examples
cargo run -p atf-cli -- policy test
DATABASE_URL=postgres://postgres:postgres@localhost:5432/atf cargo run -p atf-store --bin atf-store-migrate
DATABASE_URL=postgres://postgres:postgres@localhost:5432/atf PORT=8080 ATF_POLICIES_DIR=policies/examples cargo run -p atf-gateway
# Provision the Intent's organization first; GET Decision also requires X-ATF-Organization-ID.
```

## Where to look for more

- Product spec: `docs/PRD.md`
- Architecture / what's implemented: `docs/architecture.md`
- Threat model: `docs/threat-model.md`
- Contribution norms (for human-facing PRs): `CONTRIBUTING.md`
- Security disclosure: `SECURITY.md`
