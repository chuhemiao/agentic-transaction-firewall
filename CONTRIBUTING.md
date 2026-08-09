# Contributing to ATF

Thanks for considering a contribution. ATF is in PRD Phase 2 (Durable Shadow
Mode) and still cannot execute transactions, so please open an issue to discuss
non-trivial changes before writing code.

## Ground rules

1. **Read `docs/PRD.md` and `docs/threat-model.md` first.** Most design
   questions ("why doesn't ATF just...") are already answered there.
2. **Core domain types never use floating point** for amounts (PRD §9.1,
   §35.8) — use `rust_decimal::Decimal` or a fixed-point string.
3. **Fail closed.** Any new code path that hits an indeterminate error must
   default to deny/reject, not permit.
4. **No production secrets in this repo, ever** — not in code, tests,
   fixtures, or example policies.
5. **New Adapters must ship a Mock Server and Shadow Mode support** before a
   production execution path (PRD §27.6).
6. **Significant changes to the Transaction Intent schema, Decision model, or
   Adapter interface should be discussed in an issue first** — these are the
   project's long-term public contracts (PRD §37).

## Development setup

```bash
cargo build
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check -D warnings
ATF_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
  cargo test --workspace --all-targets --all-features
```

All five must pass before opening a PR; CI enforces the same checks
(`.github/workflows/ci.yml`).

The PostgreSQL test role must be allowed to create temporary databases and
roles. CI provisions a version-pinned PostgreSQL 17.10 service for this gate.
DS-036 also runs the persistence/race subset twice in CI. Run the same focused
gate locally with:

```bash
ATF_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
ATF_PERSISTENCE_TEST_REPETITIONS=2 ./scripts/test-persistence.sh
```

Use the isolated test-only stack documented in `deploy/docker/README.md` when
no local PostgreSQL is available.

DS-037 adds a focused Replay/property gate and a separately tooled fuzz smoke:

```bash
ATF_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
  ./scripts/test-conformance.sh
rustup toolchain install nightly-2026-08-01 --component llvm-tools-preview
cargo +nightly-2026-08-01 install cargo-fuzz --locked --version 0.13.2
RUSTUP_TOOLCHAIN=nightly-2026-08-01 ./scripts/test-fuzz.sh
```

The fuzz runner is bounded to 15 seconds by default and rejects a non-nightly
compiler or a cargo-fuzz version different from the CI pin.

## Commit / PR expectations

- Keep PRs focused on a single crate or concern where possible.
- Add or update unit tests for behavior you change.
- Update the relevant `docs/*.md` page if you change externally-visible
  behavior (schema fields, CLI commands, API routes).
- Use the PR template checklist.

## Reporting bugs vs. security issues

Regular bugs: open a GitHub issue.
Security vulnerabilities: see `SECURITY.md` — do not file a public issue.

## Code of conduct

This project follows the `CODE_OF_CONDUCT.md`.
