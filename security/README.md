# Security gate policy

DS-038 makes dependency vulnerability, committed-secret, and first-party Rust
static analysis blocking pull-request gates. Tool versions and the reviewed
Linux cargo-audit and Gitleaks checksums are declared once in
`tool-versions.env`; every GitHub Action and CI service image is referenced by
an immutable commit/digest, and `.github/CODEOWNERS` assigns these controls to
`@chuhemiao` for review.

## Local commands

Install the pinned RustSec tool and either install Gitleaks 8.30.1 or leave
Docker available for the digest-pinned fallback:

```bash
cargo install cargo-audit --locked --no-default-features --version 0.22.2
./scripts/test-security.sh
./scripts/test-rust-sast.sh
```

`test-security.sh` audits both `Cargo.lock` files, proves every advisory
exception is absent from the actual root/fuzz all-feature/all-target Cargo
trees, scans the complete Git history and current tree, then proves the
RustSec, Gitleaks, and expiry controls reject safe negative fixtures.
`test-rust-sast.sh` runs warning-free Clippy with `unsafe_code` forbidden and
proves an isolated unsafe fixture fails.

Normal runs fetch the current RustSec advisory database. `ATF_ADVISORY_DB` may
name an already cloned database only for a network-isolated local run; CI never
sets it and therefore must refresh successfully or fail closed.

## Exceptions and updates

- `advisory-exceptions.toml` accepts only an exact RUSTSEC ID/package/version,
  one GitHub owner, a concrete reason, and an expiry at most 90 days away. The
  wrapper applies them only to cargo-audit's lockfile scan. Cargo-deny evaluates
  the enabled graph, does not encounter these disconnected nodes, and retains
  an empty advisory ignore set so `-D warnings` still detects stale entries.
- `secret-exceptions.toml` accepts only exact committed Gitleaks fingerprints
  under the same owner/reason/90-day rule. Path, rule, and current-tree secret
  allowlists are not accepted.
- The two advisory exceptions currently expire on 2026-11-07. They cover
  `rkyv 0.7.46` and `rsa 0.9.10` nodes retained in Cargo locks but absent from
  the enabled root/fuzz build trees. If either becomes reachable, validation
  fails immediately; otherwise the owner must remove, remediate, or explicitly
  re-review before expiry.
- The two historical secret fingerprints also expire on 2026-11-07. They are
  deterministic public test material, not credentials; current files receive
  no exception.

For a tool update, review the upstream release, change the exact version and
immutable Action/image reference together, run both scripts including all
negative fixtures, and record the result in the changelog. Dependabot checks
the root Cargo workspace, the separate fuzz workspace, and GitHub Actions each
week; updates never merge without the normal gates and code-owner review.
