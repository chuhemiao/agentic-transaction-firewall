# Security Policy

Agentic Transaction Firewall (ATF) sits in the critical path of financial
transactions. Please report vulnerabilities privately and give us time to
respond before any public disclosure.

## Reporting a vulnerability

Do **not** open a public GitHub issue for security reports.

Instead, use GitHub's private vulnerability reporting
(Security tab -> "Report a vulnerability") on this repository, or email the
maintainers listed in `CONTRIBUTING.md`. Include:

1. A description of the vulnerability and its impact.
2. Steps to reproduce, or a proof-of-concept Transaction Intent / Policy /
   Adapter input that triggers it.
3. Affected crate(s) and version(s).
4. Whether the issue is exploitable in Shadow Mode, Review Mode, and/or
   Enforce Mode.

We aim to acknowledge reports within 5 business days.

## Scope

In scope:

- `crates/*`, `cli/*`, `services/*` — the Rust core.
- `sdk/*` — TypeScript and Python SDKs.
- Example policies under `policies/` and reference agents under `examples/`,
  to the extent a flaw there would mislead an integrator into an unsafe
  configuration.

Out of scope (see PRD §5 non-goals):

- Vulnerabilities in third-party wallets, exchanges, or custody providers ATF
  integrates with (Fireblocks, Privy, Safe, Coinbase CDP, exchanges, etc.) —
  report those upstream.
- Smart contract bugs in protocols ATF merely observes or simulates against.
- Loss of funds caused by a user- or organization-authored Policy Bundle
  behaving exactly as written.

## Our security principles

See `docs/threat-model.md` for the full threat model. Highlights that shape
how we triage reports:

- Fail Closed: any indeterminate error must default to deny, never permit.
- ATF never holds production signing keys in its core process (PRD §18.3).
- Decisions must be deterministic and replayable; a report that breaks either
  property is treated as high severity even without a direct funds-loss path.
