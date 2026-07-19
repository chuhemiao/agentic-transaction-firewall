# Architecture (draft)

This is a working draft. The authoritative source is `docs/PRD.md`; this
document translates it into the current and target code layout.

## Target pipeline (PRD §1, §8.1)

```text
Agent Intent
  -> Canonical Transaction Intent   (atf-intent)
  -> Identity Verification          (atf-identity)
  -> Policy Evaluation              (atf-policy, Cedar)
  -> Financial Risk Evaluation      (atf-risk)
  -> Simulation                     (atf-simulator)
  -> Decision merge                 (atf-decision)
  -> Approval (if REVIEW)           (atf-approval)
  -> Execution Adapter              (atf-adapter-*)
  -> Settlement Verification        (atf-reconciliation)
  -> Immutable Audit                (atf-audit)
```

## What exists today (Phase 0/1)

- **`atf-core`** — shared domain primitives: fixed-point `Amount`, `Timestamp`
  (RFC 3339), error types. *Implemented.*
- **`atf-intent`** — `TransactionIntent` type, JSON Schema validation,
  canonical serialization + SHA-256 hash. *Implemented.*
- **`atf-policy`** — Cedar schema + minimal
  `evaluate(intent) -> cedar_policy::Response`. *Implemented.*
- **`atf-decision`** — `Decision` type + merge skeleton (policy-only today;
  risk/simulation inputs are typed but not yet wired — see §10.1).
  *Implemented (partial).*
- **`cli/atf-cli`** — `atf validate-intent`, `atf evaluate`. *Implemented.*

Everything else under `crates/`, `services/`, `sdk/`, `examples/`,
`conformance/`, `deploy/`, `migrations/`, `fuzz/` is a scaffolded directory
with a `README.md` describing what belongs there and which roadmap phase
(PRD §31) will fill it in. None of it is wired into the Cargo workspace yet.

## Data flow through today's skeleton

1. A caller constructs or receives a `TransactionIntent` JSON document
   matching `schemas/transaction-intent.schema.json`.
2. `atf-intent::validate` checks it against the JSON Schema.
3. `atf-intent::canonical_hash` produces a deterministic SHA-256 hash over a
   canonical (sorted-key, fixed-point) serialization — this is the value that
   will later bind Decisions and Approvals to a specific Intent (PRD §9.1,
   §14.2).
4. `atf-policy::evaluate` loads a Cedar policy set + schema and evaluates the
   Intent's principal/action/resource/context against it, returning a Cedar
   `Decision` (Allow/Deny) plus the policy IDs that fired.
5. `atf-decision` wraps that into ATF's own `Decision` enum
   (`PERMIT`/`DENY`/`REVIEW`/`ERROR`) per PRD §10.2. The full merge algorithm
   in PRD §10.1 (Simulator > Policy forbid > Risk critical > Review
   conditions > Permit) is **not** implemented yet — today a Cedar `Deny`
   maps to `DENY`, a Cedar `Allow` maps to `PERMIT`, and any internal error
   maps to `ERROR` (fail closed, never silently `PERMIT`).
6. `atf-cli evaluate` drives steps 1-5 from the command line and prints the
   resulting `Decision` as JSON.

No Adapter, execution path, wallet integration, or production secret exists
in this repository. Everything above only evaluates; it never signs or
submits a transaction.

## Why these four crates first (PRD §35)

- Core types must stabilize before Adapters are built against them.
- Schema and policy semantics are the project's long-term public contract
  (PRD §37) — get the shape right before adding surface area.
- Shadow Mode (evaluate-only) is strictly simpler than Enforce Mode and
  carries no execution risk, so it comes first.

## Open design gaps tracked for later phases

These are called out explicitly so nobody mistakes today's skeleton for a
complete Decision Engine:

- Decision merge algorithm (PRD §10.1) — Risk and Simulation inputs exist as
  types but aren't consulted yet.
- Policy Bundle versioning/rollback and multi-bundle conflict resolution
  (PRD §11.3).
- Budget model and atomic reserve/commit/release (PRD §9.4).
- Agent identity signature verification (PRD §17.2).
