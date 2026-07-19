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
- **`atf-identity`** — Agent registration records (`AgentRecord`,
  `AgentStatus`) and an in-memory `IdentityRegistry` verifying a raw
  Ed25519 signature over `intent.canonical_hash()`, with key-rotation
  support (multiple valid keys per Agent) and status gating. *Implemented
  as a library — still not called from `services/gateway` (PRD §17.2): the
  gateway now exists, but there is no way to register an Agent's key
  through it yet, which is really an Admin API concern (PRD §17.3).*
- **`atf-policy`** — Cedar schema + minimal
  `evaluate(intent) -> cedar_policy::Response`. *Implemented.*
- **`atf-risk`** — deterministic, stateless MVP risk rules (request expiry,
  single-transaction cap, fee ratio, vendor price deviation, high-risk
  network/protocol). *Implemented (partial — rules needing history/state,
  e.g. duplicate purchase or daily cumulative spend, wait on `atf-audit`
  being queried by `atf-risk`, which doesn't happen yet either).*
- **`atf-audit`** — `AuditEvent`/`EventType` (PRD §16.2) and an in-memory,
  append-only `AuditLedger` that hash-chains events and can `verify_chain()`
  to detect after-the-fact tampering (PRD §16.3). *Implemented as a
  library — no persistent store (PRD's MVP design calls for PostgreSQL);
  now called from `services/gateway`, so it's the first of these two
  "implemented but unwired" crates to actually be wired somewhere.*
- **`atf-decision`** — `Decision` type + the real PRD §10.1 merge algorithm,
  minus the Simulator branch (no `atf-simulator` yet). *Implemented
  (partial).*
- **`cli/atf-cli`** — `atf validate-intent`, `atf evaluate`,
  `atf policy test`. *Implemented.*
- **`services/gateway`** (`atf-gateway`) — an Axum HTTP service:
  `POST /v1/intents` runs Intent validation -> Policy -> (if permitted)
  Risk -> Decision merge, records three audit events per request, and
  stores the Decision; `GET /v1/intents/{id}/decision` retrieves it;
  `/healthz`/`/readyz`. *Implemented — verified against a real bound
  socket, not just in-process tests. Does not call `atf-identity` (see
  above) and has no persistent store (PRD §22): a process restart loses
  every recorded Decision and the whole audit ledger.*

Everything else under `crates/`, `sdk/`, `examples/`, `conformance/`,
`deploy/`, `migrations/`, `fuzz/` is a scaffolded directory with a
`README.md` describing what belongs there and which roadmap phase (PRD §31)
will fill it in. None of it is wired into the Cargo workspace yet.

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
5. If (and only if) Policy did not `forbid`, `atf-risk::evaluate` runs the
   MVP rule set and returns a `Vec<RiskFinding>` (PRD §10.1.2: a denied
   request never reaches Risk scoring).
6. `atf-decision::decide` merges the two into ATF's own `Decision` enum
   (`PERMIT`/`DENY`/`REVIEW`/`ERROR`) per PRD §10.1/§10.2: Cedar `forbid` (or
   default-deny) -> `DENY`; otherwise a `Critical` Risk Finding -> `DENY`, a
   `High` Risk Finding -> `REVIEW`, anything less -> `PERMIT`; any internal
   evaluation error -> `ERROR` (fail closed, never silently `PERMIT`). The
   Simulator branch of §10.1 is not implemented — there is no
   `atf-simulator` yet.
7. `atf-cli evaluate` drives steps 1-6 from the command line and prints the
   resulting `Decision` as JSON. It does not touch `atf-audit` — it's a
   one-shot local tool, not a long-running service with a ledger to keep.
8. `atf-cli policy test` runs the Policy Kernel in isolation (step 4 only)
   against a directory of conformance cases and reports pass/fail — see
   `conformance/policy-tests/README.md`.
9. `schemas/decision.schema.json` describes the shape `atf-decision::Decision`
   serializes to; `atf-decision`'s own test suite (`tests/schema_validation.rs`)
   validates real output of all four decision kinds against it in CI, so the
   schema can't silently drift from the type. `atf-audit` does the same for
   `schemas/audit-event.schema.json`.
10. `services/gateway`'s `POST /v1/intents` is the second caller of steps
    1-6, and the first thing in this repo that also writes to
    `atf-audit::AuditLedger`: it appends `IntentReceived` right after step 2,
    `PolicyEvaluated` right after step 4, and `RiskEvaluated` right after
    step 5 (skipping the Risk call itself when Policy already denied, exactly
    like step 5 does) — then stores the final `Decision` in an in-memory
    map keyed by `intent_id` for `GET /v1/intents/{id}/decision` to return.
    Everything here is in-memory: a process restart loses both the ledger
    and every stored Decision.

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

- Decision merge algorithm (PRD §10.1) — implemented for Policy + Risk;
  the Simulator branch has no input to merge yet (no `atf-simulator`).
- Risk rules that need history/state — daily cumulative spend, first-time
  address, duplicate purchase, order frequency (PRD §12.2) — need
  `atf-risk` to query `atf-audit`, which no code does yet.
- Policy Bundle versioning/rollback and multi-bundle conflict resolution
  (PRD §11.3).
- Budget model and atomic reserve/commit/release (PRD §9.4).
- `atf-identity` is implemented but still unwired: nothing calls
  `IdentityRegistry::verify_intent_signature`, since there is still no way
  to register an Agent's key through `services/gateway` — that needs an
  Admin API (PRD §17.3), which doesn't exist. It also has no key-rotation
  *policy* (expiry windows, forced revocation) — only the mechanism to hold
  multiple keys at once (PRD §17.2.4).
- `services/gateway` has no persistent store: `atf-audit::AuditLedger` and
  the Decision-by-`intent_id` map are both plain in-memory state behind a
  `Mutex`, so a process restart loses everything (PRD §16.3's MVP design
  calls for PostgreSQL). There is also no rate limiting, no TLS termination
  config, and no multi-instance story — this is a reference wiring, not a
  production deployment target.
- `atf-core::sort_json_keys`/`sha256_hex` are shared by `atf-intent` and
  `atf-audit`'s canonical hashing; any future crate that needs a
  deterministic hash over JSON (e.g. a Policy Bundle hash for §11.3
  versioning) should reuse these rather than re-deriving the
  `preserve_order`-feature fix a second time.
