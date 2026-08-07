# ATF Lifecycle and Audit Model

Status: DS-015 transactional Intent and identity lifecycle contract

Version: 3

Authority: `docs/PRD.md` §16–17, ADR-0002, and `tasks/plan.md` DS-006/DS-007/DS-015

## Objective

Define one stable, fail-closed Intent lifecycle and versioned Audit payload
contract, then persist and replay that contract in PostgreSQL. The model makes
skipped work explicit, makes every state change attributable to one typed
event, and prevents invalid, stale, backward, partial, or post-terminal
transitions from being interpreted as progress.

The Rust lifecycle module remains the only transition table. PostgreSQL stores
the materialized state, optimistic version, contract version, and last
state-producing Audit event. Repository transactions validate the Rust
contract, append typed evidence, and update the materialized state atomically.

## Technology, structure, and commands

- `crates/atf-core/src/lifecycle.rs`: shared states and pure transition
  validator; no transport or storage dependency.
- `crates/atf-audit/src/payload.rs`: version-1 typed payloads and event-to-state
  effects.
- `crates/atf-audit/src/event.rs`: canonical event envelope and typed
  constructor/parser.
- `crates/atf-store/src/lifecycle.rs`: transactional replay and persistence
  boundary.
- `migrations/0002_intent_lifecycle.sql` and `migrations/0004_identity.sql`:
  additive Intent and identity lifecycle schemas.
- `schemas/audit-event.schema.json`: wire-level validation matching the Rust
  types.
- `crates/atf-core/tests/lifecycle.rs` and
  `crates/atf-audit/tests/schema_validation.rs`: executable contract evidence.

```bash
cargo test -p atf-core --test lifecycle
cargo test -p atf-audit --test schema_validation
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo deny check
```

Rust enum variants use PascalCase; lifecycle states and module outcomes use
`SCREAMING_SNAKE_CASE` on the wire; Audit event types retain their existing
PascalCase wire names. Payload objects contain `schema_version: 1`, reject
unknown fields, and use non-empty identifiers plus 64-character lowercase
SHA-256 hex strings where a hash is required.

## Intent lifecycle

The stable state set is:

```text
RECEIVED
  -> IDENTITY_VERIFIED | IDENTITY_UNVERIFIED
       -> POLICY_EVALUATED
            -> RISK_EVALUATED
                 -> SIMULATION_COMPLETED
                      -> DECIDED_PERMIT
                      -> DECIDED_REVIEW
                      -> DECIDED_DENY       (terminal)
                      -> DECIDED_ERROR      (terminal)
  -> IDENTITY_REJECTED                      (terminal)

DECIDED_PERMIT -> APPROVAL_PENDING | EXECUTION_AUTHORIZED
DECIDED_REVIEW -> APPROVAL_PENDING
APPROVAL_PENDING -> APPROVED | REJECTED     (REJECTED terminal)
APPROVED -> EXECUTION_AUTHORIZED
EXECUTION_AUTHORIZED -> EXECUTION_SUBMITTED
EXECUTION_SUBMITTED -> EXECUTION_CONFIRMED | EXECUTION_FAILED
EXECUTION_CONFIRMED -> SETTLEMENT_VERIFIED | RECONCILIATION_FAILED
```

`EXECUTION_FAILED`, `SETTLEMENT_VERIFIED`, and `RECONCILIATION_FAILED` are
terminal. `EXPIRED` and `CANCELLED` are terminal exits allowed only before an
execution is submitted. No state permits a self-transition or backward
transition. A current Shadow evaluation may stop durably at
`DECIDED_PERMIT`, `DECIDED_REVIEW`, `DECIDED_DENY`, or `DECIDED_ERROR`; the
absence of later modules does not make a Permit or Review terminal in the
long-term state machine.

`IDENTITY_UNVERIFIED` is the explicit compatibility branch for the current
Shadow-only Gateway, where an Identity verifier is not yet wired. It records
that the phase was skipped; it is not identity assurance and cannot authorize
execution. DS-016 replaces this branch with `IDENTITY_VERIFIED` for verified
requests. A valid lifecycle transition is necessary but never sufficient for
an execution grant: later Decision binding and the Enforce path must require
the verified identity evidence referenced by that grant.

## Explicit module outcomes

`NOT_RUN` is a module outcome, not an Intent lifecycle state. A generic
`NOT_RUN` state would be ambiguous when Risk and Simulation are both skipped
and would permit repeated self-transitions.

- Policy is security-required and records `SUCCEEDED` or `ERROR` only.
- Identity records `IdentityVerified`, `IdentityRejected`, or the explicit
  `IdentityVerificationSkipped` compatibility event. A skipped identity phase
  is allowed only for non-executable Shadow evaluation.
- Risk records `SUCCEEDED`, `ERROR`, or `NOT_RUN`. Policy denial is a valid
  reason for Risk `NOT_RUN`.
- Simulation records `SUCCEEDED`, `ERROR`, or `NOT_RUN`. Until a Simulator is
  wired, every request records a reason-coded Simulation `NOT_RUN` outcome.
- A skipped or errored module still advances through its phase event, so the
  final Decision is reached through one unambiguous path. An `ERROR` outcome
  can only result in `DECIDED_ERROR`; it must never be coerced to Permit.

Success, error, and not-run outcomes are distinct tagged variants. They cannot
carry contradictory fields such as both a result and an error.

## Event-to-lifecycle mapping

| Typed event | State effect |
|---|---|
| `IntentReceived` | initialize `RECEIVED`; invalid if a state already exists |
| `IdentityVerified` | `RECEIVED -> IDENTITY_VERIFIED` |
| `IdentityVerificationSkipped` | `RECEIVED -> IDENTITY_UNVERIFIED` |
| `IdentityRejected` | `RECEIVED -> IDENTITY_REJECTED` |
| `PolicyEvaluated` | Verified/Unverified identity -> `POLICY_EVALUATED` |
| `RiskEvaluated` | `POLICY_EVALUATED -> RISK_EVALUATED` |
| `SimulationCompleted` | `RISK_EVALUATED -> SIMULATION_COMPLETED` |
| `DecisionRecorded(PERMIT)` | `SIMULATION_COMPLETED -> DECIDED_PERMIT` |
| `DecisionRecorded(REVIEW)` | `SIMULATION_COMPLETED -> DECIDED_REVIEW` |
| `DecisionRecorded(DENY)` | `SIMULATION_COMPLETED -> DECIDED_DENY` |
| `DecisionRecorded(ERROR)` | `SIMULATION_COMPLETED -> DECIDED_ERROR` |
| `ApprovalRequested` | Permit/Review -> `APPROVAL_PENDING` |
| `ApprovalApproved` | `APPROVAL_PENDING -> APPROVED` |
| `ApprovalRejected` | `APPROVAL_PENDING -> REJECTED` |
| `ExecutionGrantIssued` | Permit/Approved -> `EXECUTION_AUTHORIZED` |
| `ExecutionSubmitted` | `EXECUTION_AUTHORIZED -> EXECUTION_SUBMITTED` |
| `ExecutionConfirmed` | `EXECUTION_SUBMITTED -> EXECUTION_CONFIRMED` |
| `ExecutionFailed` | `EXECUTION_SUBMITTED -> EXECUTION_FAILED` |
| `SettlementVerified` | `EXECUTION_CONFIRMED -> SETTLEMENT_VERIFIED` |
| `ReconciliationFailed` | `EXECUTION_CONFIRMED -> RECONCILIATION_FAILED` |
| `IntentExpired` | any explicitly expirable state -> `EXPIRED` |
| `IntentCancelled` | any explicitly cancellable state -> `CANCELLED` |
| `AgentRegistered`, `AgentStatusChanged`, `IdentityKeyRegistered`, `IdentityKeyRevoked` | typed Agent/Key lifecycle evidence; Intent lifecycle state is unchanged |
| `ContextEnriched`, `ServiceDelivered`, Budget, Policy, `AgentPaused`, and Kill Switch events | typed non-state evidence; Intent lifecycle state is unchanged |

Previously published `ApprovalGranted`, `ExecutionRequested`, and
`KillSwitchTriggered` wire variants remain decodable for Audit hash stability.
They are legacy untyped/non-state events and must not be emitted by new
decision paths. Canonical new producers use `ApprovalApproved`,
`ExecutionGrantIssued`, `KillSwitchEnabled`, or `KillSwitchDisabled`.

## Version-1 payload fields

Every row below also carries `schema_version: 1`.

| Event family | Required typed fields |
|---|---|
| Intent received | organization, Agent, idempotency key, Intent hash, amount, resource |
| Identity verified/rejected/skipped | organization, Agent, key/envelope evidence, stable rejection code, or stable skip code |
| Context enriched | context hash and source IDs |
| Policy evaluated | required-module outcome and matched policy IDs |
| Risk evaluated | optional-module outcome containing typed finding code/severity entries |
| Simulation completed | optional-module outcome containing a typed SAFE/REVIEW/UNSAFE result |
| Decision recorded | organization, Agent, Intent/Evaluation/Decision IDs and hashes, Decision kind, action/resource/amount evidence |
| Approval | approval/Decision IDs, required roles or approver plus stable rejection code |
| Execution | grant/execution/adapter IDs, request/result hashes, expiry, or stable failure code |
| Settlement/service/reconciliation | execution ID plus settlement/delivery hash or stable failure code |
| Budget | budget/reservation IDs, fixed-point amount string, and asset identifier |
| Policy changed | bundle ID/hash and actor ID |
| Agent paused | organization/Agent/actor IDs and stable reason code |
| Agent registered/status changed | organization/Agent, canonical record hash, lifecycle version, actor, status and optional previous status/reason |
| Identity key registered/revoked | organization/Agent/exact Key ID, public-key fingerprint, canonical key-record hash, lifecycle version, actor, validity window or revocation/reason; never raw/private key bytes |
| Kill Switch | scope, actor ID, and stable reason code |
| Intent expired/cancelled | stable reason code and, for cancellation, actor ID |

Free-form human messages may be stored in a separate future descriptive field,
but state changes and decision evidence use stable codes and typed fields. Raw
payload construction remains only as an explicit legacy compatibility escape
hatch; the Gateway/store admission and finalization path uses typed payloads.

## DS-007 persisted lifecycle contract

Each Intent row stores these lifecycle fields:

| Field | Meaning |
|---|---|
| `lifecycle_state` | Materialized current state from the Rust lifecycle enum |
| `lifecycle_version` | Monotonic count of state-producing events; admission starts at 1 |
| `lifecycle_contract_version` | `1` for the typed/replayable DS-007 contract; `0` for migrated compatibility rows |
| `lifecycle_event_id` | Audit event that established the materialized state |
| `lifecycle_updated_at` | Database timestamp of the last state transition |

New rows must use contract version 1. Migrated pre-DS-007 rows use contract
version 0 because their historical free-form evidence cannot be made typed by
rewriting immutable Audit bytes. Compatibility rows remain readable, but no
reader may report that they satisfy the replayable contract.

### Admission transaction

The repository creates the idempotency reservation, Intent row, initial
`RECEIVED` state/version, and typed `IntentReceived` Audit event in one
transaction. The stored event pointer must reference that event. Failure of any
write rolls back the entire admission; a caller can never observe an Intent
without its initial evidence or initial state without its Intent.

### Evaluation finalization transaction

Policy and Risk may run outside a database transaction. Finalization is a
single repository transaction which:

1. locks the Intent and checks the caller's expected lifecycle version;
2. validates typed Identity, Policy, Risk, Simulation, and Decision outcomes
   and their cross-field consistency;
3. appends each typed event in canonical phase order and advances the same
   Rust lifecycle state after each event;
4. inserts the immutable Evaluation and Decision rows;
5. updates the materialized state/version/event pointer; and
6. stores the completed idempotency response.

Concurrent finalizers using the same expected version cannot both succeed.
The stale writer returns a lifecycle conflict and commits no Evaluation,
Decision, Audit event, state update, or idempotency result.

### Reader replay and append boundary

For contract-version-1 rows, repository reads replay all state-producing typed
events for the Intent and compare the resulting state, transition count, and
last event ID with the materialized columns. A missing, unknown, malformed,
out-of-order, or legacy lifecycle payload fails closed as durable-state
corruption. Contract-version-0 rows use the documented compatibility reader
and are never silently promoted.

The generic append API rejects Intent lifecycle events. Those events may only
be emitted by repository operations that update state in the same transaction.
Typed non-state operational and administrative events remain appendable by the
generic API.

### Failure rules

- Policy or Risk evaluation failure is durable evidence, not an omitted phase:
  when PostgreSQL is healthy, typed `ERROR` evidence and `DECIDED_ERROR` commit
  together.
- Simulation that is not wired records typed `NOT_RUN` evidence with a stable
  reason code.
- An Audit append, state update, Evaluation/Decision insert, or idempotency
  completion failure rolls back the finalization batch and leaves the prior
  durable state for safe retry/recovery.
- If PostgreSQL itself is unavailable, the Gateway fails closed. It cannot
  claim a durable error Decision when no durable evidence could be committed.
- The current Shadow result conveys no execution authority, especially when
  its identity state is `IDENTITY_UNVERIFIED`.

## Testing and security boundaries

Always:

- exhaustively test the allowed transition table and the complement of invalid
  state pairs;
- test every terminal state against every possible next state;
- serialize real Rust payloads through the canonical Audit envelope and
  validate them against the JSON Schema;
- replay lifecycle events and compare state, version, and event pointer on
  every contract-version-1 read;
- race concurrent finalizers and prove exactly one expected-version writer
  succeeds;
- inject a failure in the middle of a finalization batch and prove every write
  in that batch rolls back;
- reject event/payload mismatches, unsupported payload versions, unknown
  fields, empty identifiers, and malformed hashes;
- preserve canonical bytes for already supported legacy event names.

Never:

- infer a transition from arbitrary `data` keys;
- treat an unknown event, state, outcome, or payload version as non-state or
  successful;
- let an administrative event advance an Intent;
- let `NOT_RUN` imply success or authorize execution;
- append an Intent lifecycle event without changing persisted state in the same
  transaction.

Threats addressed are Audit payload confusion/tampering, backward or
post-terminal state advancement, stale-writer races, state/event split brain,
partial evidence batches, ambiguous skipped modules, fabricated identity
assurance, and repudiation caused by free-form decision evidence.
Authentication, RBAC, rate limits, and external checkpoints remain tracked in
later tasks.

## Success criteria

1. Every allowed transition is explicit and every other pair fails closed.
2. All terminal states reject every further transition.
3. Every canonical lifecycle event has a typed version-1 payload and maps to
   initialization, one valid state transition, or an explicit non-state effect.
4. Rust serialization and `schemas/audit-event.schema.json` reject mismatched
   or malformed typed payloads.
5. Current durable `IntentReceived` and `DecisionRecorded` producers no longer
   assemble free-form JSON payloads.
6. Admission and finalization make state plus matching typed Audit evidence
   atomically visible, or make none of the attempted writes visible.
7. Optimistic version checks and row locking prevent two stale writers from
   advancing the same Intent.
8. Contract-version-1 reads replay typed evidence and reject any mismatch with
   materialized lifecycle state, version, or last event ID.

There are no open DS-007 Intent or DS-015 Agent/Key lifecycle persistence
questions. Gateway identity/Nonce verification, Decision/execution binding,
and Enforce authorization remain explicit later milestones and must preserve
this contract.
