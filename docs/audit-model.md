# ATF Lifecycle and Audit Model

Status: DS-006 domain contract

Version: 1

Authority: `docs/PRD.md` §16, ADR-0002, and `tasks/plan.md` DS-006

## Objective

Define one stable, fail-closed Intent lifecycle and versioned Audit payload
contract before PostgreSQL begins enforcing lifecycle state in DS-007. The
model must make skipped work explicit, make every state change attributable to
one typed event, and prevent an invalid, backward, or post-terminal transition
from being interpreted as progress.

This document specifies domain behavior only. DS-007 will add persisted state,
optimistic versioning/locking, and atomic state-plus-Audit transitions. It must
reuse this model rather than define a second transition table in SQL or the
Gateway.

## Technology, structure, and commands

- `crates/atf-core/src/lifecycle.rs`: shared states and pure transition
  validator; no transport or storage dependency.
- `crates/atf-audit/src/payload.rs`: version-1 typed payloads and event-to-state
  effects.
- `crates/atf-audit/src/event.rs`: canonical event envelope and typed
  constructor/parser.
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
  -> IDENTITY_VERIFIED
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

## Explicit module outcomes

`NOT_RUN` is a module outcome, not an Intent lifecycle state. A generic
`NOT_RUN` state would be ambiguous when Risk and Simulation are both skipped
and would permit repeated self-transitions.

- Policy is security-required and records `SUCCEEDED` or `ERROR` only.
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
| `IdentityRejected` | `RECEIVED -> IDENTITY_REJECTED` |
| `PolicyEvaluated` | `IDENTITY_VERIFIED -> POLICY_EVALUATED` |
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
| `ContextEnriched`, `ServiceDelivered`, Budget, Policy, Agent, and Kill Switch events | typed non-state evidence; lifecycle state is unchanged |

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
| Identity verified/rejected | organization, Agent, key/envelope evidence or stable rejection code |
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
| Kill Switch | scope, actor ID, and stable reason code |
| Intent expired/cancelled | stable reason code and, for cancellation, actor ID |

Free-form human messages may be stored in a separate future descriptive field,
but state changes and decision evidence use stable codes and typed fields. Raw
payload construction remains only as an explicit legacy compatibility escape
hatch; the Gateway/store admission and finalization path uses typed payloads.

## Testing and security boundaries

Always:

- exhaustively test the allowed transition table and the complement of invalid
  state pairs;
- test every terminal state against every possible next state;
- serialize real Rust payloads through the canonical Audit envelope and
  validate them against the JSON Schema;
- reject event/payload mismatches, unsupported payload versions, unknown
  fields, empty identifiers, and malformed hashes;
- preserve canonical bytes for already supported legacy event names.

Never:

- infer a transition from arbitrary `data` keys;
- treat an unknown event, state, outcome, or payload version as non-state or
  successful;
- let an administrative event advance an Intent;
- let `NOT_RUN` imply success or authorize execution;
- add database state enforcement in this task; DS-007 must do that atomically.

Threats addressed are Audit payload confusion/tampering, backward or
post-terminal state advancement, ambiguous skipped modules, and repudiation
caused by free-form decision evidence. Authentication, RBAC, rate limits,
external checkpoints, and database lifecycle race enforcement remain tracked
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

There are no open DS-006 design questions. Transactional persistence and
concurrency semantics remain deliberately deferred to DS-007.
