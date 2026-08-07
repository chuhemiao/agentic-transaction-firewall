# ADR-0002: Use transactional PostgreSQL state with per-organization Audit chains

- **Status:** Accepted
- **Date:** 2026-08-07
- **Decision owners:** ATF maintainers
- **Supersedes:** None
- **Related:** [PRD](../PRD.md), [architecture](../architecture.md), [threat model](../threat-model.md), [ADR-0001](0001-durable-shadow-before-enforce.md)

## Context

The reference gateway currently keeps accepted intents, decisions, and the
Audit chain in process memory. That is sufficient for the Phase 1 vertical
slice, but it cannot preserve evidence across restarts, coordinate multiple
gateway replicas, or make idempotent retries safe.

The PRD requires two atomic visibility boundaries:

1. an accepted Intent and its idempotency reservation become durable together;
2. the final Evaluation, Decision, `DecisionRecorded` event, and idempotency
   result become durable together.

It also requires append-only Audit events with deterministic hash chaining,
but leaves the chain scope and concurrency mechanism to an ADR. The Policy and
Risk pipeline may perform CPU-intensive work and, later, external enrichment.
Holding a database transaction open across that work would turn evaluator
latency into lock duration and exhaust the connection pool under load.

This ADR fixes the persistence contract before the schema and repository APIs
are implemented. It describes the target invariant. Individual roadmap items
may land the tables and APIs incrementally, but an incomplete subset is not a
production-ready persistence path.

## Decision

### 1. PostgreSQL is the durable system of record

The reference implementation will use PostgreSQL through SQLx. A new
`crates/atf-store` crate will own:

- SQL and schema-facing types;
- transaction boundaries that span Intent, Evaluation, Decision, Audit, and
  idempotency records;
- row-lock ordering, retry classification, and database error mapping;
- schema compatibility and readiness checks.

Domain crates remain storage-agnostic. The gateway calls coarse-grained store
operations and must not assemble cross-table transactions with direct SQL.
Repositories that expose only one table at a time are insufficient for the
admission and finalization operations below.

PostgreSQL stores accepted Intents, evaluator reservations, immutable
evaluation inputs when available, Evaluations, Decisions, Audit events,
idempotency results, and consumed hashed identity nonces. In-memory
indexes may be caches only; they are never authoritative and cannot authorize
execution after a database error.

### 2. Audit chains are scoped per organization

Each organization has exactly one logical Audit chain:

- `audit_chain_heads` has one row per `organization_id`, containing the last
  committed sequence number and event hash;
- `audit_events` is append-only and has a unique key on
  `(organization_id, sequence)`;
- every event records `organization_id`, `sequence`, `previous_event_hash`,
  `event_hash`, event type, schema version, subject identifiers, timestamp,
  and canonical typed payload;
- the first event uses the protocol-defined genesis predecessor; subsequent
  events use the immediately preceding committed hash for that organization.

An append operation creates the organization's head row if necessary, locks it
with `SELECT ... FOR UPDATE`, derives the next sequence and hash from the locked
state, inserts the event, and advances the head before the transaction commits.
When one state transition emits several events, they are appended in order
while the same head lock is held.

Store transactions acquire the applicable locks in this order:

1. current Agent then exact identity-Key rows for identity admission/mutation;
2. the Nonce/idempotency/Intent/evaluation rows owned by the operation, in
   stable key order when there is more than one;
3. the single organization Audit head, last.

No operation may first lock an Audit head and then wait for a business row.
This consistent order limits deadlock cycles. A transaction must never touch
Audit heads belonging to more than one organization.

The store uses PostgreSQL `READ COMMITTED` isolation plus explicit row locks,
unique constraints, and conditional updates. It does not rely on a process
mutex, PostgreSQL advisory locks, or global `SERIALIZABLE` isolation for chain
correctness. Lock and statement timeouts are finite.

### 3. Evaluation uses two critical atomic visibility boundaries

The two boundaries are separate, short transactions. Policy and Risk work is
performed between them without an open database transaction.

#### Transaction A: durable admission

After request parsing, schema and semantic validation, authenticated admission
locks and reverifies the current Agent/exact Key and atomically:

1. verifies the canonical signed Envelope and binds the immutable hashed Nonce
   to the exact Key, Intent, idempotency tuple and identity lifecycle evidence;
2. binds the unique `(organization_id, idempotency_key)` to the canonical
   Intent hash and creates the evaluator reservation;
3. inserts the immutable canonical Intent and its hash;
4. appends `IntentReceived` and `IdentityVerified`; and
5. materializes `IDENTITY_VERIFIED/v2`.

Signature decoding happens outside the transaction, but Transaction A rechecks
the referenced key's current version/status and consumes the Nonce in the same
transaction as the Intent/idempotency insert. A rejected or unverifiable identity is not an
accepted Intent; if it is auditable, it uses a separate short audit-only
transaction and cannot create a successful idempotency result.

The transaction commits before Policy or Risk evaluation begins. A successful
admission therefore means the system can recover the work after the serving
process exits.

#### Evaluation: outside a database transaction

The evaluator loads the admitted immutable input and performs Policy and Risk
work without holding row locks. Short supporting transactions are allowed for
lease renewal and for persisting an immutable Evaluation Context snapshot;
they do not weaken the two critical atomic boundaries or make a partial final
result visible.

Once Evaluation Context persistence is implemented, the evaluator must pin and
persist all inputs that affect a decision—including evaluation time, policy
version, risk/model versions, FX and sanctions snapshot identifiers, feature
flags, and relevant freshness metadata—before computing the final result.

#### Transaction B: durable finalization

Finalization locks the reservation/evaluation rows, validates the expected
lifecycle state and evaluator fencing token, and atomically:

1. inserts the Evaluation and module outputs or deterministic error evidence;
2. inserts the final Decision and advances the lifecycle state;
3. appends the typed Policy, Risk, and `DecisionRecorded` Audit events required
   for the result;
4. stores the completed idempotency response.

An `ERROR` caused by a Policy or Risk failure is still a final Decision and is
committed with its evidence when PostgreSQL is available. Any database or Audit
append failure rolls back the entire finalization. The gateway returns a final
decision only after Transaction B commits, and read APIs expose only committed
results.

### 4. Idempotency reservations are leased and fenced

The durable reservation records at least:

- organization and idempotency key;
- canonical Intent hash;
- state (`IN_PROGRESS`, `COMPLETED`, or terminal failure as the schema evolves);
- opaque lease owner;
- monotonically increasing lease generation;
- lease expiry based on the database clock;
- committed result reference when complete.

The behavior is:

- same key and same hash with a completed result returns the original result;
- same key and a different hash is a conflict and never rebinds the key;
- same key and same hash with an active lease reports bounded in-progress state
  rather than starting another evaluator;
- an expired lease may be claimed only by a conditional update that increments
  the lease generation;
- finalization succeeds only for the current owner and generation.

The generation is the fencing token. An old evaluator that resumes after its
lease expires cannot overwrite or supplement the new evaluator's result even
if its local clock or network view was stale. Lease heartbeats use independent
short transactions.

Before immutable Evaluation Context snapshots are available, expired work must
fail closed to a durable `ERROR` rather than be recomputed with possibly newer
policies, clocks, or enrichment data. After snapshots are available, recovery
must reuse the original evaluation identity and pinned inputs. It must never
silently substitute the current policy, current time, or current external data.

### 5. Failure behavior is explicit and fail closed

- PostgreSQL unavailable before admission: return an unavailable/error response
  and do not evaluate or authorize the Intent.
- Process crash after Transaction A and before Transaction B: leave no visible
  final Decision; a later worker may recover only through the fenced lease
  protocol.
- Audit append failure during either critical transaction: roll back the state
  transition paired with that event.
- Process crash after Transaction B commits but before the HTTP response: a
  retry with the same key and hash returns the committed original result.
- Deadlock, lock-timeout, serialization, or connection errors: retry only a
  bounded number of times and only through an idempotent store operation;
  exhaustion returns the restrictive unavailable/error outcome.
- Corrupt rows, an incompatible schema version, or an unverifiable Audit head:
  fail readiness and deny state-changing service until repaired.

The current reference architecture does not use the PRD's optional Shadow-mode
local buffer. Database loss therefore pauses both Shadow and Enforce admission.
A durable local buffer, its ordering rules, and reconciliation protocol require
a separate ADR before implementation.

### 6. Schema evolution and cutover are forward-only

- Migrations are ordered, reviewed, and applied once. Runtime application roles
  do not receive schema-changing privileges.
- New persisted formats are additive and versioned. Readers may tolerate
  explicitly supported older versions; writers emit the current version.
- Committed Intent canonical bytes, hashes, Decisions, and Audit events are
  never rewritten by a migration.
- Destructive down-migrations are not part of incident recovery. Rollback means
  restoring a database snapshot when data changed, or rolling the application
  back only while the additive schema remains backward compatible.
- Startup/readiness verifies the supported schema range. An incompatible binary
  fails closed before serving state-changing endpoints.
- The in-memory Phase 1 ledger is not migrated and is not dual-written. The
  durable gateway cutover starts from an explicitly provisioned database and
  has one authoritative write path.

The migration series may introduce supporting tables incrementally. Until the
idempotency, fencing, and atomic finalization pieces are connected, that series
does not satisfy this ADR's release boundary.

## Required invariants

Implementations and integration tests must demonstrate all of these:

1. **Accepted means durable:** no accepted Intent exists without its immutable
   record, idempotency binding, lifecycle state, and admission Audit evidence.
2. **One binding:** an organization/idempotency key can bind to only one
   canonical Intent hash.
3. **Evidence-complete result:** no queryable or returned final Decision exists
   without its Evaluation evidence, `DecisionRecorded` event, and completed
   idempotency result.
4. **No fork:** two committed events in one organization cannot claim the same
   sequence or predecessor.
5. **Tenant isolation:** activity in one organization cannot change or lock the
   chain head of another organization.
6. **Fenced completion:** a stale evaluator generation cannot finalize.
7. **Deterministic recovery:** recovered work uses the admitted immutable input
   and pinned Evaluation Context, or terminates with a restrictive error.
8. **No evaluation transaction:** Policy, Risk, and external calls run without
   an open admission or finalization transaction.
9. **Rollback together:** a failed Audit append makes its paired state change
   invisible.
10. **Committed-only reads:** restart and multi-replica reads never synthesize a
    result from uncommitted or cache-only state.

## Alternatives considered

### One global Audit chain

Rejected. It provides a simple total order but makes every tenant contend on
one row and couples one noisy organization to all others. A per-organization
chain preserves the required tenant history while allowing independent appends.
Cross-organization checkpoints can be added later without changing stored
events.

### PostgreSQL advisory locks

Rejected. They are application-enforced, are not represented by the protected
row, and session-level variants do not follow transaction rollback. A locked
chain-head row makes the serialization point explicit and recoverable.

### One long transaction around evaluation

Rejected. External latency would retain connections and locks, increase
deadlock exposure, and make crash recovery depend on abandoned sessions rather
than durable ownership.

### Separate commits for Decision and Audit

Rejected. Either commit order permits a crash to create an authorized Decision
without evidence or evidence for a Decision that never became visible.

### In-memory fallback or database dual-write

Rejected. Two authorities create divergent decisions, idempotency answers, and
chain heads during partitions. Caches may accelerate reads but cannot accept or
finalize work.

### Buffer Audit events locally during database loss

Deferred. It can improve Shadow availability, but correctness requires a
durable ordered queue, capacity policy, integrity protection, and a conflict
reconciliation protocol. None is currently specified.

### `SERIALIZABLE` for every transaction

Rejected as the default. The current invariants operate on predetermined rows
and are enforced directly by row locks, unique constraints, and conditional
updates under `READ COMMITTED`. A future invariant that spans predicates may
justify stronger isolation for that operation and must include retry behavior.

## Consequences

Positive consequences:

- restart and multi-replica behavior has one source of truth;
- Audit ordering is deterministic without a process-global mutex;
- a final response cannot outrun its durable evidence;
- evaluator crashes can be recovered without allowing stale completion;
- most organizations append independently.

Costs and residual risks:

- PostgreSQL becomes an availability dependency, including in Shadow mode;
- one very active organization serializes its own Audit appends on one head;
- deadlocks remain possible if future code violates the lock order;
- database administrators can still tamper with stored history, so least-
  privilege roles and external checkpoints remain required defense in depth;
- deterministic recovery remains intentionally restrictive until Evaluation
  Context snapshots are implemented.

## Implementation sequence

- `DS-002`: add `atf-store`, the migration runner, base tables, constraints,
  and schema compatibility metadata.
- `DS-003`: implement row-locked per-organization Audit appends and concurrent
  no-fork tests.
- `DS-004`: add coarse-grained admission and finalization transaction APIs.
- `DS-005`: cut the gateway over to the single durable write path and prove
  restart survival.
- `DS-012`: implemented persistent organization/key bindings, database-clock
  leases, renewal/reclaim, monotonically increasing fencing generations,
  immutable completed results, and atomic admission/finalization integration.
- `DS-013`: implemented verified original-Decision return, active-work 409,
  stage-boundary lease renewal, concurrent single-result convergence and
  request-driven fail-closed crash recovery through the DS-012 primitives.
- `DS-014`: implemented canonical domain-separated Identity Envelope bytes,
  pure scope/time validation, exact Key ID selection and strict Ed25519
  verification without a raw-hash fallback.
- `DS-015`: implemented Agent and Key lifecycle plus offline provisioning in
  migration 0004, with atomic typed Audit evidence and verified restart reads.
- `DS-016`: implemented current identity-key recheck, immutable hashed Nonce
  consumption and typed verified/rejected/replay evidence in migration 0005.
- `DS-023`: persist immutable Evaluation Context inputs for deterministic
  crash recovery and replay.

## References

- [PostgreSQL explicit locking](https://www.postgresql.org/docs/current/explicit-locking.html)
- [PostgreSQL transaction isolation](https://www.postgresql.org/docs/current/transaction-iso.html)
- [PostgreSQL `INSERT`](https://www.postgresql.org/docs/current/sql-insert.html)
