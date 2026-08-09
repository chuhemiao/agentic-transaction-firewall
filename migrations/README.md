# PostgreSQL migrations

`atf-store-migrate` embeds and applies the ordered SQLx migrations in this
directory. Migrations are forward-only: committed canonical documents, hashes,
Decisions, and Audit events must never be rewritten by a rollback.

Migration 0001 creates the schema metadata, organizations, Intents,
Evaluations, Decisions, per-organization Audit heads, and append-only Audit
events. Canonical documents retain both JSONB and exact canonical bytes beside
their SHA-256 hashes. Composite foreign keys prevent cross-tenant references.
`atf-store` extends this schema through a `SELECT ... FOR UPDATE` chain-head
writer and a consistent-snapshot verifier; callers cannot choose sequence,
predecessor, or event hash.

Migration 0002 adds the DS-007 materialized Intent lifecycle state, optimistic
version, contract version, last state-producing Audit event pointer, and update
timestamp. Existing rows are backfilled as compatibility contract version 0;
their immutable Audit bytes are not rewritten. New repository writes use the
typed, replayable contract version 1.

Migration 0003 adds the DS-012 idempotency reservation table. Each
`(organization_id,idempotency_key)` is immutably bound to one Intent hash;
`IN_PROGRESS` rows carry a database-clock lease owner/generation/expiry, and
`COMPLETED` rows additionally bind the Evaluation, Decision and Decision hash.
Triggers reject binding changes, completed-row updates, deletion and truncate.
Historical final Decisions are backfilled as completed; unfinished historical
admissions receive an expired generation-1 lease. DS-013 request-driven
recovery must increment that generation and records only a fenced fail-closed
Decision; migration 0008 now requires an immutable Evaluation Context for new
recovery outputs. Canonical Intent/Decision/Audit bytes are not rewritten.

Migration 0004 adds DS-015 organization-scoped Agent and exact Ed25519
identity-key lifecycle. Canonical records, exact bytes, hashes, monotonic
versions and last-event pointers make typed operator Audit evidence mandatory.
Only public keys are stored. Agent registration bindings and key material/time
windows are immutable; terminal Agents, revoked Keys, row deletion and table
truncate are database-guarded. Existing Intent/Decision/Audit bytes are not
rewritten.

Migration 0005 adds DS-016 immutable hashed Agent Nonce consumption. Each row
binds the organization, Agent, exact Key, Envelope hash, Intent hash,
idempotency reservation and `IdentityVerified` event/lifecycle versions.
Database guards reject rebinding, deletion and truncate; raw Nonces, Envelopes
and signatures are never stored.

Migration 0006 adds DS-018 PostgreSQL-authoritative Operator subjects and
organization roles. Only a domain-separated external-subject fingerprint is
stored. Canonical Operator/role records, exact bytes, hashes, monotonic
lifecycle versions and typed Audit pointers make registration, status,
grant/revoke and regrant verifiable after restart. Immutable issuer/subject
bindings and database guards reject rebinding, deletion and truncate.

Migration 0007 adds DS-020 immutable signed Policy Bundle artifacts and one
explicit active pointer per organization/environment/Bundle ID. Exact archive
bytes, archive/public-key hashes, detached Ed25519 proof and typed install
Audit evidence are immutable. Pointer updates are monotonic, always retain the
immediately prior installed version for rollback, and must reference the same
transaction's `PolicyChanged` event. Only publisher public keys are persisted;
private signing keys remain external.

Migration 0008 adds DS-023 immutable Evaluation Context snapshots. Each new
Intent may have exactly one authoritative context, and every row retains exact
canonical bytes plus redundant organization/Evaluation/Intent/hash/time fields
for fail-closed verification. Composite foreign keys bind the exact Intent
hash; a deferred foreign key requires the same transaction's typed
`ContextEnriched` event. Final Evaluations may bind the context hash while
legacy schema-v1 Evaluation rows remain readable without one. Update, delete
and truncate are rejected; canonical Intent/Evaluation/Decision/Audit bytes
are never rewritten.

Migration 0009 adds DS-026 organization/environment-scoped immutable Risk
Rule Set archives. Canonical JSON and exact bytes are stored beside the raw
artifact hash and domain-separated Rule Set hash. Each installation requires
current Policy-change authority and a same-transaction typed
`RiskRuleSetStored` event. Update, delete and truncate are rejected so
Original Replay can load the exact Risk behavior named by an Evaluation
Context after restart.

Migration 0010 adds DS-027 immutable Counterfactual Replay records outside the
authoritative Evaluation/Decision tables. Each row binds new Context,
Evaluation and Decision IDs plus exact canonical bytes/hashes to the original
Evaluation/Decision, explicitly selected signed Policy/Risk artifacts, current
Operator and one same-transaction `CounterfactualReplayCompleted` event.
Foreign keys, closed outcome checks and mutation/delete/truncate guards enforce
tenant isolation, `authoritative = false`, exact changed-outcome reporting and
non-overwrite semantics.

Migration 0011 adds DS-028's partial expression index over prior
`DecisionRecorded(PERMIT)` evidence, ordered by organization, Agent, resource,
occurrence time and sequence. Store uses it to capture or reconstruct an exact
repeatable-read Risk-history snapshot without supplying the full Audit chain
to the evaluator. Schema compatibility advances to reader/writer version 11.

Migration 0012 adds DS-029's partial expression index over prior
`DecisionRecorded(PERMIT)` evidence by organization, Agent, occurrence time,
sequence and bound execution asset. Store captures or reconstructs the daily
window at the same repeatable-read repository boundary, uses PostgreSQL
`NUMERIC` for fixed-point grouping, retains a count of legacy rows without a
bound asset and fails closed above 256 asset groups. Schema compatibility
advances to reader/writer version 12.

```bash
DATABASE_URL=postgres://... cargo run -p atf-store --bin atf-store-migrate
```

The migration integration test requires a PostgreSQL administrative URL whose
role may create temporary databases and roles:

```bash
ATF_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
  cargo test -p atf-store --test migrations

ATF_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
  cargo test -p atf-store --test audit_postgres
```

The authoritative transaction, per-organization chain, evaluator recovery,
and migration-compatibility contract is
[`ADR-0002`](../docs/decisions/0002-durable-state-contract.md).
