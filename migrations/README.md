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
Decision while Evaluation Context snapshots are unavailable. Canonical
Intent/Decision/Audit bytes are not rewritten.

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
