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
