# Durable Agent and Key Identity

This document fixes the DS-015 persistence and offline provisioning contract.
It builds on the cryptographic Envelope in `docs/identity-envelope.md`.
DS-016 now consumes this durable authority through the Gateway contract in
`docs/gateway-identity.md`; this document remains the operator/lifecycle side.

## Objective

PostgreSQL is the sole authority for Agent registration, Agent status and
Ed25519 identity-key lifecycle. Every mutation commits its new state and one
typed organization-scoped Audit event in the same transaction. A restarted
process can reload the exact Agent and declared Key, verify their canonical
records against the durable Audit chain, and then use `atf-identity` to enforce
their validity at an explicit verification time.

Initial operators use a local CLI with `DATABASE_URL`; DS-015 deliberately
introduces no Admin HTTP endpoint or network credential model. DS-018 adds a
separate offline `atf operator` lifecycle plus the
[`ADR-0003`](decisions/0003-operator-authentication.md) short-lived
Gateway-validated JWT and durable ATF organization-role boundary for Decision
reads; it does not turn Agent keys into Operator credentials.

The two identity systems remain deliberately disjoint. This document's Agent
Key proves one bounded signed Intent and cannot produce operator authority.
ADR-0003's operator subject proves a human/service caller for an explicit role
matrix and cannot replace the Agent Envelope or Nonce admission contract.

## Public seams

- `atf-identity::AgentRecord::validate` and `canonical_hash` define the durable
  Agent-record boundary.
- `atf-identity::IdentityKeyRecord` and `IdentityRegistry::register_key` define
  exact-key lifecycle verification.
- `atf_store::Store` exposes provision, status-change, key-registration,
  key-revocation and verified snapshot-load operations.
- `atf identity ...` exposes the same mutations to a local operator. The
  database URL is read only from `DATABASE_URL`, not a command argument.

Tests observe these public seams. They do not inspect private helper calls.

## Durable records

An Agent row stores every PRD section 17.1 field plus canonical JSON, exact
canonical bytes, a SHA-256 record hash, a monotonically increasing lifecycle
version and the Audit event that produced the current version. Agent IDs are
organization-scoped. `REVOKED` and `EXPIRED` are terminal; `ACTIVE`,
`SHADOW_ONLY` and `PAUSED` may transition among one another or into a terminal
state. Repeating the current status is rejected as an invalid transition.

An identity-key row is addressed by `(organization_id, agent_id, key_id)` and
stores only:

- algorithm `ED25519`;
- the 32-byte public key and its lowercase SHA-256 fingerprint;
- `activates_at`, optional exclusive `expires_at`, optional `revoked_at`;
- canonical record bytes/hash, lifecycle version and last Audit event.

Key identity, public bytes and activation/expiry are immutable after
registration. Revocation is a single `NULL -> timestamp` transition and can
never be removed or moved. Rows cannot be deleted or truncated through the
normal schema boundary.

All identifier/text lengths, fixed-point budgets, timestamp precision and time
ranges are validated in Rust and constrained again in PostgreSQL. Canonical
hashes explicitly use `atf_core::sort_json_keys`; JSON map backend ordering is
never trusted.

## Verification-time semantics

Identity verification receives time explicitly. It accepts a Key only when:

1. the exact `(agent_id, key_id)` record exists;
2. `activates_at <= envelope.issued_at <= verification_time`;
3. `verification_time < expires_at`, when expiry exists;
4. `envelope.expires_at <= expires_at`, when expiry exists;
5. `verification_time < revoked_at`, when revocation exists.

Expiry and revocation are exclusive and fail closed. A bounded old/new rotation
overlap works because each Envelope names one Key ID and each Key independently
satisfies these rules. Agent status, organization, environment and lifetime
remain additional mandatory checks.

## Atomic Audit contract

The typed operator events are `AgentRegistered`, `AgentStatusChanged`,
`IdentityKeyRegistered` and `IdentityKeyRevoked`. Each includes actor identity,
the affected organization/Agent, lifecycle version and canonical record hash.
Key events include only algorithm and SHA-256 public-key fingerprint, never raw
key bytes. Status/revocation events include a bounded reason code.

Mutation order is: validate input, lock the affected durable row when one
exists, append the typed event while holding the organization's chain-head
lock, write the new state/version/event pointer, and commit. Any conflict,
invalid transition or Audit failure rolls back the entire mutation.

Verified reads use a repeatable-read snapshot, verify the full organization
Audit chain, recompute canonical record bytes/hashes, compare redundant columns,
and require the pointed typed event to describe the current record hash and
version. Missing or inconsistent evidence is corruption, not a partial result.

## Offline commands

```text
DATABASE_URL=postgres://... atf identity provision-agent RECORD.json \
  --actor-id operator-1 --occurred-at 2026-08-08T10:00:00.000Z

DATABASE_URL=postgres://... atf identity register-key \
  --organization-id alpha-lab --agent-id research-agent-01 \
  --key-id identity-key-2026-01 --public-key-hex <64-lowercase-hex> \
  --activates-at 2026-08-08T10:00:00.000Z \
  --expires-at 2026-09-08T10:00:00.000Z \
  --actor-id operator-1 --occurred-at 2026-08-08T10:00:00.000Z

DATABASE_URL=postgres://... atf identity set-agent-status \
  --organization-id alpha-lab --agent-id research-agent-01 --status PAUSED \
  --actor-id operator-1 --reason-code OPERATOR_PAUSE \
  --occurred-at 2026-08-08T11:00:00.000Z

DATABASE_URL=postgres://... atf identity revoke-key \
  --organization-id alpha-lab --agent-id research-agent-01 \
  --key-id identity-key-2026-01 --actor-id operator-1 \
  --reason-code KEY_COMPROMISED \
  --occurred-at 2026-08-08T11:00:00.000Z
```

The CLI accepts public keys only. It never accepts, derives, stores or prints a
private seed/key. Successful output contains stable record identifiers,
versions and Audit event IDs; failures exit non-zero.

## Project structure and commands

- Migration: `migrations/0004_identity.sql`.
- Domain validation: `crates/atf-identity/src/`.
- Repository: `crates/atf-store/src/identity.rs`.
- PostgreSQL behavior tests: `crates/atf-store/tests/identity.rs`.
- CLI and smoke tests: `cli/atf-cli/src/main.rs`,
  `cli/atf-cli/tests/identity_commands.rs`.
- Audit contract: `crates/atf-audit`, `schemas/audit-event.schema.json`.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check -D warnings
ATF_TEST_DATABASE_URL=postgres://... \
  cargo test --workspace --all-targets --all-features
```

Rust uses explicit typed inputs and parameterized SQL. For example:

```rust
let snapshot = store
    .load_identity_snapshot(organization_id, agent_id, key_id)
    .await?;
snapshot.verify_envelope(intent, envelope, signature, &context)?;
```

## Testing strategy

1. Domain tests prove terminal Agent transitions and Key activation, expiry,
   revocation and Envelope-containment boundaries.
2. Real PostgreSQL tests prove restart behavior, organization isolation,
   bounded old/new overlap, concurrent mutation safety, atomic Audit rollback,
   state/Audit tamper rejection and absence of private material.
3. CLI integration/smoke tests run the real binary for provision, pause and
   revoke, assert non-zero invalid-input behavior, then reload through `Store`.
4. The full workspace gates remain mandatory before the feature is committed.

## Boundaries

- Always: fail closed, use explicit timestamps, parameterize SQL, verify Audit
  before returning identity state, and keep each mutation atomic.
- Requires later implementation: Admin HTTP remains absent and must define its
  own capability matrix. ADR-0003/DS-018 Operator credentials protect current
  Decision reads; Nonce consumption and Identity rejection mapping protect
  Agent admission.
- Never: store private identity/execution keys, infer a Key by trial, revive a
  revoked/expired Agent, un-revoke a Key, trust process memory as authority, or
  bypass Audit when persistence succeeds.

## Success criteria

DS-015 is complete only when paused/expired/revoked Agents and
inactive/expired/revoked exact Keys still fail after process restart; a bounded
old/new Key overlap verifies; provision/status/key/revoke changes are atomic
with typed Audit that contains no key material; real CLI commands exercise the
same repository; migration compatibility and all workspace gates pass.
