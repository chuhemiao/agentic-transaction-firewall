# Gateway Identity and Nonce Admission

Status: DS-016 implemented contract

Authority: `docs/PRD.md` §16–18, ADR-0002, and `tasks/plan.md` DS-016

## Objective

Authenticate every `POST /v1/intents` request with the DS-014
domain-separated Ed25519 Envelope against the DS-015 durable Agent/exact-Key
lifecycle. A successful request consumes its signed Nonce in PostgreSQL before
Policy or Risk. Identity rejection and Nonce replay are durable, typed Audit
evidence but can never create an accepted Intent, evaluator lease, Evaluation,
Decision, or successful idempotency result.

DS-016 is successful when two Gateway instances converge on one authenticated
Nonce binding, exact retries return the original result, fresh authenticated
retries retain DS-013 recovery semantics, and no unverified request can reach
Policy/Risk.

## HTTP contract

`POST /v1/intents` keeps the canonical Transaction Intent as its JSON body.
Identity is detached so the signed Intent hash is not recursively changed by
the signature:

- `X-ATF-Identity-Envelope`: lowercase hexadecimal encoding of the exact
  `IdentityEnvelope::canonical_bytes()` UTF-8 JSON;
- `X-ATF-Identity-Signature`: exactly 128 lowercase hexadecimal characters,
  encoding one 64-byte Ed25519 signature over those canonical bytes.

Both Headers are required exactly once. The decoded Envelope must deserialize
with unknown fields rejected, reserialize byte-for-byte to the decoded Header,
and satisfy the existing identifier, lifetime, Intent hash, organization,
Agent, audience and environment contract. Header input is bounded before
allocation and never logged or copied into an error response.

The Gateway reads trusted `ATF_IDENTITY_AUDIENCE` and
`ATF_DEPLOYMENT_ENVIRONMENT` values at startup. Both are required canonical
ASCII identifiers; startup fails rather than silently selecting a deployment
scope.

## Admission ordering and atomicity

The request path is ordered as follows:

1. Bound and decode the body, then complete closed Schema, Rust shape, common
   semantic and supported Profile validation. These failures remain zero-write.
2. Parse the two bounded identity Headers. For an existing organization, a
   missing or malformed assertion commits one organization-scoped
   `IdentityRejected` event in a short transaction, then returns a stable 401.
3. Start authenticated admission, lock the referenced Agent then exact Key,
   verify their canonical records and complete organization Audit chain, and
   verify the Envelope/signature at one explicit server verification time.
   A domain/lifetime/scope/signature/lifecycle failure commits only
   `IdentityRejected`, then returns 401 or 403.
4. Hash the Nonce and Envelope. Insert the immutable Nonce binding while
   coordinating it with the organization/idempotency reservation:
   - a new binding commits with the new admission or a matching existing
     idempotency reservation;
   - the exact existing Envelope/binding is an idempotent network retry and
     creates no duplicate Nonce or Audit event;
   - the same Agent Nonce under another Key, Envelope, Intent hash, Intent ID,
     or idempotency key commits `ReplayDetected` and returns 409;
   - an idempotency conflict rolls back the attempted new Nonce.
5. A new admission atomically commits the reservation/lease, immutable Intent,
   consumed Nonce, `IntentReceived`, `IdentityVerified`, and materialized
   `IDENTITY_VERIFIED` lifecycle version 2.
6. Matching completed, active or expired reservations retain DS-013 behavior.
   A fresh valid assertion may consume a fresh Nonce for the same immutable
   binding; exact retries add nothing. Completed work returns the verified
   original Decision, active work returns bounded 409, and expired work is
   generation-fenced into the existing fail-closed recovery path.
7. Only a new authenticated admission runs Policy and, when allowed, Risk.
   Finalization starts from `IDENTITY_VERIFIED`, persists the verified identity
   payload in Evaluation evidence, and no longer emits
   `IdentityVerificationSkipped`.

PostgreSQL is the sole Nonce authority. No in-memory replay cache or fallback
is permitted. The transaction locks Agent before Key and uses the existing
per-organization Audit-head order so lifecycle mutation and request admission
cannot deadlock by taking the same resources in reverse order.

## Durable Nonce record

Migration 0005 stores one immutable row addressed by
`(organization_id, agent_id, nonce_hash)`. It contains only:

- exact `key_id`, Intent ID/hash and idempotency key;
- Envelope hash and exclusive Envelope expiry;
- Agent and Key lifecycle versions plus canonical record hashes verified at
  consumption;
- the typed `IdentityVerified` Audit event and consumption time.

The raw Nonce, Envelope, signature, public key and all private material are not
stored. Composite foreign keys bind committed Nonces to the exact Agent, Key,
Intent, idempotency reservation and Audit evidence. UPDATE, DELETE and TRUNCATE
are rejected. Reads used for retry/replay classification recompute and compare
the binding and verify its pointed Audit event against the full chain.

`ReplayDetected` is organization-scoped operational evidence. Its payload
contains the SHA-256 Nonce hash plus attempted and already-bound Intent
IDs/hashes, Agent, Key and a stable reason code. It never stores the raw Nonce,
Envelope or signature and does not mutate the accepted Intent lifecycle.

`IdentityVerified` and `IdentityRejected` may be organization-scoped for
authenticated retries or rejected attempts that do not create an Intent. The
same typed payloads remain Intent-scoped when they advance a newly admitted
Intent from `RECEIVED` to `IDENTITY_VERIFIED` or `IDENTITY_REJECTED`.

## Stable failures

- Missing/duplicate/malformed identity Headers: 401 with a fixed identity
  Header code.
- Invalid proof, binding, time or unknown Agent/Key: 401 with the existing
  stable `IdentityError::code()` value.
- Known Agent/Key lifecycle or deployment-scope denial: 403 with the existing
  stable identity code.
- Conflicting reuse of a consumed Nonce: 409 `IDENTITY_NONCE_REPLAY`.
- Identity rejection/replay Audit persistence failure: fail closed through the
  existing safe 500 integrity or 503 durable-state error contract; never return
  the unaudited identity result as authoritative.

An organization must already be provisioned before it owns an Audit chain.
`ORGANIZATION_NOT_FOUND` therefore remains the pre-authentication tenant
boundary rather than silently creating a tenant from untrusted input.

## Project structure and commands

- HTTP assertion parsing/configuration: `services/gateway/src/auth.rs`.
- Gateway ordering: `services/gateway/src/routes.rs`.
- Coarse authenticated transaction: `crates/atf-store/src/nonce.rs` and
  `crates/atf-store/src/repository.rs`.
- Schema: `migrations/0005_nonces.sql`.
- Typed evidence: `crates/atf-audit` and `schemas/audit-event.schema.json`.
- PostgreSQL tests: `crates/atf-store/tests/nonce.rs`.
- HTTP tests and signed runtime flow: `services/gateway/tests/identity.rs`.

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo deny check -D warnings
ATF_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
  cargo test --workspace --all-targets --all-features
```

Runtime verification starts a migrated PostgreSQL database, provisions one
Agent and public Key through the supported CLI/store boundary, starts the real
Gateway with explicit audience/environment, signs a live Envelope outside the
Gateway, and uses `curl` for first admission, exact retry and replay rejection.

## Testing strategy

1. Pure Header tests reject missing, duplicate, uppercase/odd/non-hex,
   oversized, non-canonical, unknown-field and wrong-length inputs.
2. Real PostgreSQL tests cover atomic new consumption, exact retry, fresh-Nonce
   retry, wrong binding, concurrent same-Nonce/different-Intent races, restart,
   Agent/Key mutation serialization, rollback, row tampering and database
   mutation guards.
3. Gateway tests prove identity rejection/replay produces typed Audit but no
   admitted/evaluated/decided state and never emits Policy/Risk evidence.
4. End-to-end tests prove wrong organization/audience/environment/time/key/
   signature failures, current lifecycle enforcement, completed result
   convergence and cross-organization isolation.

Tests assert outcomes and durable state, not helper-call sequences. Every new
behavior starts with a failing test, then becomes green before the next slice.

## Boundaries

- Always: validate before allocation where practical, use parameterized SQL,
  lock/recheck current Agent/Key state, hash Nonces explicitly, commit evidence
  atomically, verify durable rows before reuse, and fail closed.
- Implemented separately: ADR-0003/DS-018 defines Operator authentication and
  Decision-read RBAC without weakening this Agent boundary. Rate limiting,
  general trace/metrics propagation and execution credentials remain later
  work.
- Never: accept an unsigned fallback, try multiple Keys, trust caller audience
  or environment, persist raw Nonces/signatures/private keys, log credential
  Headers, consume a Nonce only in memory, or run Policy/Risk after identity
  rejection/replay.

## Success criteria

DS-016 is complete only when all required and malformed assertions fail closed
with durable evidence for a provisioned organization; one concurrent Nonce can
bind to exactly one request; exact and fresh authenticated retries preserve the
one durable idempotent result/recovery contract; current lifecycle changes are
rechecked in the admission transaction; Evaluation evidence names the verified
Key/Envelope; `IDENTITY_UNVERIFIED` is absent from the Gateway path; the real
signed HTTP smoke works; and every workspace gate is clean.

## Open questions

None for DS-016. DS-018 Operator identity/RBAC is now implemented; public-
network hardening remains explicit DS-034 work. ADR-0003 deliberately keeps
its Operator principal disjoint from this Agent-authentication boundary.
