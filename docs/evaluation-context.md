# Immutable Evaluation Context

Status: DS-023 implemented (2026-08-08)

Authority: `docs/PRD.md` §12.5–12.6 and ADR-0002

## Objective

Every Decision must be evaluated from one immutable, durable snapshot created
before Policy or Risk executes. The snapshot captures one evaluation time and
names every selected artifact or records an explicit unavailable/not-run
state. Final Evaluation output is a separate immutable record that binds the
snapshot hash; the snapshot is never updated with results.

## Version-1 document

An `EvaluationContext` binds:

- Evaluation ID, Intent ID/hash, evaluation time and environment;
- the validated Intent Profile ID/version;
- the selected Policy Bundle ID/version/hash, or an explicit unavailable
  reason for restrictive recovery;
- the Risk engine/rule-set version/hash, or an explicit unavailable reason;
- one context snapshot ID/hash over the Agent context hash and sorted,
  verified Evidence envelopes;
- the Evidence trust-policy identity, or explicit `NOT_CONFIGURED` when the
  evidence list is empty; nonempty Evidence must carry the exact same
  domain-separated policy hash retained by `VerifiedEvidence` at verification;
- one verified Audit-chain history snapshot ID, sequence and head hash;
- market-data snapshot identity or explicit `UNAVAILABLE`;
- explicit Simulation `NOT_RUN` plus its stable reason code.

The context hash is domain separated:

```text
SHA-256("ATF_EVALUATION_CONTEXT_V1\0" || canonical_context_payload)
```

The payload excludes only `evaluation_context_hash`. JSON object keys are
recursively sorted. The nested context snapshot and Agent context use their own
domain-separated hashes. Evidence is sorted by Evidence hash and must be fresh
at `evaluation_time`; duplicate Evidence hashes are canonicalized away.

## Durable transaction

After authenticated admission, Gateway resolves the exact Policy artifact,
loads and verifies the Audit history it will give Risk, captures one evaluation
time, constructs the context, then calls one short Store transaction. That
transaction:

1. verifies the current evaluator lease/fencing token and immutable Intent;
2. inserts the context's exact canonical JSON/bytes/hash;
3. appends one matching typed `ContextEnriched` Audit event;
4. commits both or neither.

The context table rejects update, delete and truncate. One Intent has at most
one authoritative context in the current Shadow pipeline. Exact retries return
the same snapshot without appending duplicate evidence; conflicting retries
fail closed.

Policy and Risk execute only after this commit. Finalization requires the same
Evaluation ID, evaluation time and context hash and records a foreign-key
binding from final Evaluation output to the immutable context.

## Loading and recovery

Readers reparse canonical bytes, recursively canonicalize the document,
recompute all hashes, compare redundant columns and require exactly one
matching `ContextEnriched` event in the verified organization Audit chain.
Mutation, missing evidence, duplicate/conflicting rows or Audit mismatch is
durable-state corruption and fails closed.

DS-023 does not yet recompute an unfinished Evaluation. A reclaimed request
reuses an already persisted context when present; otherwise it persists one
whose Policy/Risk/market-data fields explicitly record unavailability. It then
emits `RECOVERY_REPLAY_NOT_IMPLEMENTED -> Decision(ERROR)` without executing
current Policy/Risk. Deterministic Original Replay begins in DS-026.

## Required verification

1. canonical golden vectors and mutation tests cover every bound input;
2. snapshot round-trip/load detects row, bytes, hash and Audit tampering;
3. update/delete/truncate and a second conflicting context are rejected;
4. stale evaluator generations cannot persist or replace a context;
5. Gateway persists the context before Policy/Risk and uses the same time,
   Policy/Risk identities and Audit history snapshot;
6. restart and second-instance reads return the exact context;
7. all repository gates and real Gateway/PostgreSQL smoke paths pass.
