# Gateway API contract

This document describes the HTTP surface implemented by the current Durable
Shadow Gateway. It evaluates and records Decisions; it has no execution route
or execution authority.

## Current routes

| Method | Path | Response |
|---|---|---|
| `GET` | `/healthz` | Liveness text (`ok`) |
| `GET` | `/readyz` | PostgreSQL/schema readiness text (`ready` or `not ready`) |
| `POST` | `/v1/intents` | A durably recorded Decision |
| `GET` | `/v1/intents/{intent_id}/decision` | A verified durable Decision |

The organization header used by the Decision read route is only a temporary
tenant selector. It is not authentication or authorization; business routes
must not be exposed to a shared or untrusted network before DS-017/DS-018.

## Request correlation

The Gateway generates a fresh ULID for every HTTP request. Every response,
including successful and health/readiness responses, contains:

```http
X-ATF-Request-ID: 01J00000000000000000000000
```

An inbound `X-ATF-Request-ID` is untrusted and never becomes the server ID.
Errors repeat the exact server-generated value in the JSON body. Store and
readiness failure logs include it together with a stable error code, never the
underlying database diagnostic. Full trace/Audit propagation remains DS-033.

## Error envelope

Every JSON error from a business route, unknown route, or unsupported method
has exactly these top-level fields:

```json
{
  "code": "INTENT_SEMANTIC_INVALID",
  "message": "Intent violates one or more semantic rules.",
  "request_id": "01J00000000000000000000000",
  "details": [
    {
      "code": "AMOUNT_NOT_POSITIVE",
      "field": "transaction.amount"
    }
  ]
}
```

`code` is the machine contract. `message` is a fixed safe description and is
not intended for parsing. `details` is always an array; only stable,
server-owned semantic code/field pairs are currently exposed. It is empty
when no safe structured detail exists. The envelope never copies raw request
data, JSON Schema diagnostics, SQL text, database URLs, policy text, key
material, or an internal error string.

A fail-closed `Decision(ERROR)` is still a normal Decision representation,
not an error envelope. Its Policy failure reason is likewise fixed to
`POLICY_EVALUATION_ERROR` / `Policy evaluation failed safely.`; the underlying
Cedar/request-mapping diagnostic is not serialized.

Health and readiness probes deliberately retain their minimal text bodies for
operators and orchestrators. They still carry `X-ATF-Request-ID`.

## Stable error mapping

| HTTP | Code | Meaning |
|---:|---|---|
| 400 | `INVALID_UTF8` | Body is not UTF-8 |
| 400 | `INVALID_JSON` | Body is not JSON |
| 400 | `REQUEST_BODY_INVALID` | Body buffering failed safely |
| 400 | `INTENT_SCHEMA_INVALID` | Common Intent Schema rejected the document |
| 400 | `INTENT_SHAPE_INVALID` | Typed parsing rejected a Schema/Rust mismatch |
| 400 | `INTENT_SEMANTIC_INVALID` | Common or Profile semantic rules rejected the Intent |
| 400 | `ORGANIZATION_HEADER_INVALID` | Temporary tenant-selector header is malformed |
| 400 | `ORGANIZATION_NOT_FOUND` | Declared organization is unavailable |
| 404 | `DECISION_NOT_FOUND` | No tenant-scoped durable Decision exists |
| 404 | `ROUTE_NOT_FOUND` | Path is not registered |
| 405 | `METHOD_NOT_ALLOWED` | Method is not registered for the path |
| 409 | `DURABLE_STATE_CONFLICT` | Immutable durable state conflicts with the request |
| 409 | `IDEMPOTENCY_CONFLICT` | Organization/key is already bound to another Intent hash |
| 409 | `IDEMPOTENCY_IN_PROGRESS` | The same organization/key/hash is evaluating or awaiting expired-work recovery |
| 413 | `REQUEST_BODY_TOO_LARGE` | Active body limit rejected the request |
| 500 | `DURABLE_STATE_INTEGRITY_ERROR` | Persisted evidence failed verification |
| 500 | `INTERNAL_ERROR` | An internal invariant failed safely |
| 503 | `DURABLE_STATE_UNAVAILABLE` | Required durable state is unavailable/incompatible |

Future authentication, authorization, exact retry/recovery, replay and
dependency features add codes to this one envelope. Changing or removing an
existing code or field is a compatibility decision and requires an explicit
migration.

## Admission ordering

`POST /v1/intents` executes the following boundary in order:

1. Buffer body and require UTF-8 JSON.
2. Validate the closed common JSON Schema and typed Rust envelope.
3. Validate common financial/time/identifier semantics.
4. Derive and validate the supported Action Profile.
5. Atomically reserve the organization/idempotency key, acquire one evaluator
   lease, persist the Intent and append admission evidence.
6. Evaluate Policy; evaluate Risk only when Policy permits.
7. Atomically finalize Evaluation, Decision, lifecycle and Audit evidence.

Steps 1–4 cannot create an Intent, Evaluation, Decision, or Audit event.
Integration tests inspect the reservation plus all four business PostgreSQL
tables for Schema, common
semantic and unsupported-Profile failures. Internal failure after durable
admission remains fail closed. DS-012 provides the durable lease/fencing and
completed-result foundation: an `IN_PROGRESS` duplicate stops before
Policy/Risk and a different hash returns `IDEMPOTENCY_CONFLICT`. Until DS-013,
an expired reservation is not automatically reclaimed, and a completed
same-hash POST is not yet translated into the original Decision.
