# Gateway API contract

This document describes the HTTP surface implemented by the current Durable
Shadow Gateway. It evaluates and records Decisions; it has no execution route
or execution authority.

## Current routes

| Method | Path | Response |
|---|---|---|
| `GET` | `/healthz` | Liveness text (`ok`) |
| `GET` | `/readyz` | PostgreSQL/schema and Operator-JWKS readiness text (`ready` or `not ready`) |
| `GET` | `/metrics` | Low-cardinality Prometheus text metrics |
| `POST` | `/v1/intents` | A durably recorded Decision |
| `GET` | `/v1/intents/{intent_id}/decision` | A verified durable Decision |
| `GET` | `/v1/audit/events` | A bounded verified organization Audit page |
| `GET` | `/v1/audit/intents/{intent_id}` | The same query with an Intent filter fixed by the path |
| `POST` | `/v1/policy-bundles/{bundle_id}/activate` | Activate one installed signed version |
| `POST` | `/v1/policy-bundles/{bundle_id}/rollback` | Select the immediately prior signed version |

The Decision and Audit read routes require exactly one RFC 9068
`Authorization: Bearer` access token validated by the Gateway and a current
PostgreSQL `auditor` or `org_admin` binding for the selected organization.
Agent Envelopes and Operator tokens are disjoint principal types and fail when
used on the wrong route. `X-ATF-Organization-ID` remains a canonical tenant
selector; it and JWT organization/role/email claims never become authority.
Decision absence, cross-organization selection and insufficient read role all
return the same `404 DECISION_NOT_FOUND` response. Audit cross-organization
selection, missing current role and absent organization all return the same
`404 AUDIT_EVENTS_NOT_FOUND` response.

Both Decision routes return the closed DS-025 Decision v1 envelope defined by
`schemas/decision.schema.json`. In addition to ID/kind/reasons it carries the
canonical Intent hash, Profile, exact Policy/Risk artifact references,
Evaluation ID and Context/snapshot hashes, explicit Simulation state,
evaluation/expiry times, future Approval/Obligation arrays and closed
execution constraints. Unknown top-level or nested core fields are rejected.
`decision_hash` is:

```text
SHA-256("ATF_DECISION_V1\0" || canonical_decision_without_decision_hash)
```

The stored Decision column and `DecisionRecorded.binding` are verified against
the same envelope before a read is exposed. `adapter_id` is explicitly `null`
until Adapter selection exists; this service still cannot execute a Decision.

Policy mutation routes require the same validated Operator token and selector,
plus a current `policy_author` or `org_admin` binding. The Store repeats that
authorization while holding the mutation transaction locks. Missing Bundle,
cross-organization selection, insufficient role and unavailable rollback are
non-enumerating `404 POLICY_BUNDLE_NOT_FOUND` responses. Activate accepts the
closed body `{"environment":"...","policy_version":"..."}`; rollback accepts
`{"environment":"..."}`. Success returns Bundle ID/version/hash, pointer
lifecycle version and Audit event ID. Installation is intentionally offline.

`POST /v1/intents` requires the detached Agent identity Headers defined in
[`gateway-identity.md`](gateway-identity.md): lowercase-hex canonical Envelope
bytes plus one exact Ed25519 signature. Trusted audience/environment come from
required Gateway startup configuration, not the request.

DS-020 requires `ATF_POLICY_ORGANIZATION_ID`, `ATF_POLICY_BUNDLE_ID` and
`ATF_DEPLOYMENT_ENVIRONMENT` to resolve one signed durable active pointer.
Startup fails on missing pointer or artifact/archive/signature/Audit/scope/time
integrity errors. Every new evaluation reloads the pointer and immutable
archive in one repeatable-read snapshot, rechecks the signature, Bundle hash,
Schema, scope and expiry, and then evaluates that exact owned version. See
[`policy-model.md`](policy-model.md) for installation and signing details.

DS-026 additionally requires `ATF_RISK_RULE_SET_PATH` to identify an exact
bounded closed artifact already installed in the organization/environment
audited archive. Startup reloads and verifies the durable canonical bytes,
hashes and `RiskRuleSetStored` evidence; invalid, missing or unknown
configuration fails before serving. Both executed and Policy-skipped
Risk evidence record `risk_rule_set_version` and `risk_rule_set_hash`. See
[`risk-rule-sets.md`](risk-rule-sets.md).

DS-022 does not add an Agent evidence HTTP field. Intent `context` remains
`AGENT_PROVIDED`; price, balance, position, spend, reputation, freshness and
simulation keys cannot grant trusted Risk authority. The current Gateway has
no production enricher, so the reference Rule Set returns a restrictive
vendor-price insufficient-data finding rather than using
`context.historical_vendor_median`. Trusted integrations construct the closed
`evidence.schema.json` envelope, apply an exact local trust policy, and pass
only `VerifiedEvidence` into Evaluation Context construction. DS-023 persists
the exact verified Evidence/trust selection, Agent-context hash and evaluation
time before Policy/Risk. DS-024 makes `atf_policy::PolicyBundle::evaluate` and
`atf_risk::evaluate_context` validate that immutable authority; Risk rejects
any Audit prefix not ending at the Context snapshot. See
[`context-provenance.md`](context-provenance.md).

Gateway startup also requires `ATF_OPERATOR_ISSUER_ID`, exact
`ATF_OPERATOR_ISSUER_URL`, `ATF_OPERATOR_AUDIENCE`, configured HTTPS
`ATF_OPERATOR_DISCOVERY_URL` and `ATF_OPERATOR_JWKS_URL`, plus an asymmetric
`ATF_OPERATOR_JWT_ALGORITHMS` allowlist. Token lifetime, clock skew, JWKS
freshness and HTTP timeout have bounded optional environment settings; a
private/test CA can be supplied via `ATF_OPERATOR_CA_CERT_PATH`. Startup fails
closed unless discovery and an initial unique usable key set validate.

## DS-032 Audit query contract

Both Audit routes require an Operator principal with a current durable
`auditor` or `org_admin` role in the organization selected by the canonical
`X-ATF-Organization-ID` header. The Gateway performs a fast role check, then
the Store repeats subject/status/role authorization and verifies the complete
declared organization chain inside one repeatable-read, read-only snapshot.
No target chain is loaded when the operator has no role row for that target.

`GET /v1/audit/events` accepts these optional, conjunctive query parameters:

| Parameter | Meaning |
|---|---|
| `intent_id` | Exact canonical Intent ID |
| `agent_id` | Exact `data.agent_id` in a verified typed Audit payload |
| `event_type` | Exact canonical `EventType` wire value |
| `occurred_from` | Inclusive RFC 3339 lower bound at millisecond precision |
| `occurred_to` | Inclusive RFC 3339 upper bound at millisecond precision |
| `limit` | Page size, `1..=100`; default `50` |
| `cursor` | Opaque URL-safe base64 cursor from the preceding response |

`GET /v1/audit/intents/{intent_id}` fixes the Intent filter from the path and
accepts all other filters. Supplying `intent_id` again on that route is
invalid. Unknown parameters, invalid identifiers/times/event values, a lower
time greater than the upper time, padded/noncanonical/oversized cursors and an
out-of-range limit return `400 AUDIT_QUERY_INVALID`.

Success is ordered by ascending organization sequence and has this shape:

```json
{
  "schema_version": 1,
  "organization_id": "alpha-lab",
  "chain": {
    "status": "VERIFIED",
    "through_sequence": 42,
    "through_event_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  },
  "events": [],
  "pagination": {
    "order": "SEQUENCE_ASC",
    "limit": 50,
    "next_cursor": null
  }
}
```

Each non-empty `events` entry carries `sequence`, `event_hash`, the complete
closed `AuditEvent` defined by `schemas/audit-event.schema.json`, and nullable
`evaluation_id`/`decision_id` storage bindings.

The versioned cursor binds the organization, exact filter set, last returned
sequence and the verified `through_sequence`/hash. Later appends therefore do
not change an in-progress traversal. A cursor cannot be reused with another
tenant or filter set. The cursor is opaque state binding, not a bearer
credential or cryptographic authorization token; JWT validation and current
durable RBAC are repeated for every page. Any canonical/hash/order/head
corruption returns `500 DURABLE_STATE_INTEGRITY_ERROR` and exposes no events.
The current proof verifies the full chain on every query; until Audit
checkpoints exist this has O(organization event count) cost and remains subject
to DS-034 operational limits.

## Request correlation

The Gateway generates a fresh ULID for every HTTP request. Every response,
including successful and health/readiness responses, contains:

```http
X-ATF-Request-ID: 01J00000000000000000000000
```

An inbound `X-ATF-Request-ID` is untrusted and never becomes the server ID.
Errors repeat the exact server-generated value in the JSON body. DS-033 puts
the same ID on the JSON `http.request` span; stable admission, Decision,
Policy-mutation and Audit-page completion events inside that span name their
durable Audit event ID. Store/readiness failures include only stable codes,
never the underlying database diagnostic. See [`operations.md`](operations.md)
for the allowlist, redaction tests and correlation procedure.

## DS-033 Metrics contract

`GET /metrics` returns `text/plain; version=0.0.4; charset=utf-8`. Labels are
closed route templates, method/status classes and domain outcomes/severities;
raw URLs, organization/request/Intent IDs, credentials, signatures, full
payloads, error text, Policy IDs and Risk rule IDs are excluded. Replay totals
come from durable typed Audit evidence because Replay runs in the offline CLI.
The endpoint is an infrastructure scrape surface and must remain behind a
trusted private network or authenticated ingress until DS-034 completes the
shared TLS/proxy/rate-limit boundary.

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
| 400 | `REQUEST_BODY_INVALID` | Body buffering or a closed Admin JSON contract failed safely |
| 400 | `INTENT_SCHEMA_INVALID` | Common Intent Schema rejected the document |
| 400 | `INTENT_SHAPE_INVALID` | Typed parsing rejected a Schema/Rust mismatch |
| 400 | `INTENT_SEMANTIC_INVALID` | Common or Profile semantic rules rejected the Intent |
| 400 | `ORGANIZATION_HEADER_INVALID` | Canonical tenant-selector header is malformed |
| 400 | `ORGANIZATION_NOT_FOUND` | Declared organization is unavailable |
| 400 | `AUDIT_QUERY_INVALID` | Audit filters, limit or cursor are malformed, unknown, unbounded or mismatched |
| 404 | `DECISION_NOT_FOUND` | No tenant-scoped durable Decision exists |
| 404 | `AUDIT_EVENTS_NOT_FOUND` | Audit organization is absent, cross-tenant or not readable by the principal |
| 404 | `POLICY_BUNDLE_NOT_FOUND` | Policy resource is absent, cross-tenant, unauthorized, or cannot roll back |
| 404 | `ROUTE_NOT_FOUND` | Path is not registered |
| 405 | `METHOD_NOT_ALLOWED` | Method is not registered for the path |
| 401 | `AUTHENTICATION_REQUIRED` | Route-appropriate Agent/Operator credential is missing, invalid, disabled, or used on the wrong route |
| 401 | `IDENTITY_HEADERS_*` / `IDENTITY_*` | Identity Header or signed proof is missing, malformed, expired, mismatched or invalid |
| 403 | `IDENTITY_AGENT_*` / `IDENTITY_KEY_*` | A known durable Agent/Key lifecycle or deployment restriction denies submission |
| 409 | `DURABLE_STATE_CONFLICT` | Immutable durable state conflicts with the request |
| 409 | `IDEMPOTENCY_CONFLICT` | Organization/key is already bound to another Intent hash |
| 409 | `IDEMPOTENCY_IN_PROGRESS` | The same organization/key/hash has an active evaluator or recovery lease |
| 409 | `IDENTITY_NONCE_REPLAY` | The Agent Nonce is already bound to another request |
| 413 | `REQUEST_BODY_TOO_LARGE` | Active body limit rejected the request |
| 500 | `DURABLE_STATE_INTEGRITY_ERROR` | Persisted evidence failed verification |
| 500 | `INTERNAL_ERROR` | An internal invariant failed safely |
| 503 | `DURABLE_STATE_UNAVAILABLE` | Required durable state is unavailable/incompatible |

Changing or removing an existing code or field is a compatibility decision and
requires an explicit migration.

## DS-018/DS-020/DS-032 Operator error mapping

The current protected-read contract deliberately minimizes credential and
resource-state disclosure:

| HTTP | Code | Meaning |
|---:|---|---|
| 401 | `AUTHENTICATION_REQUIRED` | No single valid route-appropriate credential, no active mapped Operator, or principal-type mismatch |
| 404 | `DECISION_NOT_FOUND` | Decision absent, cross-organization, or not readable by the principal; the cases are indistinguishable |
| 404 | `POLICY_BUNDLE_NOT_FOUND` | Policy Bundle/pointer absent, cross-organization, wrong-role, or rollback unavailable; the cases are indistinguishable |
| 404 | `AUDIT_EVENTS_NOT_FOUND` | Audit organization absent, cross-organization, or not readable by the principal; the cases are indistinguishable |
| 503 | readiness text only | No fresh usable configured issuer key set is available; `/readyz` fails and protected reads fail closed |

401 responses include only a fixed safe `WWW-Authenticate: Bearer` challenge.
No response distinguishes expired versus revoked subjects, unknown versus
disabled accounts, signing-key details, role membership, or another tenant's
resource existence. Raw tokens and provider diagnostics never enter the error
envelope.

## Admission ordering

`POST /v1/intents` executes the following boundary in order:

1. Buffer body and require UTF-8 JSON.
2. Validate the closed common JSON Schema and typed Rust envelope.
3. Validate common financial/time/identifier semantics.
4. Derive and validate the supported Action Profile.
5. Parse the bounded canonical detached identity Headers. For a provisioned
   organization, Header failure commits only typed `IdentityRejected`.
6. Lock/reverify the current durable Agent and exact Key, validate the signed
   Envelope against trusted audience/environment, and atomically bind the
   hashed Nonce with the idempotency reservation, evaluator lease, Intent,
   `IntentReceived`, and `IdentityVerified`. Identity failure/replay cannot
   create an accepted Intent or reach Policy/Risk.
7. Resolve the durable reservation before evaluation:
   - a completed same-hash reservation loads and returns its fully verified
     original Decision without Policy/Risk or new Audit evidence;
   - an active evaluator/recovery lease returns
     `409 IDEMPOTENCY_IN_PROGRESS`;
   - an expired lease is conditionally reclaimed with a higher fencing
     generation, reuses an existing context or persists one with explicit
     unavailable inputs, and finalizes once as `Decision(ERROR)` with
     `RECOVERY_REPLAY_NOT_IMPLEMENTED` evidence.
8. For a new admission, resolve Policy/Risk artifacts, capture one evaluation
   time and verified history prefix, then atomically persist the immutable
   Evaluation Context plus `ContextEnriched` before module output.
9. Evaluate the pinned Policy; renew the lease in an independent short
   transaction; evaluate Risk only when Policy permits using the same context
   time/history; renew again.
10. Atomically finalize Evaluation, Decision, lifecycle, Audit evidence and the
   idempotency result.

Steps 1–4 cannot create an Intent, Evaluation, Decision, or Audit event.
Integration tests inspect the reservation plus all four business PostgreSQL
tables for Schema, common
semantic and unsupported-Profile failures. Internal failure after durable
admission remains fail closed. DS-012 provides the durable lease/fencing and
completed-result foundation. DS-013 wires its request semantics: completed
same-hash retry is exact, active work is bounded, and expired work is reclaimed
only through the generation-fenced fail-closed path. This is request-driven
recovery, not a background worker. A different hash always returns
`IDEMPOTENCY_CONFLICT`. DS-016 adds exact retry with no duplicate evidence,
fresh valid retry Nonce consumption, and conflicting-reuse
`IDENTITY_NONCE_REPLAY`; PostgreSQL is the only replay authority.
