# Gateway Operations

This runbook describes the current Durable Shadow observability boundary. It
does not grant execution authority: the Gateway still evaluates and records,
and cannot sign or submit a transaction.

## On-call questions

The DS-033/DS-035 signals are designed to answer six questions without inspecting a
financial payload:

1. Is the HTTP surface available, and which fixed route/status class is slow?
2. Are finalized Decision outcomes or exact-idempotency retries changing?
3. Is Policy or Risk slow, failing closed, or producing more findings?
4. Are Evidence freshness, durable Replay evidence, or Audit reads/writes
   unhealthy?
5. Are clients being rejected by body/Header, deadline, source-rate or
   principal-rate controls?
6. Which required serving dependency failed, and did the request stop before
   exposing an unfinalized Decision?

## Metrics endpoint

`GET /metrics` returns Prometheus text format. It has no application credential
because it is an infrastructure scrape endpoint, not a business API. It shares
the same DS-034 body/Header, timeout and source-rate controls, but must still be
exposed only on a trusted private operations network or authenticated ingress;
do not publish it directly to the Internet.

```bash
curl --fail --silent http://127.0.0.1:8080/metrics
```

Implemented families:

| Metric | Type | Fixed labels | Meaning |
|---|---|---|---|
| `atf_gateway_http_requests_total` | counter | `method`, `route`, `status_class` | Completed HTTP responses |
| `atf_gateway_http_request_duration_seconds` | histogram | same | End-to-end Gateway latency |
| `atf_gateway_decisions_total` | counter | `kind` | Newly finalized Decisions, excluding exact retries |
| `atf_gateway_policy_evaluation_duration_seconds` | histogram | `outcome` | Policy evaluator latency |
| `atf_gateway_policy_matches_total` | counter | `outcome` | Number of matched Policy IDs without exporting the IDs |
| `atf_gateway_risk_evaluation_duration_seconds` | histogram | `outcome` | Risk evaluator latency, including explicit `NOT_RUN` |
| `atf_gateway_risk_findings_total` | counter | `severity` | Risk/Shadow findings without rule IDs or messages |
| `atf_gateway_idempotency_requests_total` | counter | `outcome` | New, exact-retry, recovered, conflict, and in-progress admissions |
| `atf_gateway_evidence_freshness_total` | counter | `state` | Evidence freshness at the pinned Evaluation time |
| `atf_gateway_replays_total` | counter | `mode` | Cumulative typed Replay completion Audit events |
| `atf_gateway_replay_metrics_available` | gauge | none | Whether the durable Replay aggregate was readable |
| `atf_gateway_audit_failures_total` | counter | `operation` | Audit-backed write or verified-read failures |
| `atf_gateway_dependency_failures_total` | counter | `dependency` | Database, active Policy, history Snapshot, Audit-integrity or lock failures |
| `atf_gateway_request_rejections_total` | counter | `reason` | Body/Header, request/evaluator timeout, source-rate and principal-rate rejections |

HTTP, Decision, evaluator, idempotency, freshness, Audit-failure and dependency-
failure metrics are process-local. Sum counters across Gateway instances; do
not sum histogram quantiles. Replay runs in an offline CLI, so its two counters are read from
durable typed Audit evidence on each scrape rather than a misleading local
process counter. If that aggregate is unavailable, the scrape still exposes
process metrics, sets `atf_gateway_replay_metrics_available` to `0`, and
increments the Audit read-failure counter.

Simulation latency, Adapter errors, Approval wait, Kill Switch, settlement,
and reconciliation metrics are intentionally absent because those components
do not exist. Their metric contracts must be added with the component that can
produce truthful observations.

## Dependency failure and readiness boundary

`/healthz` is liveness only and remains `200 ok` while the HTTP process is
running. `/readyz` is serving safety: it returns `200 ready` only when the live
schema is compatible, the configured durable active Policy resolves to a
current signed Bundle, and Operator JWKS is fresh and usable. A `503 not ready`
must remove the instance from serving rotation; it does not imply the process
should be killed before diagnostics can be scraped.

Store pool acquisition is capped at three seconds, below the 15-second
evaluation and 30-second whole-request budgets. A disappeared database
therefore reaches the stable 503 dependency contract before the generic HTTP
deadline. Write transactions separately retain their five-second PostgreSQL
lock timeout.

| Failure | Safe outcome | Signals |
|---|---|---|
| Database/schema unavailable before Admission | `503 DURABLE_STATE_UNAVAILABLE`; no Intent or reservation | readiness down; dependency `DATABASE` |
| PostgreSQL lock timeout/deadlock | bounded `503 DURABLE_STATE_UNAVAILABLE`; transaction rollback | dependency `LOCK` |
| Active signed Policy unavailable with storage healthy | readiness down; POST persists unavailable Policy Context and returns only an atomically finalized `Decision(ERROR)` | dependency `ACTIVE_POLICY`; Policy/Decision `ERROR` |
| Bounded history Snapshot invalid | `500 DURABLE_STATE_INTEGRITY_ERROR`; no new Decision response | dependency `HISTORY_SNAPSHOT` |
| Audit chain/evidence corrupt | `500 DURABLE_STATE_INTEGRITY_ERROR`; no new Decision response | dependency `AUDIT`; fixed Audit operation |
| Audit/finalization database write fails | `503 DURABLE_STATE_UNAVAILABLE`; Evaluation, Decision and phase events roll back together | root `DATABASE`/`LOCK`; fixed Audit operation |

Dependency labels are a closed set: `DATABASE`, `ACTIVE_POLICY`,
`HISTORY_SNAPSHOT`, `AUDIT`, and `LOCK`. The existing Audit counter records the
affected operation; the dependency counter records the root serving boundary.
Neither contains a tenant, artifact, SQLSTATE or error message.

After a failed POST, do not infer a Decision from local logs or evaluator
output. A Decision is authoritative only if the response contains it and a
subsequent authorized read verifies the committed Store/Audit binding.
Admission that committed before a later dependency failure remains fenced; an
exact retry can reclaim it only after lease expiry and can then produce only
the existing generation-fenced recovery `Decision(ERROR)`.

## Persistence race verification

DS-036 provides one focused, repeatable gate for the migrations and durable
races that protect Shadow Mode. The configured test role must be able to create
and drop isolated PostgreSQL databases:

```bash
ATF_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
ATF_PERSISTENCE_TEST_REPETITIONS=2 ./scripts/test-persistence.sh
```

The suite covers migration/append-only constraints, concurrent Audit append,
atomic lifecycle finalization, idempotency fencing/recovery, Nonce replay,
Gateway restart/two-instance convergence, dependency rollback, lock timeout and
real deadlock classification. Every lock/deadlock test has a five-second outer
deadline. CI executes two complete repetitions before the full workspace test
gate.

For an isolated CI-equivalent run without a host PostgreSQL:

```bash
ATF_PERSISTENCE_TEST_REPETITIONS=2 \
  docker compose -f deploy/docker/compose.test.yml run --rm persistence-tests
docker compose -f deploy/docker/compose.test.yml down --volumes
```

This is a test stack, not the DS-039 supported local Gateway stack. PostgreSQL
uses temporary storage, source is mounted read-only, and Cargo registry/target
volumes are disposable. Compose defaults to one linker and no test debug
symbols to remain reliable on small Docker Desktop/CI memory allocations.

## HTTP safety boundary

All limits are finite, validated at startup and process-local. Zero, malformed
or values above the compiled safety ceilings prevent startup. Defaults are:

| Environment variable | Default | Meaning |
|---|---:|---|
| `ATF_MAX_REQUEST_BODY_BYTES` | `262144` | Maximum buffered body on every route |
| `ATF_MAX_REQUEST_HEADER_BYTES` | `32768` | Aggregate Header names, values and separators |
| `ATF_MAX_REQUEST_HEADERS` | `64` | Parsed Header value count |
| `ATF_REQUEST_TIMEOUT_MILLIS` | `30000` | Whole application request, including body receive |
| `ATF_EVALUATION_TIMEOUT_MILLIS` | `15000` | Nested `POST /v1/intents` Handler deadline; cannot exceed request timeout |
| `ATF_SOURCE_RATE_LIMIT_PER_MINUTE` | `600` | GCRA rate per direct socket IP |
| `ATF_SOURCE_RATE_LIMIT_BURST` | `100` | Immediate source burst |
| `ATF_PRINCIPAL_RATE_LIMIT_PER_MINUTE` | `120` | GCRA rate per domain-hashed Agent/Operator |
| `ATF_PRINCIPAL_RATE_LIMIT_BURST` | `30` | Immediate principal burst |
| `ATF_RATE_LIMIT_MAX_KEYS` | `4096` | Maximum retained keys in each source/principal map |

The source key is the TCP peer IP, never `Forwarded`, `X-Forwarded-For` or
`X-Real-IP`. Those and related forwarding Headers are stripped before route
logic. Agent quota is charged only after a read-only verification of the exact
current durable Key and signature; admission repeats verification under lock
to close lifecycle races. Operator quota is charged after RFC 9068/JWKS
verification. Only domain-separated SHA-256 keys are retained, not raw
principal identifiers. Operational quota does not change Audit history or the
DS-031 financial `REQUESTED` velocity rule.

Rejections use the normal request ID and safe envelope:

| HTTP | Code | Condition |
|---:|---|---|
| 408 | `REQUEST_TIMEOUT` | Whole application request exceeded its deadline |
| 413 | `REQUEST_BODY_TOO_LARGE` | Buffered body exceeded the configured maximum |
| 429 | `RATE_LIMITED` | Source or verified principal exceeded GCRA; includes `Retry-After` |
| 431 | `REQUEST_HEADERS_TOO_LARGE` | Parsed Header bytes/count exceeded its maximum |
| 504 | `EVALUATION_TIMEOUT` | Intent Handler exceeded its nested deadline |

Every response also sets `Cache-Control: no-store`,
`X-Content-Type-Options: nosniff` and `Referrer-Policy: no-referrer`.

### TLS and trusted proxy boundary

The binary currently serves plaintext. `ATF_BIND_ADDRESS` defaults to
`127.0.0.1`; a non-loopback address is rejected unless
`ATF_TLS_TERMINATED_BY_TRUSTED_PROXY=true`. That flag is an explicit deployment
assertion, not TLS implementation or proxy authentication. A non-loopback
deployment must additionally:

1. terminate TLS at a controlled ingress and encrypt/protect the ingress-to-
   Gateway hop;
2. firewall the Gateway port so only that ingress can connect directly;
3. enforce handshake, incomplete-Header/parser byte limits and any global
   multi-instance source quota at ingress;
4. set HSTS and any public CORS policy at the HTTPS ingress; the Gateway does
   not infer scheme or client identity from forwarding Headers.

The application request deadline starts after Hyper has parsed the request
Headers. This is why slow/incomplete Header protection remains an ingress
responsibility, while slow/incomplete bodies are covered by the Gateway
deadline. Behind one proxy, all connections share its source bucket by design;
verified-principal buckets still separate authenticated callers.

## Cardinality and redaction contract

Metric dimensions are closed enums in code. The route label is an Axum route
template or `UNMATCHED`; it is never the raw path or query. The method and
status labels collapse to fixed sets. The following must never appear as a
metric label or value:

- organization, Agent, Operator, Intent, Evaluation, Decision, request, or
  replay IDs;
- raw paths, query strings, error text, Policy IDs, Risk rule IDs, or finding
  messages;
- Authorization/JWT values, identity envelopes, Nonces, signatures, private
  keys, full request/response bodies, amounts, destinations, or arbitrary
  context.

Gateway logs are JSON. The request span allowlist is `request_id`, fixed HTTP
method, route template, status, and duration. Stable business events may add
an error code, fixed operation, Decision kind, Audit event ID, or page count.
Audit event IDs are allowed only in logs for correlation and never in metric
labels. Payloads, credentials, signatures, raw URLs, SQL/Policy diagnostics,
and financial fields are forbidden. Captured-log tests send canary credentials
and payload data and fail if any are emitted.

## Request, trace, and Audit correlation

Every request ignores a caller-supplied correlation value, creates a fresh
server ULID, and returns it as `X-ATF-Request-ID`. The same value is attached to
the `http.request` span. Successful admission, finalization, Policy mutation,
and verified Audit-page events log their durable `audit_event_id` inside that
span.

To investigate a response:

1. copy its `X-ATF-Request-ID`;
2. find the `http.request.completed` JSON event with that span value;
3. inspect a stable event such as `decision.finalized` or
   `audit.page.returned` in the same span;
4. verify the named event through the authenticated organization-scoped Audit
   API or offline chain tooling.

The correlation log is navigation evidence, not an alternative Audit ledger.
PostgreSQL canonical events and their verified hash chain remain authoritative.

## Initial alert guidance

Before DS-039 measures a workload baseline, use symptom alerts rather than
claiming SLO-derived thresholds:

- page on sustained `5xx` request growth or readiness failure;
- page immediately when `atf_gateway_audit_failures_total` increases;
- page on any sustained `DATABASE`, `AUDIT` or `LOCK` dependency failure;
- investigate `ACTIVE_POLICY` or `HISTORY_SNAPSHOT` immediately before
  returning an instance to serving rotation;
- investigate `atf_gateway_replay_metrics_available == 0`;
- investigate increases in Policy/Risk `ERROR`, Decision `ERROR`, or
  high/critical Risk findings;
- compare latency histograms by fixed route/module, never by tenant or ID.

DS-039 owns measured SLOs, dashboard thresholds, retention, and recovery
procedures. DS-034 owns the application scrape/request boundary; DS-035 owns
standardized dependency-failure behavior.
