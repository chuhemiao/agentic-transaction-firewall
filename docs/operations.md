# Gateway Operations

This runbook describes the current Durable Shadow observability boundary. It
does not grant execution authority: the Gateway still evaluates and records,
and cannot sign or submit a transaction.

## On-call questions

The DS-033 signals are designed to answer four questions without inspecting a
financial payload:

1. Is the HTTP surface available, and which fixed route/status class is slow?
2. Are finalized Decision outcomes or exact-idempotency retries changing?
3. Is Policy or Risk slow, failing closed, or producing more findings?
4. Are Evidence freshness, durable Replay evidence, or Audit reads/writes
   unhealthy?

## Metrics endpoint

`GET /metrics` returns Prometheus text format. It currently has no application
credential because it is an infrastructure scrape endpoint, not a business
API. Until DS-034 supplies explicit TLS/proxy/request/rate boundaries, expose
it only on a trusted private operations network or authenticated ingress; do
not publish it directly to the Internet.

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

HTTP, Decision, evaluator, idempotency, freshness, and Audit-failure metrics
are process-local. Sum counters across Gateway instances; do not sum histogram
quantiles. Replay runs in an offline CLI, so its two counters are read from
durable typed Audit evidence on each scrape rather than a misleading local
process counter. If that aggregate is unavailable, the scrape still exposes
process metrics, sets `atf_gateway_replay_metrics_available` to `0`, and
increments the Audit read-failure counter.

Simulation latency, Adapter errors, Approval wait, Kill Switch, settlement,
and reconciliation metrics are intentionally absent because those components
do not exist. Their metric contracts must be added with the component that can
produce truthful observations.

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
- investigate `atf_gateway_replay_metrics_available == 0`;
- investigate increases in Policy/Risk `ERROR`, Decision `ERROR`, or
  high/critical Risk findings;
- compare latency histograms by fixed route/module, never by tenant or ID.

DS-039 owns measured SLOs, dashboard thresholds, retention, and recovery
procedures. DS-034/DS-035 own scrape exposure limits and standardized
dependency-failure behavior.
