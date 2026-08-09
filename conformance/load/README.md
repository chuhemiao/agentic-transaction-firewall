# DS-039 local Shadow load evidence

This directory records a measured baseline for the supported single-host
Compose stack. It does not redefine the targets in PRD §26 and does not claim
production readiness.

The generator is `atf-shadow-load`, built from the same locked workspace as the
Gateway. For every measured request it:

1. creates a unique, current, Profile-valid Transaction Intent;
2. creates and Ed25519-signs the canonical `ATF_INTENT_V1` envelope;
3. sends the request through the loopback-only Caddy TLS edge;
4. parses the response as the closed `atf_decision::Decision` type; and
5. recomputes the Decision hash before counting the sample as successful.

Latency is end-to-end client elapsed time for the HTTP request. P50/P95/P99 use
integer nearest-rank calculation. Throughput is emitted as a decimal string
with three fractional digits, so the measurement adds no floating-point type
to ATF. Warmups are excluded from the report.

Run the same bounded workload with:

```bash
ATF_LOCAL_LOAD_REQUESTS=50 \
ATF_LOCAL_LOAD_CONCURRENCY=4 \
ATF_LOCAL_LOAD_WARMUP_REQUESTS=5 \
  deploy/docker/local/run-load.sh
```

The committed `ds039-local-baseline.json` is evidence from one Docker Desktop
host. It compares, but does not replace, PRD §26's `<50 ms` no-external-
Simulation P95 and `>=100` Shadow evaluations/second targets. It does not test
1,000 active Agents, multiple hosts, HA PostgreSQL, shared ingress quota,
external data fetches, Simulation, Adapters, Approval, execution or settlement.

The checked-in run was taken after the full clean recovery/rollback sequence on
2026-08-09: macOS/Darwin 25.5.0 arm64 (`Mac17,8`, 18 host CPUs, 48 GiB host
RAM), Docker Engine/Desktop 29.6.1 with an 18-vCPU/8,319,213,568-byte LinuxKit
VM. Fifty measured requests at concurrency four all succeeded; P50/P95/P99
were 137/178/187 ms and throughput was 28.328 evaluations/second. Both PRD
latency and throughput targets were therefore unmet.
