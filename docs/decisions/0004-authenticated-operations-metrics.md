# ADR-0004: Isolate metrics behind an authenticated operations principal

- **Status:** Accepted
- **Date:** 2026-08-09
- **Approval:** Explicitly approved by an ATF maintainer on 2026-08-09
- **Decision owners:** ATF maintainers
- **Supersedes:** None
- **Related:** [PRD](../PRD.md), [Gateway API](../api.md),
  [operations](../operations.md), [architecture](../architecture.md),
  [threat model](../threat-model.md),
  [release-candidate checklist](../release-candidate-checklist.md),
  [ADR-0003](0003-operator-authentication.md)

## Context

DS-040 found one current-scope contradiction that blocks Checkpoint C4.
`GET /metrics` is served by the same Gateway Router as business APIs, but it
does not form an Agent or Operator principal. Private-network placement and
fixed, redacted labels reduce exposure; they do not satisfy PRD §22 and
§32.2.2 authentication and minimum-RBAC requirements.

The correction has a second non-negotiable constraint. Metrics must remain
available during PostgreSQL loss so an operator can observe the outage. The
current handler deliberately renders process metrics and
`atf_gateway_replay_metrics_available 0` when the durable Replay aggregate
cannot be read. Reusing ADR-0003's Operator authorization path would reload
PostgreSQL roles on every scrape and make that evidence unavailable during the
failure it is intended to diagnose.

The selected design must therefore prove all of the following:

1. an unauthenticated caller cannot scrape Metrics;
2. Metrics authentication and minimum authorization do not depend on
   PostgreSQL or live JWKS access;
3. a Metrics credential cannot call a business, read, or mutation route;
4. the business listener does not expose `/metrics` and the Metrics upstream
   is not directly reachable outside the trusted edge boundary;
5. the existing body, Header, timeout, source-rate, redaction, fixed-label and
   database-outage semantics remain bounded and tested; and
6. this narrow operations identity cannot silently become an alternative
   Operator, Agent, bootstrap, or administrative authentication flow.

This ADR defines the accepted boundary and narrowly amends PRD §22/§32.2.2 to
admit the disjoint Metrics-only Operations service principal described below.

## Decision

### 1. Separate business and operations surfaces

The Gateway business Router will no longer register `GET /metrics`. Requests
for that path on the business listener return the normal safe `404` contract,
including when the caller has a valid Agent or Operator credential.

The same process will expose a metrics-only Router through a Unix-domain
socket. That Router accepts exactly `GET /metrics`; it has no Intent, Decision,
Audit, Policy, health, readiness, fallback administration, or future execution
route. The socket is created fail-closed with bounded path/configuration and
filesystem permissions and is mounted only into the Gateway and trusted edge
containers. It is never published as a host port or attached as a general
container-network TCP listener.

The operations edge exposes a distinct TLS listener. The supported local
topology binds it to a separate loopback host port; any future shared topology
must place it on an explicitly private operations network. The existing
business TLS listener cannot proxy to the Metrics socket.

This is a real routing and reachability split, not a documentation-only rename
of the current anonymous route.

### 2. Authenticate a disjoint `OperationsPrincipal` with mTLS

The operations TLS listener requires and verifies a client certificate from a
dedicated Metrics-reader trust pool. The certificate must be within its
validity interval, be valid for TLS client authentication, and map to one
bounded service identity. A certificate accepted by the normal server CA,
Operator IdP, Agent registry, or an unrelated deployment CA is not sufficient.

After successful verification, the trusted edge forms this closed principal:

```text
OperationsPrincipal {
  principal_kind: SERVICE,
  credential_fingerprint:
    SHA-256("ATF_OPERATIONS_MTLS_V1" || 0x00 || DER(leaf SPKI)),
  capability: METRICS_READ
}
```

The edge strips every caller-supplied operations-identity Header and forwards
only a canonical verified assertion over the Unix socket. The metrics-only
Router accepts that assertion only on the Unix-socket server and converts it
to the typed principal before invoking the handler. The business Router never
recognizes the assertion. A TCP request, a forged Header, a normal Operator
JWT, an Agent Envelope, or a certificate without the dedicated trust chain
cannot form an `OperationsPrincipal`.

The raw certificate, subject DN, SAN, private key and assertion are not written
to ATF Audit, metrics, application traces or errors. The hashed SPKI
fingerprint may appear only in bounded operations-edge access evidence; it is
not a label and grants no tenant or financial authority.

This narrowly extends the PRD principal invariant from “Agent or Operator” to
“Agent, Operator, or Metrics-only Operations service” for the separately
exposed operations surface. It does not weaken ADR-0003: reverse-proxy
assertions remain forbidden as Operator authentication, PostgreSQL remains the
authority for every Operator role, and no business route accepts the new
principal. Approval of this ADR must explicitly approve that PRD amendment.

### 3. Make minimum RBAC structural

`METRICS_READ` is the only capability available to an
`OperationsPrincipal`. It is granted by the dedicated client-certificate trust
pool and the metrics-only route matrix, not by token claims, organization
selectors, request Headers or PostgreSQL state.

Metrics remain organization-neutral: the response contains no organization,
Agent, Operator, Intent, artifact, Policy, Risk-rule or credential labels.
There is no organization selector to authorize. Adding any tenant-scoped
metric, second operations capability, configuration endpoint, debug endpoint,
profiling endpoint or administrative route requires a new accepted ADR and
cannot reuse this principal implicitly.

### 4. Preserve outage observability and fail closed on authentication

Client-certificate validation uses the edge's locally loaded trust material;
it never queries PostgreSQL and does not require a per-request IdP/JWKS call.
When PostgreSQL is unavailable, an authorized scrape still returns process
metrics, records the bounded dependency failure and reports durable Replay
availability as `0`.

Missing, malformed, untrusted, expired or not-yet-valid client certificates
fail the TLS handshake before HTTP. Missing/invalid edge trust configuration
or an unsafe/exported socket configuration prevents the operations listener
from starting. These failures never fall back to anonymous Metrics, Operator
JWT, Agent identity, plaintext or the business listener.

The business serving path may remain available if only the operations listener
is unavailable, but the supported topology is not C4-conformant or ready for a
release-candidate drill until authenticated Metrics passes its own health and
smoke evidence.

### 5. Keep certificate lifecycle outside the financial core

The Gateway does not issue client certificates and never receives client
private keys. The supported local stack may generate a development-only
Metrics-reader certificate into a non-committed restricted volume for its
executable smoke test. Shared deployments must use their existing workload PKI
or service-mesh certificate lifecycle, with individually attributable service
identities, bounded certificate lifetime and documented emergency revocation.

Changing the trust pool is a deployment security mutation. It must be
reviewable, atomic and followed by an authenticated/unauthenticated scrape
test. This ADR does not claim production PKI, CRL/OCSP, HSM, HA or shared
ingress readiness.

## Required invariants and executable evidence

Implementation may close `C4-GAP-001` only when all of these pass:

1. business-Router unit tests prove `/metrics` is absent for anonymous, Agent
   and Operator requests;
2. metrics-Router tests require a typed `OperationsPrincipal` and expose no
   other method or route;
3. forged/duplicate/oversized operations assertions fail, and the business
   Router never consumes them;
4. live TLS tests reject an absent certificate, the wrong CA,
   expired/not-yet-valid certificates, wrong EKU and an unapproved identity;
5. one approved Metrics-reader certificate succeeds on the operations port
   and fails on every business route;
6. the operations port is loopback/private, the business edge does not proxy
   `/metrics`, and neither Gateway TCP nor the Unix socket is host-accessible;
7. PostgreSQL loss leaves authenticated Metrics available with
   `atf_gateway_replay_metrics_available 0` while readiness and financial
   admission fail closed;
8. fixed-label, redaction, Request-ID, finite Header/body, timeout and
   source-rate tests remain green on the new surface;
9. restart and certificate/trust-pool rotation do not create an anonymous
   interval; and
10. the clean supported Compose drill, full Rust DoD and DS-038 security gates
    pass from empty local state.

## Threat and abuse review

| Threat | Abuse case | Required control |
|---|---|---|
| Spoofing | Present no certificate or a certificate from the server/Operator CA | Dedicated client trust pool, clientAuth validation and handshake rejection |
| Spoofing | Inject the edge's operations assertion on the business port | Edge strips it; business Router ignores it; assertion is accepted only over the protected Unix socket |
| Tampering | Replace the socket or route business traffic into the metrics upstream | Exact socket path/permissions, narrow volume mounts and route-inventory tests |
| Repudiation | Share one Metrics credential across unrelated scrapers | One service certificate/fingerprint per scraper identity and bounded edge access evidence |
| Information disclosure | Add tenant IDs or raw credentials to Prometheus labels | Closed fixed-label renderer plus captured redaction/cardinality tests |
| Denial of service | Abuse TLS handshakes or slow scrapes | Edge handshake bounds plus existing finite HTTP timeout/source-rate controls |
| Elevation of privilege | Reuse Metrics mTLS identity on Decision, Audit or Policy routes | Physically separate listener/Router and one closed `METRICS_READ` capability |
| Availability | Database/JWKS outage prevents diagnosing the failure | Local mTLS verification; Metrics handler degrades only the durable aggregate to unavailable |

## Alternatives considered

### Reuse ADR-0003 Operator JWT and PostgreSQL roles

Rejected as the reference Metrics path. It satisfies existing Operator
attribution but makes every scrape depend on PostgreSQL role reload. Caching a
last-known role would weaken ADR-0003's next-request revocation and introduce a
new stale authorization authority during an outage.

### Trust only a private network, firewall or unexported Docker port

Rejected. Reachability is defense in depth, not caller authentication or
minimum RBAC. This is the assumption that produced `C4-GAP-001`.

### Add a static Bearer token or shared API key

Rejected. It creates an unattributable shared secret, needs a new secret
distribution/rotation path and is explicitly outside ADR-0003's accepted
reference mechanisms.

### Terminate client mTLS inside the financial Gateway TCP listener

Rejected for the current local reference design. It would move server TLS key
material, certificate parsing and a second TLS policy into the financial core,
duplicate the existing edge and still require exact route separation. It may
be reconsidered for a deployment that has no trusted edge, through another
ADR.

### Keep `/metrics` on the business edge and require mTLS for the whole port

Rejected. It would force Agent and human Operator clients into the Metrics PKI,
mix identity domains and leave route-confusion risk. The operations credential
must not be accepted on a business surface.

### Remove Metrics or accept database-dependent outage blindness

Rejected. DS-033/DS-035 deliberately require safe failure telemetry. Removing
the evidence would close an access-control symptom by breaking the reliability
acceptance contract.

## Consequences

- C4-GAP-001 is implemented across Gateway Router/server separation, typed
  principal handling, trusted-edge configuration and live Compose evidence.
- The supported topology gains a second loopback/private TLS port and a
  development-only Metrics client credential lifecycle.
- ADR-0003 remains authoritative for every human/service Operator and every
  organization capability. ADR-0004 owns only aggregate
  `METRICS_READ` on the isolated operations surface.
- The operations edge and Unix-socket permission boundary become security-
  critical and must be included in configuration, secret, SAST and runtime
  review.
- This closes neither production PKI/readiness nor, by itself, independent C4
  approval.

## Approval and implementation record

The ATF maintainer approval recorded above explicitly accepted:

1. the new disjoint `OperationsPrincipal` and narrow PRD §22/§32.2.2 amendment;
2. mTLS at a separate operations edge as the reference authentication and
   minimum-RBAC mechanism;
3. the protected Unix-socket assertion boundary and its residual trusted-edge
   risk; and
4. the database-independent certificate lifecycle and revocation residuals.

The implementation removes Metrics from the business Router, adds the
metrics-only UDS Router and typed principal, provisions the separate mTLS edge
and development PKI, and makes every required invariant executable in Router,
resource-boundary, configuration and clean Compose tests. `C4-GAP-001` is
closed. At implementation time, C4 still required the separate independent
human sign-off in `C4-SIGNOFF-001`.

That separate sign-off was completed on 2026-08-10: the independent human
project-owner reviewer accepted the documented residual risks and approved
reviewed implementation commit `850477e` for Durable Shadow Checkpoint C4.
The approval permits RA-001 to begin and does not authorize production or
execution authority.
