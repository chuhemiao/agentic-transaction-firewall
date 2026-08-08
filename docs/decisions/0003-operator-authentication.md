# ADR-0003: Verify operator JWT access tokens at the Gateway and authorize from durable ATF bindings

- **Status:** Accepted
- **Date:** 2026-08-08
- **Accepted:** 2026-08-08
- **Implemented:** DS-018, 2026-08-08
- **Approval:** Explicit ATF maintainer approval recorded in the project task
- **Decision owners:** ATF maintainers
- **Supersedes:** None
- **Related:** [PRD](../PRD.md), [Gateway API](../api.md), [identity](../identity.md), [architecture](../architecture.md), [threat model](../threat-model.md), [ADR-0002](0002-durable-state-contract.md)

## Context

ATF has two different callers with different authority:

1. an Agent submits a financial Intent using the domain-separated Ed25519
   Identity Envelope defined by DS-014..DS-016; and
2. a human or service operator reads Decisions and, later, administers Agents,
   Policy, Budget, Approval, and Audit resources.

The Agent proof is deliberately narrow. Treating it as operator identity would
turn a transaction-submission key into administrative authority and create a
confused deputy. Conversely, using an operator credential to synthesize an
Agent submission would bypass the Intent Envelope, exact Key, and Nonce
contract.

The current `GET /v1/intents/{intent_id}/decision` route has no caller
authentication. `X-ATF-Organization-ID` selects a PostgreSQL tenant key, but
any caller can forge it. The route therefore cannot be exposed to a shared or
untrusted network. The PRD requires independent operator identity, least-
privilege organization roles, no anonymous or shared accounts, and Audit
evidence for administrative actions.

This ADR fixes the reference trust boundary before DS-018 implements it. It
does not claim that the current Gateway is protected.

## Decision

### 1. Agent and operator principals are disjoint

Gateway authentication produces one typed `RequestPrincipal`:

- `AgentPrincipal` contains the verified organization, Agent, exact identity
  Key, Envelope, Nonce binding, and authenticated Intent hash required by the
  existing admission transaction.
- `OperatorPrincipal` contains an internal immutable operator ID, principal
  kind (`HUMAN` or `SERVICE`), configured issuer ID, external-subject
  fingerprint, organization membership, and the effective ATF roles loaded for
  that request.

An Agent Envelope can authenticate only an Agent submission. An operator token
can authenticate only an operator/admin route. There is no automatic
conversion, fallback, or role inheritance between the variants. A future
delegation or operator-on-behalf-of-Agent workflow requires a separate ADR,
endpoint, and Audit contract.

### 2. The Gateway is an OAuth resource server

The reference mechanism is a short-lived, asymmetrically signed JWT OAuth 2.0
access token conforming to RFC 9068, issued by one explicitly configured
OIDC-capable authorization server. A caller sends exactly one credential as:

```http
Authorization: Bearer <access-token>
```

The Gateway validates the token itself. It does not accept an ID token, cookie,
password, static API key, query parameter, client-supplied identity Header, or
reverse-proxy assertion as operator authentication. Browser clients obtain
access tokens outside ATF through Authorization Code + PKCE. Service principals
use a provider-managed confidential-client flow and receive their own subject;
they do not share a bearer secret or ATF account.

The following values are trusted startup configuration, not token-controlled
input:

- one exact HTTPS issuer URL and a stable local issuer ID;
- one exact ATF audience/resource identifier;
- an allowlist of asymmetric signature algorithms;
- the issuer metadata/discovery URL and its HTTPS `jwks_uri`;
- maximum token lifetime, clock skew, JWKS freshness, and network timeouts.

The reference defaults are a maximum 15-minute access-token lifetime and at
most two minutes of clock skew. Deployments may make either stricter. Raising
the token lifetime above one hour is invalid configuration.

For every request, validation must:

1. require `typ` to be exactly `at+jwt` or `application/at+jwt`;
2. reject `alg=none`, symmetric algorithms, and any algorithm outside the
   configured allowlist;
3. verify the signature using a key from the configured issuer only;
4. match `iss` exactly and require the configured ATF value in `aud`;
5. require valid `exp` and `iat`, enforce the maximum lifetime and token age,
   and enforce `nbf` when present using the bounded skew;
6. require a non-empty stable `sub`; and
7. select one signing key by a bounded `kid` without trying every unrelated
   key.

Token `jku`, `x5u`, embedded JWK, or other token-selected key locations are
never dereferenced. Unknown `kid` may trigger one bounded refresh from the
configured `jwks_uri`; refresh failure, ambiguous keys, stale-beyond-limit
cache, or invalid metadata fails closed. JWKS refresh is bounded and may keep
previous keys only for the configured overlap. Readiness fails when no fresh,
usable verification key set is available.

### 3. PostgreSQL, not token claims, grants ATF authority

A valid JWT proves only the external subject `(issuer, sub)`. DS-018 will add
PostgreSQL-authoritative records equivalent to:

- an operator subject binding from `(issuer_id, SHA-256(issuer || 0x00 ||
  sub))` to one immutable internal `operator_id`, principal kind, and lifecycle
  status; and
- zero or more explicit `(operator_id, organization_id, role)` bindings with
  lifecycle state.

The raw external subject, email, display name, token, and token signature are
not stored in ATF Audit evidence. Email, groups, scopes, organization, role,
and entitlement claims are not durable ATF authorization. They may be retained
only as non-authoritative diagnostics after a separate privacy review.

Every protected request reloads and verifies the local subject status and
organization-role bindings. A disabled subject or removed role therefore
takes effect immediately even while an access token remains cryptographically
valid. Authentication or authorization caches must not outlive the request in
DS-018. Operator provisioning initially uses an offline, database-backed CLI
from a trusted administrative host. That bootstrap path is authorized by the
deployment's individual OS/database administrator credential, records an
attributable internal actor and typed Audit event, and is not accepted by any
HTTP route. Shared database credentials are forbidden for that workflow; there
is no bootstrap admin HTTP route or anonymous first-user flow.

The minimum roles remain those in PRD §17.3:

| Role | Capability boundary |
|---|---|
| `org_admin` | Manage Agent and Budget state; does not implicitly publish Policy or approve |
| `policy_author` | Publish Policy; cannot approve its effect |
| `approver` | Act on Approval requests; cannot publish Policy |
| `auditor` | Read-only Decision and Audit access |

Capabilities are an explicit route matrix; no role is an implicit superuser.
A principal may hold multiple explicitly provisioned roles, but future high-
risk production operations still require the PRD's distinct multi-party
approval and separation-of-duty rules.

For the current API, `GET /v1/intents/{intent_id}/decision` requires an
`OperatorPrincipal` bound to the selected organization with `auditor` or
`org_admin`. `POST /v1/intents` continues to require `AgentPrincipal` only.
`/healthz` and `/readyz` remain unauthenticated and expose only their current
minimal probe result.

`X-ATF-Organization-ID`, and any future organization in a path or body, is a
selector only. It must match an active role binding and the resource's durable
organization. It never grants tenant authority. For resource reads, a missing
resource, cross-organization selector, and insufficient read role all return
the same `404 DECISION_NOT_FOUND` shape so the response cannot confirm another
tenant's resource. A valid principal denied a non-resource action returns a
generic 403. Missing, malformed, expired, or unverifiable credentials return a
generic 401 and a safe `WWW-Authenticate: Bearer` challenge.

### 4. Rotation and revocation are bounded and fail closed

- The identity provider rotates signing keys through the configured HTTPS
  JWKS endpoint with a bounded old/new overlap. The Gateway refreshes before
  expiry and never uses a stale-beyond-limit key set.
- ATF subject disable and role removal are checked from PostgreSQL on every
  request and are immediate local revocation mechanisms.
- Identity-provider account or client revocation is bounded by the remaining
  short access-token lifetime unless the provider guarantees a stronger
  revocation signal. Operators must locally disable a subject during an
  emergency; ATF does not pretend a cached self-contained token was remotely
  revoked.
- Refresh tokens, authorization codes, client secrets, and private keys never
  enter the Gateway. Raw bearer tokens are never persisted, logged, included
  in errors, traces, metrics, or Audit payloads.
- An operator Audit event records the internal operator ID, organization,
  effective role/capability, request ID, and outcome, not credential material.

### 5. TLS termination does not become identity delegation

Production/shared deployment requires HTTPS at a trusted ingress. The
ingress-to-Gateway hop must also be private and protected against observation,
injection, and replay, for example authenticated mTLS/service-mesh transport or
same-host loopback with equivalent isolation. Direct public access to the
plaintext Gateway port is forbidden.

The proxy must strip spoofable security Headers and forward the original
`Authorization` value only over that protected hop. The Gateway still validates
the access token. `Forwarded`, `X-Forwarded-*`, client-certificate Headers, and
custom identity Headers are not operator authentication. DS-034 must implement
and test bounded Header/body/time/rate controls plus the concrete proxy and TLS
deployment profile before the service is called shared-network ready.

Reference Durable Shadow Mode uses audience-restricted bearer tokens over this
TLS boundary. Sender-constrained access tokens (mTLS-bound or DPoP) are required
to be reconsidered in a separate accepted ADR before production Policy, Kill
Switch, Approval, or Enforce authority is exposed.

## Required invariants

DS-018 and its tests must demonstrate all of the following:

1. Every non-health request has exactly one typed Agent or Operator principal.
2. Agent proof can never authorize operator/admin behavior, and an operator
   token can never bypass Agent admission.
3. No organization selector, proxy Header, email, scope, group, or token role
   grants ATF authority without an active PostgreSQL binding.
4. Wrong issuer, audience, type, algorithm, signature, time, subject, or Key ID
   fails before route logic and without credential leakage.
5. Removed roles and disabled local subjects fail on the next request.
6. Cross-tenant and wrong-role resource reads are non-enumerating.
7. Every service principal is individually attributable; no shared account or
   anonymous bootstrap path exists.
8. Token/JWKS failures fail closed and cannot be converted into Permit or a
   partially trusted principal.
9. High-risk mutations retain separation of duty and cannot be authorized by
   a broad implicit admin role.
10. Raw tokens and external PII do not enter Audit, logs, metrics, traces, or
    HTTP errors.

## Threat and abuse review

| Threat | Failure mode | Required control/test |
|---|---|---|
| Spoofing | Forge `X-ATF-Organization-ID` or a proxy identity Header | Header is only a selector; direct token verification plus durable binding |
| Spoofing | Present an ID token, wrong-issuer token, or wrong-audience token | Explicit `typ`, exact `iss`, and exact `aud` rejection tests |
| Tampering | `alg=none`, algorithm confusion, or token-selected JWKS URL | Fixed asymmetric allowlist; never dereference `jku`/`x5u`; mutation tests |
| Repudiation | Shared service credential hides the actor | One provider subject and internal operator ID per human/service principal |
| Information disclosure | Cross-tenant Decision enumeration or bearer token logging | Uniform 404 resource denial; redaction assertions across errors/logs/Audit |
| Denial of service | Unknown `kid` or JWKS outage triggers unbounded fetches | One bounded refresh, finite cache/timeouts, readiness/auth fail closed |
| Elevation of privilege | Agent signature reused as admin auth | Disjoint principal variants and route extractors |
| Elevation of privilege | Stale token role survives local removal | Ignore role claims; check durable bindings on every request |
| Confused deputy | Multi-org operator selects a resource in another tenant | Bind selector, role, resource organization, and Audit organization together |
| Replay | Stolen bearer token is replayed within its lifetime | TLS, exact audience, short lifetime; revisit sender constraint before Enforce |

## Alternatives considered

### Local passwords or static hashed API keys

Rejected as the reference mechanism. They move password/MFA/recovery and
credential-distribution responsibilities into ATF, encourage shared service
secrets, and provide weaker rotation attribution. A future pluggable verifier
must receive its own ADR and preserve the same typed-principal and durable-role
invariants; it cannot become a silent fallback.

### Trust reverse-proxy identity Headers

Rejected. A direct-port bypass, proxy misconfiguration, or unsanitized inbound
Header can forge the principal. The proxy remains a TLS/network control, while
the Gateway remains the token-validation boundary.

### Use mTLS certificates as the only operator identity

Rejected as the sole human/RBAC mechanism because certificate issuance and
revocation do not by themselves express ATF organization roles or human
account lifecycle. mTLS remains valid for the proxy-to-Gateway hop and may
later sender-constrain access tokens.

### Opaque tokens with per-request introspection

Deferred. Introspection can improve central revocation but adds an online
authorization-server dependency and latency to every request. A future
implementation may use it if it preserves exact issuer/audience validation,
bounded failure, and PostgreSQL-authoritative ATF roles.

### Carry organization and roles only in JWT claims

Rejected. Long-lived claim authority makes local role removal stale, couples
ATF roles to provider conventions, and increases cross-tenant confused-deputy
risk. JWT claims authenticate the external subject; ATF's database authorizes
the subject.

### Reuse the Agent Identity Envelope

Rejected. Agent keys authorize one signed Intent, while operator credentials
authorize administrative capabilities. Combining them violates least
privilege and turns compromise of either credential into broader authority.

## Consequences

- DS-018 needs JWT/JWKS validation, durable operator subject/role persistence,
  offline provisioning, typed principals, stable error mapping, and real
  PostgreSQL/HTTP role-matrix tests.
- Protected requests add one local authorization lookup; correctness and
  immediate ATF revocation take priority over a premature permission cache.
- The authorization server and JWKS endpoint become bounded authentication
  dependencies. Their failure denies operator routes and may fail readiness;
  it never creates anonymous access.
- External account revocation is not instantaneous for an already issued
  self-contained token. Short lifetime plus local emergency disable makes the
  residual window explicit.
- DS-018 closes the application principal/RBAC gap only. DS-033/DS-034 and a
  production deployment review remain required before shared exposure.

## Implementation gate

The ATF maintainer explicitly approved the reference mechanism and residual
bearer-token window on 2026-08-08. That approval closes the DS-017 design gate;
at approval time it did not claim that Operator authentication or RBAC already
existed. DS-018 subsequently implemented and verified the accepted boundary
before the Decision route was marked protected.

DS-018 landed as one reviewable vertical slice:

1. migration and `atf-store` APIs for immutable operator subjects and
   organization-role lifecycle;
2. offline subject/role provisioning with typed Audit evidence;
3. bounded issuer/JWKS configuration and RFC 9068 validation;
4. typed route principals and the current Decision-read role matrix;
5. wrong-token, revoked-role, cross-tenant, confused-deputy, restart, redaction,
   and authenticated real-HTTP smoke tests.

The gate is satisfied for the current `GET Decision` surface. Migration 0006,
`atf-store` Operator/Role verification, offline `atf operator` commands,
configured HTTPS JWT/JWKS validation, typed principals and the
`auditor`/`org_admin` non-enumerating role matrix are implemented and covered
by PostgreSQL/Gateway/CLI tests. DS-034 and future endpoint-specific role
matrices remain outside this ADR's implementation claim.

## References

- [RFC 6750 — OAuth 2.0 Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [RFC 8725 — JSON Web Token Best Current Practices](https://datatracker.ietf.org/doc/rfc8725/)
- [RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)
- [RFC 9700 — Best Current Practice for OAuth 2.0 Security](https://datatracker.ietf.org/doc/rfc9700/)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [RFC 8705 — OAuth 2.0 Mutual-TLS Client Authentication and Certificate-Bound Access Tokens](https://datatracker.ietf.org/doc/html/rfc8705)
