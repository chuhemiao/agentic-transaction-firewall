# Identity Envelope v1

This document fixes the DS-014 Agent identity signature contract. It defines
the pure domain boundary only: DS-015 persists Agent/key lifecycle, and DS-016
verifies this envelope plus atomically consumes its nonce during Gateway
admission. An envelope that verifies proves which registered Agent signed one
exact Intent; it never grants permission to bypass Policy or Risk.

## Objective

Replace the ambiguous legacy signature over the hexadecimal Intent hash with
one versioned, domain-separated message. The signed bytes bind the tenant,
Agent, exact key, Intent, request lifetime, nonce, target service and runtime
environment so a signature cannot be replayed into another ATF context.

The public Rust seams are:

- `IdentityEnvelope::canonical_bytes` for SDK-compatible signing bytes;
- `IdentityEnvelope::validate` for pure binding and time validation;
- `IdentityRegistry::verify_envelope` for Agent status, exact-key selection
  and strict Ed25519 verification.

## Envelope fields

Every field is a JSON string and every object rejects unknown fields.

| Field | Contract |
|---|---|
| `domain` | Exactly `ATF_INTENT_V1` |
| `organization_id` | Exact `Intent.principal.organization_id` |
| `agent_id` | Exact `Intent.principal.agent_id` |
| `key_id` | Selects one registered key; verification never tries every key |
| `intent_hash` | Lowercase 64-character SHA-256 hex of canonical Intent bytes |
| `issued_at` | Millisecond-aligned RFC 3339 UTC timestamp |
| `expires_at` | Millisecond-aligned RFC 3339 UTC timestamp |
| `nonce` | Opaque single-use identifier; durable consumption is DS-016 |
| `audience` | Exact trusted verifier configuration |
| `environment` | Exact trusted verifier and Agent deployment environment |

Identifiers are 1 to 128 ASCII bytes and use only letters, digits, `.`, `_`,
`:`, or `-`. Nonces are 16 to 128 bytes under the same alphabet. ATF never
trims, case-folds or normalizes them. The restricted alphabet makes the wire
bytes portable and avoids visually equivalent identifier encodings.

## Canonical signing bytes

Canonical bytes are UTF-8 encoded, compact JSON with keys sorted by ascending
bytewise field name and no trailing newline. `atf_core::sort_json_keys` must be
used explicitly; workspace feature unification means callers cannot rely on
`serde_json::Map` iteration order. Since every value is an ASCII string, this
contract does not depend on cross-language Unicode escaping choices.

The field order is therefore:

```text
agent_id, audience, domain, environment, expires_at,
intent_hash, issued_at, key_id, nonce, organization_id
```

The literal `domain` value is inside the signed object. Signing the raw Intent
hash, a differently named domain, pretty-printed JSON, or a caller-supplied
field order produces different bytes and must fail verification.

## Time and binding rules

Verification receives an explicit trusted `verification_time`, `audience` and
`environment`; it never reads the wall clock internally. All comparisons are
fail closed:

1. `issued_at < expires_at`.
2. Envelope lifetime is at most five minutes.
3. `issued_at <= verification_time < expires_at`; expiry is exclusive and no
   implicit clock-skew allowance exists.
4. `Intent.created_at <= issued_at` and `expires_at <= Intent.expires_at`.
5. Organization, Agent and Intent hash exactly match the supplied Intent.
6. Audience and environment exactly match trusted verifier configuration.
7. The registered Agent organization and deployment environment exactly match
   the verified envelope, and its status/lifetime allow submission.

The fixed five-minute window limits a stolen signature's useful lifetime while
DS-016 supplies the stronger single-use nonce guarantee. Deployments that need
clock tolerance must synchronize clocks; silently widening the signed window
is not part of v1.

## Registry and key selection

Keys are addressed by `(agent_id, key_id)`. Duplicate registration of that
pair fails instead of replacing key material. Verification looks up only the
declared pair and uses strict Ed25519 verification over canonical bytes. There
is no legacy raw-hash verifier and no “try every key until one works” fallback.
Key activation, expiry, revocation and durable rotation overlap are DS-015.

A successful verification returns a `VerifiedIdentity` containing the exact
organization, Agent, key ID, nonce and envelope expiry. DS-016 will consume the
nonce and re-check durable key state before admission; this value alone is not
authorization and is not an execution grant.

## Errors and information boundary

Every rejection maps to a stable `IdentityError::code()`. Errors may identify
the rejected field or non-secret Agent/key IDs for internal Audit evidence,
but never include signature bytes, public-key bytes or private material.
Gateway response redaction remains the responsibility of DS-016's API mapping.

| Code | Meaning |
|---|---|
| `IDENTITY_DOMAIN_MISMATCH` | Unsupported signing domain |
| `IDENTITY_ENVELOPE_FIELD_INVALID` | Noncanonical identifier, hash or timestamp |
| `IDENTITY_ORGANIZATION_MISMATCH` | Envelope and Intent organizations differ |
| `IDENTITY_AGENT_MISMATCH` | Envelope and Intent Agents differ |
| `IDENTITY_INTENT_HASH_MISMATCH` | Envelope does not bind the supplied Intent |
| `IDENTITY_AUDIENCE_MISMATCH` | Trusted audience differs |
| `IDENTITY_ENVIRONMENT_MISMATCH` | Trusted environment differs |
| `IDENTITY_ENVELOPE_TIME_RANGE_INVALID` | `issued_at >= expires_at` |
| `IDENTITY_ENVELOPE_LIFETIME_EXCEEDED` | Envelope exceeds five minutes |
| `IDENTITY_ENVELOPE_NOT_YET_VALID` | Verification precedes issuance |
| `IDENTITY_ENVELOPE_EXPIRED` | Verification is at/after expiry |
| `IDENTITY_ENVELOPE_OUTSIDE_INTENT_LIFETIME` | Envelope outlives the Intent boundary |
| `IDENTITY_AGENT_UNKNOWN` | No Agent record exists |
| `IDENTITY_AGENT_NOT_ACTIVE` | Agent status blocks submission |
| `IDENTITY_AGENT_ORGANIZATION_MISMATCH` | Registered Agent tenant differs |
| `IDENTITY_AGENT_ENVIRONMENT_MISMATCH` | Registered deployment differs |
| `IDENTITY_AGENT_NOT_YET_ACTIVE` | Envelope predates Agent creation |
| `IDENTITY_AGENT_EXPIRED` | Agent expired at verification time |
| `IDENTITY_ENVELOPE_EXCEEDS_AGENT_LIFETIME` | Envelope outlives Agent registration |
| `IDENTITY_KEY_ALREADY_REGISTERED` | Registration would replace a Key ID |
| `IDENTITY_KEY_NOT_REGISTERED` | Declared Key ID is unknown |
| `IDENTITY_SIGNATURE_INVALID` | Strict Ed25519 verification failed |

## Compatibility

This intentionally replaces the pre-release `register_key(agent_id, key)` and
`verify_intent_signature` interface. Callers must assign a stable `key_id`,
construct an `IdentityEnvelope`, and sign `canonical_bytes()`. Keeping the old
verifier would preserve a cross-protocol replay path, so v1 has no compatibility
fallback.

## Project and verification contract

- Source: `crates/atf-identity/src/`; public behavior tests:
  `crates/atf-identity/tests/envelope.rs`.
- Published cross-language fixture:
  `conformance/identity-vectors/atf-intent-v1.json`.
- Format: `cargo fmt --all -- --check`.
- Lint: `cargo clippy --all-targets --all-features -- -D warnings`.
- Test: `cargo test --workspace --all-targets --all-features`.
- Dependency policy: `cargo deny check`.

Always validate every bound field before accepting the signature and keep
identity separate from Policy/Risk authorization. Never add a raw-message
fallback, infer a key by trying candidates, read time implicitly, persist a
nonce in process memory, or log key/signature material.

DS-014 is complete when the literal canonical/signature vector is stable,
every bound-field mutation and wrong context/time/key case fails, exact key
selection is proven, the legacy verifier is absent, and the full workspace
quality gates pass.
