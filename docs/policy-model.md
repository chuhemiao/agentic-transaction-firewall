# Signed durable Policy lifecycle

DS-019 defines the deterministic Policy Bundle identity. DS-020 makes that
identity installable, selectable and reversible without trusting a writable
directory at Gateway runtime.

## Detached publisher proof

The publisher signs one exact byte string with pure Ed25519 (RFC 8032):

1. ASCII domain `ATF_POLICY_BUNDLE_SIGNATURE_V1` followed by one NUL byte.
2. An unsigned 64-bit big-endian length and the UTF-8 publisher `key_id`.
3. An unsigned 64-bit big-endian length and the 64-byte lowercase ASCII
   `bundle_hash`.

The proof is a closed JSON object conforming to
`schemas/policy-bundle-signature.schema.json`:

```json
{
  "signature_version": "1",
  "algorithm": "Ed25519",
  "key_id": "publisher-2026",
  "bundle_hash": "<64 lowercase hex bytes>",
  "signature": "<128 lowercase hex bytes>"
}
```

Verification uses `ed25519-dalek::VerifyingKey::verify_strict`. The Key ID is
inside the signed message, and the Bundle Hash already binds manifest version,
Bundle ID/version, organization/environment, active window, Cedar Schema and
every exact policy-file digest. Any mismatch fails before installation or
evaluation. Private signing keys are never accepted by ATF.

## Durable state

Migration 0007 creates two guarded tables:

- `policy_bundles` stores the bounded exact-byte archive, archive hash,
  redundant Bundle identity/time columns, detached signature, publisher public
  key and hashes, installer Operator and install Audit pointer. The primary key
  makes `(organization, environment, bundle_id, policy_version)` unique;
  update, delete and truncate are rejected.
- `active_policy_bundles` stores one current pointer for each
  `(organization, environment, bundle_id)`, its immediately prior installed
  version/hash, monotonic lifecycle version and `PolicyChanged` event pointer.
  An update must select a different immutable Bundle, increment exactly once,
  and copy the old current version/hash into the previous fields.

Install, activation and rollback run under short PostgreSQL transactions. The
Store locks and verifies the current Operator/role evidence, requiring an
active `policy_author` or `org_admin`; verifies the full organization Audit
chain; revalidates Bundle bytes and signature; appends `PolicyChanged`; and
then writes the artifact or pointer. A conflict rolls both state and Audit
back. Concurrent activation of the same version has exactly one winner.

Every durable Policy event records organization, environment, Bundle ID,
version, old hash (nullable only for install/first activation), new hash,
change kind, pointer lifecycle version where applicable, and actor ID.

## Operational paths

The offline lifecycle is:

```bash
# signature.json is normally placed in the Bundle directory. The public-key
# file contains exactly 64 lowercase hexadecimal characters; it is not secret.
DATABASE_URL=postgres://... atf policy install policies/release-1 \
  --organization-id alpha-lab \
  --environment production \
  --publisher-public-key publisher-2026.pub \
  --actor-id policy-author-1 \
  --occurred-at 2026-08-08T12:00:00.000Z

DATABASE_URL=postgres://... atf policy activate \
  --organization-id alpha-lab --environment production \
  --bundle-id payments --policy-version 1.2.0 \
  --actor-id policy-author-1 \
  --occurred-at 2026-08-08T12:05:00.000Z

DATABASE_URL=postgres://... atf policy rollback \
  --organization-id alpha-lab --environment production \
  --bundle-id payments --actor-id policy-author-1 \
  --occurred-at 2026-08-08T12:10:00.000Z
```

The CLI is an offline database-administration boundary: possession of its
database credential is privileged, and `--actor-id` is Audit attribution, not
end-user authentication. Online activation/rollback should use the Gateway
Admin routes, which validate the configured RFC 9068 JWT/JWKS boundary before
loading the same current PostgreSQL role and running the Store's transactional
reauthorization:

- `POST /v1/policy-bundles/{bundle_id}/activate`
- `POST /v1/policy-bundles/{bundle_id}/rollback`

Both require `Authorization: Bearer ...` and `X-ATF-Organization-ID`.

Gateway startup requires `ATF_POLICY_ORGANIZATION_ID`,
`ATF_DEPLOYMENT_ENVIRONMENT` and `ATF_POLICY_BUNDLE_ID`. Startup fails if the
pointer or signed artifact cannot be verified. Each new evaluation reloads the
active pointer and exact archive in one repeatable-read snapshot, then evaluates
that owned immutable Bundle. An activation or rollback therefore takes effect
on the next new request without a process restart; an already admitted request
continues with the single exact Bundle it loaded.

## Current limits

- The key passed to `policy install` is the explicit publisher trust anchor for
  that immutable artifact. Dedicated publisher-key rotation/revocation policy
  is not yet a separate durable lifecycle; installed proof remains historical
  evidence.
- Rollback selects only the immediately prior installed signed version. A
  second rollback swaps back to the version that was current immediately
  before it.
- The Gateway currently selects one configured Bundle ID. Multi-Bundle merge,
  static conflict detection and Agent/Adapter-scoped resolution remain later
  work.
- The Admin routes change active pointers but do not upload/install archives;
  installation remains an offline deployment operation to avoid accepting
  multi-file policy content at the public HTTP edge.
