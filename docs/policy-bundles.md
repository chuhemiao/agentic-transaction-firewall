# Policy Bundle Contract

ATF constructs Cedar only from a validated Policy Bundle artifact. Loading raw
`.cedar` text or concatenating an unmanifested directory is not supported.
Directories are an offline authoring/install input; Gateway runtime resolves an
immutable signed archive through PostgreSQL.

## Version 1 layout

Each directory contains exactly one `manifest.json`, one declared Cedar JSON
Schema, and one or more declared `.cedar` files. The manifest follows
`schemas/policy-bundle.schema.json` and is closed to unknown fields. It binds:

- `bundle_id` and semantic `policy_version`;
- exact `organization_id` and deployment `environment` scope;
- inclusive `activates_at` and exclusive `expires_at`, both aligned to whole
  milliseconds;
- the relative path and lowercase SHA-256 digest of the Cedar Schema and every
  policy file;
- the lowercase canonical `bundle_hash`.

Paths must be direct filenames under the Bundle root; nested/absolute paths,
traversal, symlinks, duplicate entries, unsorted entries, missing files, digest
mismatches and undeclared `.cedar` files fail closed. Manifest size is capped at
64 KiB, each Schema/Policy file at 1 MiB, and all declared executable files at
16 MiB total; reads are bounded even if a file changes after metadata lookup.
An install directory must not be concurrently writable by an untrusted user.
DS-020 immediately converts the validated files into a bounded exact-byte
archive and persists it with detached publisher proof; Gateway never evaluates
that directory.

## Canonical bundle hash

`bundle_hash` is SHA-256 over a domain-separated, length-framed byte stream:

1. ASCII `ATF_POLICY_BUNDLE_V1` followed by a zero byte.
2. The recursively key-sorted compact JSON manifest with `bundle_hash`
   removed.
3. The declared Cedar Schema path and exact bytes.
4. Every policy path and exact bytes in ascending path order.

Every item after the domain is prefixed with its unsigned 64-bit big-endian
byte length; named files frame the path and contents independently. This avoids
ambiguous concatenation and makes whitespace changes in executable artifacts
visible. Implementations must use `atf_core::sort_json_keys`, because workspace
feature unification enables `serde_json`'s insertion-order map backend.

The example bundle identity is:

```text
bundle_id: atf-example-payments
policy_version: 1.0.0
bundle_hash: 87276dc9ae9b5cfd09bc664fc12a7a6d1bdc6cec3f847644239b27a368478373
```

## Validation and evaluation

`PolicyBundle::from_dir` requires a `PolicyBundleLoadContext` containing the
expected organization, environment and evaluation time. It verifies the JSON
manifest contract, scope/time window, all file digests, canonical bundle hash,
Cedar Schema and Cedar policies in strict mode. Warnings are rejected as well
as errors.

`PolicyBundle::evaluate` accepts the immutable `EvaluationContext`, rederives
the Intent/Profile binding, checks environment, exact Bundle ID/version/hash
and active time, constructs the Cedar request with the same Schema, and treats
any Cedar runtime diagnostic as an error. A successful `PolicyOutcome` carries
`bundle_id`, `policy_version` and `bundle_hash` with its Permit/Forbid result.

Cedar documents that policy validation is a separate pre-authorization step
and that requests must conform to the Schema contract:
[policy validation](https://docs.cedarpolicy.com/policies/validation.html) and
[Cedar 4.11.2 Validator API](https://docs.rs/cedar-policy/4.11.2/cedar_policy/struct.Validator.html).

Detached signature bytes, immutable installation, version uniqueness,
activation and rollback are specified in [`policy-model.md`](policy-model.md).
Multi-Bundle resolution and static conflict detection remain future work.
