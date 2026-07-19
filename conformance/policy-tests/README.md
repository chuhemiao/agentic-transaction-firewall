# conformance/policy-tests

Conformance test cases for Policy Bundles, run via `atf policy test` (PRD §21).

```bash
cargo run -p atf-cli -- policy test
# or, for a different directory of cases:
cargo run -p atf-cli -- policy test --dir conformance/policy-tests
```

## Case format

Each `*.json` file directly inside this directory (not recursive) is one
case:

```json
{
  "name": "human-readable description",
  "policies": "policies/examples",
  "expect": "permit",
  "intent": { "...": "a full Transaction Intent, PRD §9.2" }
}
```

- `policies` is a directory of `.cedar` files, resolved relative to the
  current working directory (same convention as `atf-cli evaluate
  --policies`).
- `expect` is `"permit"` or `"forbid"` — Cedar's own decision (PRD §11),
  **not** ATF's overall PERMIT/DENY/REVIEW/ERROR Decision (PRD §10.2). This
  harness tests the Policy Kernel in isolation; it does not run the Risk
  Engine or the Decision merge.
- `intent` is inlined rather than a path, so a case is fully self-contained
  in one file.

The command exits non-zero if any case fails or errors, so it can be used as
a CI gate.
