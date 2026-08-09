# conformance/replay-tests

**Status:** Original Replay is implemented by DS-026, isolated Counterfactual
Replay by DS-027, and their executable hash/property gate by DS-037.

`original.json` is consumed by `crates/atf-store/tests/replay.rs`. It locks the
exact replayed-equals-original hash relation, stable fail-closed codes and non-authoritative/
non-overwrite invariants for the restart fixture. The integration suite builds
the complete durable authority, restarts Store, reloads every exact artifact
and Audit prefix, and verifies both successful and missing/tampered paths.

`counterfactual.json` locks the non-authoritative, linked-new-identity and
changed-outcome relation plus stable authorization/missing-artifact/conflict
codes. The PostgreSQL integration fixture selects a replacement Risk Rule Set,
restarts Store, proves the original authoritative bytes/counts are unchanged,
reloads the new lineage, and rejects consistently rewritten Evaluation
evidence because its hash is bound into immutable Audit evidence.

`decision-hashes.json` is deliberately independent of database-generated
Audit event IDs. It supplies fixed Intent, Context, artifact and identity
inputs to `crates/atf-decision/tests/replay_vectors.rs`, locking exact Original
and Counterfactual Context/Decision hashes as well as same-snapshot,
new-identity, non-authoritative and changed-outcome lineage. The PostgreSQL
fixtures continue to verify the same relations against dynamically generated
durable Audit prefixes; their hashes are not hard-coded because event ULIDs are
legitimate inputs to those snapshots.

Run the full executable gate against a PostgreSQL role that can create and
drop temporary databases:

```bash
ATF_TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/postgres \
  ./scripts/test-conformance.sh
```
