# conformance/replay-tests

**Status:** Original Replay is implemented by DS-026 and isolated
Counterfactual Replay by DS-027.

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
