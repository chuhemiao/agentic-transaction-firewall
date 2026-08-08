# conformance/replay-tests

**Status:** Original Replay is implemented by DS-026; Counterfactual Replay
remains DS-027.

`original.json` is consumed by `crates/atf-store/tests/replay.rs`. It locks the
exact replayed-equals-original hash relation, stable fail-closed codes and non-authoritative/
non-overwrite invariants for the restart fixture. The integration suite builds
the complete durable authority, restarts Store, reloads every exact artifact
and Audit prefix, and verifies both successful and missing/tampered paths.

Counterfactual lineage fixtures will be added by DS-027.
