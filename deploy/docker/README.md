# deploy/docker

**Status:** DS-036 provides the isolated real-PostgreSQL persistence test stack
in `compose.test.yml`. DS-039 adds the supported single-host Durable Shadow
runtime in `compose.yml`: PostgreSQL and Gateway stay private, Caddy exposes
only loopback TLS, and one-shot services migrate and idempotently provision
the local organization, identities, signed Policies and Risk Rule Set.

Start and exercise the supported runtime from the repository root:

```bash
deploy/docker/local/start.sh
scripts/test-local-ops.sh
```

The complete quickstart, backup/restore, Policy rollback/forward and destructive
reset instructions are in [`../../docs/quickstart.md`](../../docs/quickstart.md).
This topology is Shadow-only and is not a production, HA, internet-exposed or
real-funds deployment.

Run the repeatable persistence race suite entirely in Compose from the
repository root:

```bash
ATF_PERSISTENCE_TEST_REPETITIONS=2 \
  docker compose -f deploy/docker/compose.test.yml run --rm persistence-tests
docker compose -f deploy/docker/compose.test.yml down --volumes
```

The PostgreSQL data directory is a temporary filesystem. The runner mounts the
source read-only and uses named Cargo registry/target volumes; it cannot write
generated artifacts or database state into the checkout. Container builds use
one Cargo job and omit test debug symbols by default so parallel linking cannot
exhaust a small Docker Desktop/CI memory allocation; set
`ATF_PERSISTENCE_CARGO_JOBS` explicitly only when the runner has been sized for
additional linkers.
