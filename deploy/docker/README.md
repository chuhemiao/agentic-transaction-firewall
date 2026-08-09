# deploy/docker

**Status:** DS-036 provides an isolated real-PostgreSQL persistence test stack
in `compose.test.yml`. The supported local Gateway development/operations stack
remains DS-039 work and is not implied by this test-only file.

Per-service Dockerfiles; `deploy/docker-compose.yml` (once added) wires up
local development (PRD §30.1).

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
