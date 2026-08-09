# Durable Shadow local quickstart

This is the supported **single-host local evaluation stack** delivered by
DS-039. It is Shadow-only: there is no execution, wallet, Adapter, Approval,
or real-funds path. It is not an internet-exposed or production deployment.

## Prerequisites

- Docker Engine/Desktop with Docker Compose v2
- Python 3 for the fail-closed configuration preflight
- at least 8 GiB available to Docker for the first Rust release build
- ports `127.0.0.1:8443` available (override with
  `ATF_LOCAL_HTTPS_PORT`)

All external images and Dockerfile bases are digest pinned. PostgreSQL and the
Gateway are reachable only on the private Compose network. Caddy terminates a
local generated CA certificate and exposes only TLS on the host loopback
address. Agent signing material and the local CA private key are generated
inside named volumes; neither is committed to Git.

## Start, submit, restart and Replay

From the repository root:

```bash
deploy/docker/local/start.sh
deploy/docker/local/run-e2e.sh
```

`start.sh` builds the locked Rust workspace, migrates the durable schema,
creates the local organization/operator/Agent and keys, installs two signed
Policy versions plus the Risk Rule Set, and waits for `/readyz` through the TLS
edge. `run-e2e.sh` submits a unique signed Intent, restarts the real Gateway,
waits for readiness, and runs `atf replay original`. It succeeds only when the
submitted, stored and replayed Decision hashes are identical.

The public local endpoint is `https://localhost:8443`. Use the provided tools
instead of bypassing the private Gateway port. The generated CA can be read
inside the `ops` service at
`/local-ca/root.crt`; Caddy's CA private-key directory is never shared with
the Gateway or operations containers.

## Recovery and rollback drills

Run both after the E2E has created an Intent:

```bash
deploy/docker/local/backup-restore.sh
deploy/docker/local/policy-rollback.sh
```

The restore drill takes a PostgreSQL 17 custom-format backup, records its
SHA-256, restores into the exact isolated database `atf_restore_ds039`,
compares durable object counts and the organization Audit head, then performs
Original Replay against the restored database. The temporary restore database
is dropped when the drill ends; the backup remains in the `local-backups`
volume.

The rollback drill moves the audited active Policy pointer from local version
1.1.0 to 1.0.0, restarts and replays, then activates 1.1.0 again and repeats
the readiness/Replay proof. Database migrations are forward-only. Never apply
hand-written down SQL: for an incompatible migration, stop writers, restore a
verified pre-change backup into a new database, run the prior digest-pinned
image against it, and switch only after readiness and Replay succeed.

## Measure the local Shadow path

```bash
ATF_LOCAL_LOAD_REQUESTS=50 \
ATF_LOCAL_LOAD_CONCURRENCY=4 \
  deploy/docker/local/run-load.sh
```

The bounded client signs unique Intents, verifies every typed Decision hash,
and reports integer P50/P95/P99 plus decimal-string throughput. Results are a
machine-specific local baseline, not an SLO or production capacity claim. See
[`../conformance/load/README.md`](../conformance/load/README.md) for scope and
the checked-in DS-039 measurement.

## Stop or reset

Stop containers while retaining PostgreSQL, local keys, CA and backups:

```bash
docker compose -f deploy/docker/compose.yml down
```

To deliberately erase the entire `atf-local` data set and generated local
credentials:

```bash
docker compose -f deploy/docker/compose.yml down --volumes
```

The second command is destructive and cannot be used for a recovery drill.
