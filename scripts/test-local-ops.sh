#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repository_root}"

python3 scripts/test-local-ops-config.py
docker compose --file deploy/docker/compose.yml config --quiet
docker compose --file deploy/docker/compose.yml down --volumes --remove-orphans
cleanup() {
  docker compose --file deploy/docker/compose.yml down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT
deploy/docker/local/run-e2e.sh
deploy/docker/local/backup-restore.sh
deploy/docker/local/policy-rollback.sh
ATF_LOCAL_LOAD_REQUESTS="${ATF_LOCAL_LOAD_REQUESTS:-50}" \
ATF_LOCAL_LOAD_CONCURRENCY="${ATF_LOCAL_LOAD_CONCURRENCY:-4}" \
ATF_LOCAL_LOAD_WARMUP_REQUESTS="${ATF_LOCAL_LOAD_WARMUP_REQUESTS:-5}" \
  deploy/docker/local/run-load.sh

echo "DS-040 authenticated Metrics and DS-039 local operations evidence passed"
