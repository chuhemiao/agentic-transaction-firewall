#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_local_stack
wait_for_gateway

requests="${ATF_LOCAL_LOAD_REQUESTS:-50}"
concurrency="${ATF_LOCAL_LOAD_CONCURRENCY:-4}"
warmup="${ATF_LOCAL_LOAD_WARMUP_REQUESTS:-5}"

run_ops /opt/atf/bin/atf-shadow-load run \
  --base-url https://edge:8443 \
  --ca-cert /local-ca/root.crt \
  --seed-file /state/local-agent-seed.hex \
  --requests "${requests}" \
  --concurrency "${concurrency}" \
  --warmup-requests "${warmup}" \
  --report /state/latest-load-report.json \
  --save-last-intent /state/last-intent-id
