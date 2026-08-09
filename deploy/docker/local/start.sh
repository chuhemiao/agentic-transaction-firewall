#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_local_stack
python3 "${repository_root}/scripts/test-local-ops-config.py"
compose up --build --detach --wait
wait_for_gateway

echo "ATF Durable Shadow local stack is ready at https://localhost:${ATF_LOCAL_HTTPS_PORT:-8443}"
echo "Use deploy/docker/local/run-e2e.sh to submit, restart and Replay."
