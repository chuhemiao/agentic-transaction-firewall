#!/usr/bin/env bash

set -euo pipefail

local_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "${local_dir}/../../.." && pwd)"
compose_file="${repository_root}/deploy/docker/compose.yml"

compose() {
  docker compose --file "${compose_file}" "$@"
}

require_local_stack() {
  command -v docker >/dev/null 2>&1 || {
    echo "Docker is required for the DS-039 local stack" >&2
    exit 2
  }
  docker compose version >/dev/null
}

run_ops() {
  compose --profile tools run --rm --no-deps --quiet-pull ops "$@"
}

run_ops_with_database() {
  local database_url="$1"
  shift
  compose --profile tools run --rm --no-deps --quiet-pull \
    --env "DATABASE_URL=${database_url}" ops "$@"
}

operator_time() {
  run_ops date -u '+%Y-%m-%dT%H:%M:%S.000Z'
}

last_intent_id() {
  run_ops sh -ec 'test -s /state/last-intent-id && tr -d "\r\n" </state/last-intent-id'
}

wait_for_gateway() {
  local attempt
  for attempt in $(seq 1 45); do
    if run_ops /opt/atf/bin/atf-shadow-load health \
      --base-url https://edge:8443 \
      --ca-cert /local-ca/root.crt \
      >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "Gateway did not become ready within 45 seconds" >&2
  compose logs --no-color --tail 100 gateway >&2 || true
  return 1
}

scrape_metrics() {
  run_ops /opt/atf/bin/atf-shadow-load metrics \
    --base-url https://edge:9443 \
    --ca-cert /local-ca/root.crt \
    --client-cert /metrics-client/client.crt \
    --client-key /metrics-client/client.key
}

business_status() {
  local method="$1"
  local path="$2"
  run_ops bash -ec '
    printf "%s %s HTTP/1.1\r\nHost: edge\r\nX-ATF-Organization-ID: alpha-lab\r\nConnection: close\r\n\r\n" "$1" "$2" \
      | openssl s_client -connect edge:8443 -servername edge \
          -CAfile /local-ca/root.crt -verify_return_error -quiet 2>/dev/null \
          -cert /metrics-client/client.crt -key /metrics-client/client.key \
      | sed -n "1{s/\r$//;s/^HTTP\/[0-9.]* \([0-9][0-9][0-9]\).*/\1/p;}"
  ' bash "${method}" "${path}"
}

expect_metrics_rejected() {
  local certificate="$1"
  local key="$2"
  local label="$3"
  if run_ops /opt/atf/bin/atf-shadow-load metrics \
    --base-url https://edge:9443 \
    --ca-cert /local-ca/root.crt \
    --client-cert "${certificate}" \
    --client-key "${key}" >/dev/null 2>&1; then
    echo "Metrics accepted the rejected ${label} certificate" >&2
    return 1
  fi
}
