#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_local_stack
compose up --build --detach --wait
wait_for_gateway

metrics_output="$(scrape_metrics)"
if ! grep -q '^metrics: authenticated; replay_metrics_available=1$' <<<"${metrics_output}"; then
  echo "approved Metrics reader could not scrape the isolated operations edge" >&2
  exit 1
fi
if [[ "$(business_status GET /metrics)" != "404" ]]; then
  echo "business TLS listener exposed /metrics" >&2
  exit 1
fi
if run_ops bash -o pipefail -ec '
  printf "GET /metrics HTTP/1.1\r\nHost: edge\r\nConnection: close\r\n\r\n" \
    | openssl s_client -connect edge:9443 -servername edge \
        -CAfile /local-ca/root.crt -verify_return_error -quiet >/dev/null 2>&1
'; then
  echo "operations edge accepted a client without a certificate" >&2
  exit 1
fi
for fixture in wrong-client expired future wrong-eku unapproved; do
  expect_metrics_rejected \
    "/metrics-invalid/${fixture}.crt" "/metrics-invalid/${fixture}.key" "${fixture}"
done

while read -r method route expected; do
  actual="$(business_status "${method}" "${route}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "Metrics credential business-route result drifted for ${method} ${route}: expected ${expected}, got ${actual}" >&2
    exit 1
  fi
done <<'EOF'
POST /v1/intents 400
GET /v1/intents/01J000000000000000000000000/decision 401
GET /v1/audit/events 401
POST /v1/policy-bundles/atf-example-payments/activate 401
EOF

submit_report="$(run_ops /opt/atf/bin/atf-shadow-load run \
  --base-url https://edge:8443 \
  --ca-cert /local-ca/root.crt \
  --seed-file /state/local-agent-seed.hex \
  --requests 1 \
  --concurrency 1 \
  --report /state/e2e-report.json \
  --save-last-intent /state/last-intent-id)"
decision_hash="$(printf '%s\n' "${submit_report}" | sed -n 's/.*"decision_hash": "\([0-9a-f]\{64\}\)".*/\1/p')"
if [[ -z "${decision_hash}" ]]; then
  echo "signed Shadow submit did not return a verified Decision hash" >&2
  exit 1
fi
intent_id="$(last_intent_id)"

compose restart gateway >/dev/null
wait_for_gateway
scrape_metrics >/dev/null

replay_output="$(run_ops /opt/atf/bin/atf replay original \
  --organization-id alpha-lab \
  --intent-id "${intent_id}" \
  --actor-id local-operator \
  --occurred-at "$(operator_time)")"
if ! grep -q '^matched: true$' <<<"${replay_output}"; then
  echo "Original replay did not reproduce the restarted Decision" >&2
  printf '%s\n' "${replay_output}" >&2
  exit 1
fi
original_hash="$(sed -n 's/^original_decision_hash: //p' <<<"${replay_output}")"
replayed_hash="$(sed -n 's/^replayed_decision_hash: //p' <<<"${replay_output}")"
if [[ "${decision_hash}" != "${original_hash}" || "${original_hash}" != "${replayed_hash}" ]]; then
  echo "submit/restart/Replay Decision hashes differ" >&2
  exit 1
fi

postgres_stopped=true
restore_postgres() {
  if [[ "${postgres_stopped}" == "true" ]]; then
    compose start postgres >/dev/null 2>&1 || true
  fi
}
trap restore_postgres EXIT
compose stop postgres >/dev/null
outage_metrics="$(scrape_metrics)"
if ! grep -q '^metrics: authenticated; replay_metrics_available=0$' <<<"${outage_metrics}"; then
  echo "authenticated Metrics did not remain available during PostgreSQL loss" >&2
  exit 1
fi
if [[ "$(business_status GET /readyz)" != "503" ]]; then
  echo "Gateway readiness did not fail closed during PostgreSQL loss" >&2
  exit 1
fi
if run_ops /opt/atf/bin/atf-shadow-load run \
  --base-url https://edge:8443 \
  --ca-cert /local-ca/root.crt \
  --seed-file /state/local-agent-seed.hex \
  --requests 1 --concurrency 1 >/dev/null 2>&1; then
  echo "financial admission unexpectedly succeeded during PostgreSQL loss" >&2
  exit 1
fi
compose start postgres >/dev/null
postgres_stopped=false
trap - EXIT
wait_for_gateway
scrape_metrics >/dev/null

compose run --rm --no-deps \
  --env ATF_ROTATE_METRICS_PKI=true metrics-init >/dev/null
compose restart edge >/dev/null
wait_for_gateway
scrape_metrics >/dev/null
if run_ops bash -o pipefail -ec '
  printf "GET /metrics HTTP/1.1\r\nHost: edge\r\nConnection: close\r\n\r\n" \
    | openssl s_client -connect edge:9443 -servername edge \
        -CAfile /local-ca/root.crt -verify_return_error -quiet >/dev/null 2>&1
'; then
  echo "trust-pool rotation created an anonymous Metrics interval" >&2
  exit 1
fi

echo "DS-040 authenticated Metrics and DS-039 Shadow E2E passed"
echo "intent_id: ${intent_id}"
echo "decision_hash: ${decision_hash}"
echo "restart: readyz"
echo "replay original: matched: true"
echo "metrics: mTLS/UDS isolated; invalid certificates rejected; database outage observed"
