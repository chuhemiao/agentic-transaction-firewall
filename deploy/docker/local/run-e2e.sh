#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_local_stack
compose up --build --detach --wait
wait_for_gateway

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

echo "DS-039 E2E passed"
echo "intent_id: ${intent_id}"
echo "decision_hash: ${decision_hash}"
echo "restart: readyz"
echo "replay original: matched: true"
