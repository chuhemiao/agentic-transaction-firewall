#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_local_stack
wait_for_gateway
intent_id="$(last_intent_id)"
rolled_back=0
local_database_url="postgres://atf:${ATF_LOCAL_POSTGRES_PASSWORD:-atf-local-only}@postgres:5432/atf"

active_policy() {
  run_ops psql "${local_database_url}" \
    --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
    --command "SELECT policy_version FROM active_policy_bundles WHERE organization_id = 'alpha-lab' AND environment = 'development' AND bundle_id = 'atf-example-payments'"
}

roll_forward_after_failure() {
  if [[ "${rolled_back}" == 1 ]]; then
    run_ops /opt/atf/bin/atf policy activate \
      --organization-id alpha-lab \
      --environment development \
      --bundle-id atf-example-payments \
      --policy-version 1.1.0 \
      --actor-id local-operator \
      --occurred-at "$(operator_time)" >/dev/null 2>&1 || true
    compose restart gateway >/dev/null 2>&1 || true
  fi
}
trap roll_forward_after_failure EXIT

if [[ "$(active_policy)" != "1.1.0" ]]; then
  echo "rollback drill requires active local Policy 1.1.0" >&2
  exit 1
fi

run_ops /opt/atf/bin/atf policy rollback \
  --organization-id alpha-lab \
  --environment development \
  --bundle-id atf-example-payments \
  --actor-id local-operator \
  --occurred-at "$(operator_time)" >/dev/null
rolled_back=1
[[ "$(active_policy)" == "1.0.0" ]]
compose restart gateway >/dev/null
wait_for_gateway

rollback_replay="$(run_ops /opt/atf/bin/atf replay original \
  --organization-id alpha-lab \
  --intent-id "${intent_id}" \
  --actor-id local-operator \
  --occurred-at "$(operator_time)")"
grep -q '^matched: true$' <<<"${rollback_replay}"

run_ops /opt/atf/bin/atf policy activate \
  --organization-id alpha-lab \
  --environment development \
  --bundle-id atf-example-payments \
  --policy-version 1.1.0 \
  --actor-id local-operator \
  --occurred-at "$(operator_time)" >/dev/null
rolled_back=0
[[ "$(active_policy)" == "1.1.0" ]]
compose restart gateway >/dev/null
wait_for_gateway

forward_replay="$(run_ops /opt/atf/bin/atf replay original \
  --organization-id alpha-lab \
  --intent-id "${intent_id}" \
  --actor-id local-operator \
  --occurred-at "$(operator_time)")"
grep -q '^matched: true$' <<<"${forward_replay}"

echo "DS-039 Policy rollback/forward drill passed"
echo "rollback_version: 1.0.0"
echo "restored_version: 1.1.0"
echo "replay original: matched: true"
