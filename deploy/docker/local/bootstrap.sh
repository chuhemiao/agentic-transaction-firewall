#!/usr/bin/env bash
set -euo pipefail

: "${DATABASE_URL:?DATABASE_URL is required}"
umask 077

atf=/opt/atf/bin/atf
load=/opt/atf/bin/atf-shadow-load
seed_file=/state/local-agent-seed.hex
organization_id=alpha-lab
operator_id=local-operator
environment=development
bundle_id=atf-example-payments

now() {
  date -u '+%Y-%m-%dT%H:%M:%S.000Z'
}

scalar() {
  psql "${DATABASE_URL}" --no-psqlrc --tuples-only --no-align \
    --set ON_ERROR_STOP=1 --command "$1"
}

exists() {
  [[ "$(scalar "$1")" == "t" ]]
}

psql "${DATABASE_URL}" --no-psqlrc --set ON_ERROR_STOP=1 \
  --command "INSERT INTO organizations (organization_id) VALUES ('${organization_id}') ON CONFLICT DO NOTHING" \
  >/dev/null

if [[ ! -e "${seed_file}" ]]; then
  openssl rand -hex 32 >"${seed_file}"
fi
chmod 0600 "${seed_file}"
public_key="$(${load} public-key --seed-file "${seed_file}")"

if ! exists "SELECT EXISTS (SELECT 1 FROM operator_subjects WHERE operator_id = '${operator_id}')"; then
  printf '%s\n' 'local-operator-subject' | "${atf}" operator provision-subject \
    --organization-id "${organization_id}" \
    --operator-id "${operator_id}" \
    --issuer-id local-idp \
    --issuer-url https://edge:8444 \
    --principal-kind SERVICE \
    --created-at "$(now)" \
    --actor-id local-bootstrap \
    --occurred-at "$(now)"
fi

if ! exists "SELECT EXISTS (SELECT 1 FROM operator_roles WHERE operator_id = '${operator_id}' AND organization_id = '${organization_id}' AND role = 'org_admin' AND status = 'ACTIVE')"; then
  "${atf}" operator grant-role \
    --organization-id "${organization_id}" \
    --operator-id "${operator_id}" \
    --role org_admin \
    --actor-id local-bootstrap \
    --reason-code LOCAL_STACK_BOOTSTRAP \
    --occurred-at "$(now)"
fi

if ! exists "SELECT EXISTS (SELECT 1 FROM agents WHERE organization_id = '${organization_id}' AND agent_id = 'research-agent-01')"; then
  "${atf}" identity provision-agent /opt/atf/fixtures/local-agent.json \
    --actor-id "${operator_id}" \
    --occurred-at "$(now)"
fi

if ! exists "SELECT EXISTS (SELECT 1 FROM identity_keys WHERE organization_id = '${organization_id}' AND agent_id = 'research-agent-01' AND key_id = 'local-agent-key')"; then
  "${atf}" identity register-key \
    --organization-id "${organization_id}" \
    --agent-id research-agent-01 \
    --key-id local-agent-key \
    --public-key-hex "${public_key}" \
    --activates-at 2026-01-01T00:00:00.000Z \
    --expires-at 2099-01-01T00:00:00.000Z \
    --actor-id "${operator_id}" \
    --occurred-at "$(now)"
else
  stored_public_key="$(scalar "SELECT encode(public_key, 'hex') FROM identity_keys WHERE organization_id = '${organization_id}' AND agent_id = 'research-agent-01' AND key_id = 'local-agent-key'")"
  if [[ "${stored_public_key}" != "${public_key}" ]]; then
    echo "local Agent seed does not match the immutable registered public key" >&2
    exit 1
  fi
fi

if ! exists "SELECT EXISTS (SELECT 1 FROM policy_bundles WHERE organization_id = '${organization_id}' AND environment = '${environment}' AND bundle_id = '${bundle_id}' AND policy_version = '1.0.0')"; then
  "${atf}" policy install /opt/atf/policies/current \
    --organization-id "${organization_id}" \
    --environment "${environment}" \
    --publisher-public-key /opt/atf/policies/current/publisher-2026.pub \
    --actor-id "${operator_id}" \
    --occurred-at "$(now)"
fi

if ! exists "SELECT EXISTS (SELECT 1 FROM policy_bundles WHERE organization_id = '${organization_id}' AND environment = '${environment}' AND bundle_id = '${bundle_id}' AND policy_version = '1.1.0')"; then
  "${atf}" policy install /opt/atf/fixtures/policy-next \
    --organization-id "${organization_id}" \
    --environment "${environment}" \
    --publisher-public-key /opt/atf/fixtures/policy-next/publisher-local.pub \
    --actor-id "${operator_id}" \
    --occurred-at "$(now)"
fi

active_policy="$(scalar "SELECT policy_version FROM active_policy_bundles WHERE organization_id = '${organization_id}' AND environment = '${environment}' AND bundle_id = '${bundle_id}'")"
if [[ -z "${active_policy}" ]]; then
  "${atf}" policy activate \
    --organization-id "${organization_id}" \
    --environment "${environment}" \
    --bundle-id "${bundle_id}" \
    --policy-version 1.0.0 \
    --actor-id "${operator_id}" \
    --occurred-at "$(now)"
  active_policy=1.0.0
fi
if [[ "${active_policy}" == "1.0.0" ]]; then
  "${atf}" policy activate \
    --organization-id "${organization_id}" \
    --environment "${environment}" \
    --bundle-id "${bundle_id}" \
    --policy-version 1.1.0 \
    --actor-id "${operator_id}" \
    --occurred-at "$(now)"
elif [[ "${active_policy}" != "1.1.0" ]]; then
  echo "unsupported active local Policy version: ${active_policy}" >&2
  exit 1
fi

if ! exists "SELECT EXISTS (SELECT 1 FROM risk_rule_sets WHERE organization_id = '${organization_id}' AND environment = '${environment}' AND engine_version = 'atf-risk-engine-v1' AND rule_set_version = 'risk-rules-1.3.0')"; then
  "${atf}" risk install /opt/atf/risk-rules/default.json \
    --organization-id "${organization_id}" \
    --environment "${environment}" \
    --actor-id "${operator_id}" \
    --occurred-at "$(now)"
fi

echo "ATF local durable state is initialized; active Policy 1.1.0"
