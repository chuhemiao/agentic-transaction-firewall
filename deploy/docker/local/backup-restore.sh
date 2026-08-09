#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=lib.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib.sh"

require_local_stack
wait_for_gateway

intent_id="$(last_intent_id)"
restore_database=atf_restore_ds039
database_password="${ATF_LOCAL_POSTGRES_PASSWORD:-atf-local-only}"
source_url="postgres://atf:${database_password}@postgres:5432/atf"
restore_url="postgres://atf:${database_password}@postgres:5432/${restore_database}"
admin_url="postgres://atf:${database_password}@postgres:5432/postgres"
dump_path=/backups/ds039-atf.dump

cleanup_restore_database() {
  run_ops psql "${admin_url}" --no-psqlrc --set ON_ERROR_STOP=1 \
    --command "DROP DATABASE IF EXISTS ${restore_database} WITH (FORCE)" \
    >/dev/null 2>&1 || true
}
trap cleanup_restore_database EXIT

source_head="$(run_ops psql "${source_url}" \
  --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
  --command "SELECT last_sequence || ':' || last_event_hash FROM audit_chain_heads WHERE organization_id = 'alpha-lab'")"
source_counts="$(run_ops psql "${source_url}" \
  --no-psqlrc --tuples-only --no-align --set ON_ERROR_STOP=1 \
  --command "SELECT (SELECT count(*) FROM intents) || ':' || (SELECT count(*) FROM evaluations) || ':' || (SELECT count(*) FROM decisions) || ':' || (SELECT count(*) FROM audit_events)")"

run_ops pg_dump \
  --format=custom \
  --no-owner \
  --no-privileges \
  --file "${dump_path}" \
  "postgres://atf:${database_password}@postgres:5432/atf"
dump_checksum="$(run_ops sha256sum "${dump_path}" | sed 's/[[:space:]].*$//')"

cleanup_restore_database
run_ops psql "${admin_url}" --no-psqlrc --set ON_ERROR_STOP=1 \
  --command "CREATE DATABASE ${restore_database}" >/dev/null
run_ops pg_restore \
  --exit-on-error \
  --no-owner \
  --no-privileges \
  --dbname "${restore_url}" \
  "${dump_path}"
run_ops_with_database "${restore_url}" /opt/atf/bin/atf-store-migrate >/dev/null

restored_head="$(run_ops psql "${restore_url}" --no-psqlrc --tuples-only --no-align \
  --set ON_ERROR_STOP=1 \
  --command "SELECT last_sequence || ':' || last_event_hash FROM audit_chain_heads WHERE organization_id = 'alpha-lab'")"
restored_counts="$(run_ops psql "${restore_url}" --no-psqlrc --tuples-only --no-align \
  --set ON_ERROR_STOP=1 \
  --command "SELECT (SELECT count(*) FROM intents) || ':' || (SELECT count(*) FROM evaluations) || ':' || (SELECT count(*) FROM decisions) || ':' || (SELECT count(*) FROM audit_events)")"
if [[ "${source_head}" != "${restored_head}" || "${source_counts}" != "${restored_counts}" ]]; then
  echo "restored durable counts or Audit head differ from the backup snapshot" >&2
  exit 1
fi

replay_output="$(run_ops_with_database "${restore_url}" /opt/atf/bin/atf replay original \
  --organization-id alpha-lab \
  --intent-id "${intent_id}" \
  --actor-id local-operator \
  --occurred-at "$(operator_time)")"
if ! grep -q '^matched: true$' <<<"${replay_output}"; then
  echo "restored Original replay did not reproduce the Decision" >&2
  printf '%s\n' "${replay_output}" >&2
  exit 1
fi

echo "DS-039 backup/restore drill passed"
echo "backup_sha256: ${dump_checksum}"
echo "source_and_restored_head: ${source_head}"
echo "source_and_restored_counts: ${source_counts}"
echo "replay original: matched: true"
