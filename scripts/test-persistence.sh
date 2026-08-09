#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${ATF_TEST_DATABASE_URL:-}" ]]; then
  printf '%s\n' 'ATF_TEST_DATABASE_URL must name a PostgreSQL database whose user can create and drop test databases.' >&2
  exit 2
fi

repetitions="${ATF_PERSISTENCE_TEST_REPETITIONS:-1}"
if [[ ! "${repetitions}" =~ ^[1-9][0-9]*$ ]] || (( repetitions > 10 )); then
  printf '%s\n' 'ATF_PERSISTENCE_TEST_REPETITIONS must be an integer from 1 through 10.' >&2
  exit 2
fi

for ((run = 1; run <= repetitions; run += 1)); do
  printf 'ATF persistence suite run %d/%d\n' "${run}" "${repetitions}"

  cargo test --locked --all-features -p atf-store \
    --test migrations \
    --test audit_postgres \
    --test idempotency \
    --test nonce \
    --test repository \
    --test recovery

  cargo test --locked --all-features -p atf-gateway \
    --test postgres_routes \
    --test identity \
    --test routes \
    --test dependency_failures \
    --test multi_instance
done
