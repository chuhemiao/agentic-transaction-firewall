#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

if [[ -z "${ATF_TEST_DATABASE_URL:-}" ]]; then
  printf '%s\n' 'ATF_TEST_DATABASE_URL must name a PostgreSQL database whose user can create and drop Replay test databases.' >&2
  exit 2
fi

printf '%s\n' 'ATF Policy conformance'
cargo run --locked -p atf-cli -- policy test

printf '%s\n' 'ATF deterministic Replay and Decision binding properties'
cargo test --locked --all-features -p atf-policy \
  repeated_evaluation_of_one_snapshot_is_byte_equivalent
cargo test --locked --all-features -p atf-risk --test determinism
cargo test --locked --all-features -p atf-decision \
  --test replay_vectors \
  --test properties

printf '%s\n' 'ATF durable Original/Counterfactual Replay conformance'
cargo test --locked --all-features -p atf-store --test replay
