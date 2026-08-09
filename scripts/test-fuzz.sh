#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"

if ! cargo fuzz --version >/dev/null 2>&1; then
  printf '%s\n' 'cargo-fuzz 0.13.2 is required (install with: cargo install cargo-fuzz --locked --version 0.13.2).' >&2
  exit 2
fi

fuzz_version="$(cargo fuzz --version)"
if [[ "${fuzz_version}" != "cargo-fuzz 0.13.2" ]]; then
  printf 'expected cargo-fuzz 0.13.2, found %s\n' "${fuzz_version}" >&2
  exit 2
fi

rust_version="$(rustc --version)"
if [[ "${rust_version}" != *-nightly* ]]; then
  printf 'cargo-fuzz must run with a nightly compiler, found %s\n' "${rust_version}" >&2
  exit 2
fi

max_total_time="${ATF_FUZZ_MAX_TOTAL_TIME_SECONDS:-15}"
if [[ ! "${max_total_time}" =~ ^[1-9][0-9]*$ ]] || (( max_total_time > 60 )); then
  printf '%s\n' 'ATF_FUZZ_MAX_TOTAL_TIME_SECONDS must be an integer from 1 through 60.' >&2
  exit 2
fi

temporary_corpus="$(mktemp -d "${TMPDIR:-/tmp}/atf-intent-fuzz.XXXXXX")"
trap 'rm -rf "${temporary_corpus}"' EXIT
cp fuzz/corpus/intent/* "${temporary_corpus}/"
mkdir "${temporary_corpus}/artifacts"

fuzz_log="${temporary_corpus}/fuzz.log"
if cargo fuzz run intent "${temporary_corpus}" -- \
  -artifact_prefix="${temporary_corpus}/artifacts/" \
  -max_total_time="${max_total_time}" \
  -timeout=5 \
  -rss_limit_mb=2048 \
  -verbosity=0 \
  -print_final_stats=1 >"${fuzz_log}" 2>&1; then
  printf 'bounded Intent fuzz smoke passed (%s seconds)\n' "${max_total_time}"
  grep '^stat::' "${fuzz_log}"
else
  status=$?
  cat "${fuzz_log}" >&2
  exit "${status}"
fi
