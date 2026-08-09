#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repository_root}"

# shellcheck disable=SC1091
source security/tool-versions.env

read -r cargo_audit_name cargo_audit_version < <(cargo audit --version)
if [[ "${cargo_audit_name}" != cargo-audit* || \
  "${cargo_audit_version}" != "${CARGO_AUDIT_VERSION}" ]]; then
  echo "cargo-audit ${CARGO_AUDIT_VERSION} is required" >&2
  exit 2
fi
gitleaks_version="$(scripts/run-gitleaks.sh version)"
if [[ "${gitleaks_version#v}" != "${GITLEAKS_VERSION}" ]]; then
  echo "gitleaks ${GITLEAKS_VERSION} is required" >&2
  exit 2
fi

python3 scripts/test-security-config.py

runtime_dir="$(mktemp -d)"
fixture_log="${runtime_dir}/fixture.log"
audit_log="${runtime_dir}/audit.log"
cargo_tree_file="${runtime_dir}/cargo-tree.txt"
exception_ids_file="${runtime_dir}/advisory-exception-ids.txt"
gitleaks_ignore_file="${runtime_dir}/gitleaksignore"
trap 'rm -rf -- "${runtime_dir}"' EXIT
{
  cargo tree --locked --workspace --all-features --target all \
    --prefix none --format '{p}'
  cargo tree --locked --manifest-path fuzz/Cargo.toml --all-features --target all \
    --prefix none --format '{p}'
} | sort -u >"${cargo_tree_file}"
if [[ ! -s "${cargo_tree_file}" ]]; then
  echo "Cargo reachability tree is unexpectedly empty" >&2
  exit 1
fi
python3 security/validate_advisory_exceptions.py \
  security/advisory-exceptions.toml "${cargo_tree_file}" \
  >"${exception_ids_file}"
python3 security/validate_secret_exceptions.py \
  security/secret-exceptions.toml >"${gitleaks_ignore_file}"

audit_root_args=(--file Cargo.lock)
audit_fuzz_args=(--no-fetch --file fuzz/Cargo.lock)
audit_fixture_args=(--no-fetch --file tests/security/fixtures/vulnerable-lock/Cargo.lock)
if [[ -n "${ATF_ADVISORY_DB:-}" ]]; then
  advisory_db="$(cd "${ATF_ADVISORY_DB}" && pwd -P)"
  audit_root_args+=(--db "${advisory_db}" --no-fetch)
  audit_fuzz_args+=(--db "${advisory_db}")
  audit_fixture_args+=(--db "${advisory_db}")
fi
while IFS= read -r advisory_id; do
  if [[ -n "${advisory_id}" ]]; then
    audit_root_args+=(--ignore "${advisory_id}")
    audit_fuzz_args+=(--ignore "${advisory_id}")
  fi
done <"${exception_ids_file}"

audit_status=1
for attempt in 1 2 3; do
  set +e
  cargo audit "${audit_root_args[@]}" 2>&1 | tee "${audit_log}"
  audit_status="${PIPESTATUS[0]}"
  set -e
  if [[ "${audit_status}" -eq 0 ]]; then
    break
  fi
  if [[ -n "${ATF_ADVISORY_DB:-}" ]] || \
    ! grep -q "couldn't fetch advisory database" "${audit_log}" || \
    [[ "${attempt}" -eq 3 ]]; then
    exit "${audit_status}"
  fi
  echo "RustSec advisory fetch failed; retrying (${attempt}/3)" >&2
done
cargo audit "${audit_fuzz_args[@]}"

scripts/run-gitleaks.sh git --config .gitleaks.toml \
  --gitleaks-ignore-path "${gitleaks_ignore_file}" --redact --no-banner \
  --no-color .
scripts/run-gitleaks.sh dir --config .gitleaks.toml \
  --gitleaks-ignore-path "${gitleaks_ignore_file}" --redact --no-banner \
  --no-color .

fixture_dir="${runtime_dir}/secret-fixture"
mkdir "${fixture_dir}"

if cargo audit "${audit_fixture_args[@]}" >"${fixture_log}" 2>&1; then
  echo "RustSec vulnerable-lock fixture unexpectedly passed" >&2
  exit 1
fi
if ! grep -q "RUSTSEC-2020-0071" "${fixture_log}"; then
  echo "RustSec fixture failed without its expected advisory" >&2
  cat "${fixture_log}" >&2
  exit 1
fi

fixture_secret="$(python3 -c \
  'import hashlib; print(hashlib.sha256(b"ATF DS-038 synthetic leak fixture").hexdigest())')"
printf 'api_key = "%s"\n' "${fixture_secret}" >"${fixture_dir}/leak.txt"
if scripts/run-gitleaks.sh dir --config .gitleaks.toml \
  --gitleaks-ignore-path "${gitleaks_ignore_file}" --redact --no-banner --no-color \
  --report-format json --report-path - \
  "${fixture_dir}" >"${fixture_log}" 2>&1; then
  echo "Gitleaks synthetic-secret fixture unexpectedly passed" >&2
  exit 1
fi
if ! grep -q "generic-api-key" "${fixture_log}"; then
  echo "Gitleaks fixture failed without the expected generic-api-key finding" >&2
  cat "${fixture_log}" >&2
  exit 1
fi

cat >"${fixture_dir}/expired.toml" <<'EOF'
schema_version = 1
exceptions = [
  { id = "RUSTSEC-2020-0071", package = "time", version = "0.1.44", owner = "@atf-security", reason = "Fixture is deliberately vulnerable for gate verification.", expires = "2000-01-01" },
]
EOF
if python3 security/validate_advisory_exceptions.py \
  "${fixture_dir}/expired.toml" >"${fixture_log}" 2>&1; then
  echo "expired advisory exception fixture unexpectedly passed" >&2
  exit 1
fi
if ! grep -q "expired on 2000-01-01" "${fixture_log}"; then
  echo "expired exception fixture failed without the expected expiry finding" >&2
  cat "${fixture_log}" >&2
  exit 1
fi

cat >"${fixture_dir}/expired-secret.toml" <<'EOF'
schema_version = 1
exceptions = [
  { fingerprint = "0000000000000000000000000000000000000000:fixture.txt:generic-api-key:1", owner = "@atf-security", reason = "Fixture proves historical secret exceptions cannot survive expiry.", expires = "2000-01-01" },
]
EOF
if python3 security/validate_secret_exceptions.py \
  "${fixture_dir}/expired-secret.toml" >"${fixture_log}" 2>&1; then
  echo "expired secret exception fixture unexpectedly passed" >&2
  exit 1
fi
if ! grep -q "expired on 2000-01-01" "${fixture_log}"; then
  echo "expired secret exception failed without the expected expiry finding" >&2
  cat "${fixture_log}" >&2
  exit 1
fi

echo "dependency, secret and expiring-exception gates passed"
