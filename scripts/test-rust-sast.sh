#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repository_root}"

# shellcheck disable=SC1091
source security/tool-versions.env

actual_rust="$(rustc --version | awk '{ print $2 }')"
if [[ "${actual_rust}" != "${RUST_SAST_TOOLCHAIN}" ]]; then
  echo "Rust SAST requires rustc ${RUST_SAST_TOOLCHAIN}; found ${actual_rust}" >&2
  exit 2
fi

cargo clippy --all-targets --all-features -- -D warnings -F unsafe-code

fixture_target="$(mktemp -d)"
fixture_log="$(mktemp)"
trap 'rm -rf -- "${fixture_target}"; rm -f -- "${fixture_log}"' EXIT

if CARGO_TARGET_DIR="${fixture_target}" cargo clippy \
  --manifest-path tests/security/fixtures/rust-sast/Cargo.toml \
  -- -D warnings -F unsafe-code >"${fixture_log}" 2>&1; then
  echo "Rust SAST unsafe-code fixture unexpectedly passed" >&2
  exit 1
fi

if ! grep -q "usage of an.*unsafe.*block" "${fixture_log}"; then
  echo "Rust SAST fixture failed without the expected unsafe-code finding" >&2
  cat "${fixture_log}" >&2
  exit 1
fi

echo "Rust SAST rejected the unsafe-code fixture"
