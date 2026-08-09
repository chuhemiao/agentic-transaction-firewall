#!/usr/bin/env bash
set -euo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1091
source "${repository_root}/security/tool-versions.env"

if native_version="$(gitleaks version 2>/dev/null)" && \
  [[ "${native_version#v}" == "${GITLEAKS_VERSION}" ]]; then
  exec gitleaks "$@"
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "gitleaks ${GITLEAKS_VERSION} or Docker with ${GITLEAKS_IMAGE} is required" >&2
  exit 2
fi

docker_mounts=(--volume "${repository_root}:${repository_root}:ro")
for argument in "$@"; do
  if [[ -e "${argument}" ]]; then
    if [[ -d "${argument}" ]]; then
      host_path="$(cd "${argument}" && pwd -P)"
      container_path="$(cd "${argument}" && pwd -L)"
    else
      host_path="$(cd "$(dirname "${argument}")" && pwd -P)"
      container_path="$(cd "$(dirname "${argument}")" && pwd -L)"
    fi
    if [[ "${host_path}" != "${repository_root}"* ]]; then
      docker_mounts+=(--volume "${host_path}:${container_path}:ro")
    fi
  fi
done

exec docker run --rm "${docker_mounts[@]}" \
  --workdir "${repository_root}" "${GITLEAKS_IMAGE}" "$@"
