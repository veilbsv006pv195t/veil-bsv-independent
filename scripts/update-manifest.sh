#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${project_root}"

manifest_tmp="$(mktemp)"
cleanup() {
  rm -f "${manifest_tmp}"
}
trap cleanup EXIT

git ls-files --cached --others --exclude-standard \
  | LC_ALL=C sort \
  | while IFS= read -r file; do
      if [[ "${file}" != "MANIFEST.sha256" ]]; then
        shasum -a 256 "${file}"
      fi
    done > "${manifest_tmp}"

mv "${manifest_tmp}" MANIFEST.sha256
trap - EXIT
echo "Updated MANIFEST.sha256"
