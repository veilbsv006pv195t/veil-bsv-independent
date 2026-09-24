#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${project_root}"

finish() {
  status=$?
  echo
  if [[ ${status} -eq 0 ]]; then
    echo "VEIL BOUNTY REPLAY PASSED"
  else
    echo "VEIL BOUNTY REPLAY FAILED (exit ${status})"
    echo "Keep this window open and share the error above with the maintainer."
  fi
  if [[ -t 0 ]]; then
    read -r -p "Press Return to close..." _
  fi
  exit "${status}"
}
trap finish EXIT

if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1; then
  echo "Node.js 20 or newer and npm are required."
  echo "Install the current LTS release from https://nodejs.org/ and run this file again."
  exit 1
fi

node_major="$(node -p 'Number(process.versions.node.split(".")[0])')"
if [[ "${node_major}" -lt 20 ]]; then
  echo "Node.js 20 or newer is required; found $(node --version)."
  exit 1
fi

echo "Veil bounty replay"
echo "This runs locally. It starts no public server and broadcasts no transaction."
echo "The first run is CPU-intensive and may take several minutes."
echo

npm ci
npm run bounty:replay
