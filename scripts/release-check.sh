#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${project_root}"

if git ls-files --error-unmatch .private >/dev/null 2>&1; then
  echo "release check failed: .private is tracked" >&2
  exit 1
fi

if rg -n --hidden \
  -g '!.git/**' \
  -g '!.private/**' \
  -g '!node_modules/**' \
  -g '!artifacts/**' \
  -g '!dist/**' \
  -g '!dist-ui/**' \
  -g '!release/**' \
  -g '!scripts/release-check.sh' \
  '(@outlook\.com|@proton\.me|/Users/[^/]+/|BEGIN [A-Z ]*PRIVATE KEY|\b[KLc][1-9A-HJ-NP-Za-km-z]{50,51}\b)' .; then
  echo "release check failed: possible credential, identity, or local path" >&2
  exit 1
fi

jq -e '.format == "veil-v4-public-testnet-evidence-v1" and .network == "bsv-testnet"' \
  evidence/testnet-v4-lifecycle.json >/dev/null
jq -e '.scripts["bounty:replay"] != null' package.json >/dev/null

if [[ -f MANIFEST.sha256 ]]; then
  shasum -a 256 -c MANIFEST.sha256 >/dev/null
fi

echo "release metadata and confidential-data checks passed"
