#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-0.2.2}"
bundle_name="veil-bsv-replay-${version}"
release_dir="${project_root}/release"
archive="${release_dir}/${bundle_name}.zip"
staging_dir="$(mktemp -d)"
bundle_dir="${staging_dir}/${bundle_name}"

cleanup() {
  rm -rf "${staging_dir}"
}
trap cleanup EXIT

if [[ ! -f "${project_root}/dist-ui/index.html" ]]; then
  echo "dist-ui is missing. Run: npm run build:ui" >&2
  exit 1
fi

mkdir -p "${release_dir}" "${bundle_dir}/build"
rm -f "${archive}" "${archive}.sha256"

for item in \
  .gitignore \
  LICENSE \
  BOUNTY_COMPLIANCE.md \
  PROVENANCE.md \
  THIRD_PARTY_NOTICES.md \
  COMPATIBILITY.md \
  README.md \
  REPLAY_GUIDE.md \
  RUN_REPLAY.command \
  SECURITY.md \
  TESTNET_DEPLOYMENT.md \
  package.json \
  package-lock.json \
  scrypt.config.json \
  scrypt.index.json \
  tsconfig.json \
  tsconfig-scryptTS.json \
  circuits \
  docs \
  evidence \
  scripts \
  src \
  tests \
  dist-ui
do
  cp -R "${project_root}/${item}" "${bundle_dir}/"
done

# The prebuilt site already contains the large proving assets. Do not package a
# second copy under ui/public/zk; `npm run build:circuit` regenerates and syncs
# those files when a recipient chooses the source-rebuild path.
mkdir -p "${bundle_dir}/ui" "${bundle_dir}/artifacts/src/v4" "${bundle_dir}/artifacts/v4"
cp "${project_root}/ui/index.html" "${bundle_dir}/ui/"
cp "${project_root}/ui/vite.config.ts" "${bundle_dir}/ui/"
cp -R "${project_root}/ui/src" "${bundle_dir}/ui/"

# Ship the historical monolithic artifact and the deployed optimized-v4
# contract artifacts. Benchmark compiler output is not part of the release.
cp "${project_root}/artifacts/shieldedPool.json" "${bundle_dir}/artifacts/"
cp "${project_root}"/artifacts/src/v4/*.json "${bundle_dir}/artifacts/src/v4/"
cp "${project_root}/artifacts/v4/chain-manifest.json" "${bundle_dir}/artifacts/v4/"

cp "${project_root}/build/.gitkeep" "${bundle_dir}/build/.gitkeep"

(
  cd "${bundle_dir}"
  find . -type f ! -name MANIFEST.sha256 -print0 \
    | sort -z \
    | xargs -0 shasum -a 256 > MANIFEST.sha256
)

(
  cd "${staging_dir}"
  zip -qr "${archive}" "${bundle_name}"
)

(
  cd "${release_dir}"
  shasum -a 256 "${bundle_name}.zip" > "${bundle_name}.zip.sha256"
)

echo "Created ${archive}"
echo "Created ${archive}.sha256"
