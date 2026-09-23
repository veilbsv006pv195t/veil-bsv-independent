#!/usr/bin/env bash
set -euo pipefail

project_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
version="${1:-0.2.1}"
asset_name="veil-v4-deployed-proving-artifacts-${version}"
source_dir="${project_root}/.private/deployed-artifacts"
release_dir="${project_root}/release"
archive="${release_dir}/${asset_name}.zip"
staging_dir="$(mktemp -d)"
asset_dir="${staging_dir}/${asset_name}"

cleanup() {
  rm -rf "${staging_dir}"
}
trap cleanup EXIT

for file in shielded_pool_final.zkey shielded_pool.wasm verification_key.json; do
  if [[ ! -f "${source_dir}/${file}" ]]; then
    echo "missing exact deployed artifact: ${source_dir}/${file}" >&2
    exit 1
  fi
done

actual_zkey="$(shasum -a 256 "${source_dir}/shielded_pool_final.zkey" | cut -d ' ' -f 1)"
actual_wasm="$(shasum -a 256 "${source_dir}/shielded_pool.wasm" | cut -d ' ' -f 1)"
actual_vkey="$(jq -S -c . "${source_dir}/verification_key.json" | shasum -a 256 | cut -d ' ' -f 1)"

[[ "${actual_zkey}" == "c3c56072a706e8489272248352a130b20c80ec6ee63fbc06211f0bc5438414ba" ]]
[[ "${actual_wasm}" == "7de9771dc82cd849234d85fc4b52d6359d69469f18d0acc0cf887258782f2a18" ]]
[[ "${actual_vkey}" == "b4502a5746a628da94d5f46db3877d8979cb3c3bb95eb646317a2880d9a763b5" ]]

mkdir -p "${release_dir}" "${asset_dir}"
rm -f "${archive}" "${archive}.sha256"
cp "${source_dir}/shielded_pool_final.zkey" "${asset_dir}/"
cp "${source_dir}/shielded_pool.wasm" "${asset_dir}/"
cp "${source_dir}/verification_key.json" "${asset_dir}/"
cp "${project_root}/evidence/deployed-v4-chain-manifest.json" "${asset_dir}/"

(
  cd "${asset_dir}"
  find . -type f ! -name MANIFEST.sha256 -print0 \
    | sort -z \
    | xargs -0 shasum -a 256 > MANIFEST.sha256
)

(
  cd "${staging_dir}"
  zip -qr "${archive}" "${asset_name}"
)

(
  cd "${release_dir}"
  shasum -a 256 "${asset_name}.zip" > "${asset_name}.zip.sha256"
)

echo "Created ${archive}"
echo "Created ${archive}.sha256"
