#!/usr/bin/env bash
set -euo pipefail

registry="${REGISTRY:-https://registry.npmjs.org}"
npm_tag="${NPM_TAG:-next}"
version="${VERSION:-}"
tarball_dir="${TARBALL_DIR:-artifacts/npm-release}"
manifest_path="${MANIFEST_PATH:-}"

if [[ -z "${NODE_AUTH_TOKEN:-${NPM_TOKEN:-}}" ]]; then
  echo "::error::NODE_AUTH_TOKEN or NPM_TOKEN is required to publish packages." >&2
  exit 1
fi

if [[ -z "${version}" ]]; then
  echo "::error::VERSION is required to publish packages." >&2
  exit 1
fi

if [[ -z "${manifest_path}" || ! -f "${manifest_path}" ]]; then
  echo "::error::A verified release manifest is required to publish packages." >&2
  exit 1
fi
node scripts/release-candidate-manifest.mjs --artifact-dir "${tarball_dir}" --verify "${manifest_path}"
node --input-type=module -e '
  import { readFileSync } from "node:fs";
  const [path, version] = process.argv.slice(1);
  if (JSON.parse(readFileSync(path, "utf8")).packageVersion !== version) {
    throw new Error("Approved release manifest version differs from publish version");
  }
' "${manifest_path}" "${version}"

published_version_for_package() {
  local package_name="$1"
  npm view "${package_name}@${version}" version --registry "${registry}" 2>/dev/null || true
}

while IFS= read -r workspace; do
  if [[ -z "${workspace}" ]]; then
    continue
  fi

  package_name="$(
    node --input-type=module -e '
      import { packageManifestCatalog } from "./scripts/trust-registry-workspace-catalog.mjs";
      const workspace = process.argv[1];
      const name = packageManifestCatalog.get(workspace)?.name;
      if (!name) {
        throw new Error(`missing package name for ${workspace}`);
      }
      process.stdout.write(name);
    ' "${workspace}"
  )"
  tarball="${tarball_dir}/$(node -e 'const [name, version] = process.argv.slice(1); process.stdout.write(`${name.replace(/^@/, "").replace("/", "-")}-${version}.tgz`)' "${package_name}" "${version}")"
  if [[ ! -s "${tarball}" ]]; then
    echo "::error::Packed tarball is missing or empty: ${tarball}" >&2
    exit 1
  fi

  published_version="$(published_version_for_package "${package_name}")"
  if [[ "${published_version}" == "${version}" ]]; then
    echo "[publish-npm-packages] ${package_name}@${version} already exists; skipping immutable npm publish."
    continue
  fi

  echo "[publish-npm-packages] Publishing tested tarball ${tarball} with npm tag ${npm_tag}"
  npm publish "${tarball}" --ignore-scripts --access public --registry "${registry}" --tag "${npm_tag}"
done < <(node scripts/trust-registry-workspace-catalog.mjs --publish-workspaces)
