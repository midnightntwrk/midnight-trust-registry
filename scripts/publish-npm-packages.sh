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

lookup_error="$(mktemp)"
trap 'rm -f "${lookup_error}"' EXIT

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

  if published_dist="$(npm view "${package_name}@${version}" dist --json --registry "${registry}" 2>"${lookup_error}")"; then
    node scripts/check-publish-tarball.mjs "${manifest_path}" "${tarball}" "${package_name}" "${version}"
    node scripts/check-published-package-integrity.mjs "${tarball}" "${published_dist}"
    echo "[publish-npm-packages] ${package_name}@${version} already exists with matching bytes; skipping immutable npm publish."
    continue
  fi
  if ! grep -Eq '^npm (error|ERR!) code E404$' "${lookup_error}"; then
    echo "::error::Could not determine whether ${package_name}@${version} already exists; refusing publish." >&2
    exit 1
  fi

  node scripts/check-publish-tarball.mjs "${manifest_path}" "${tarball}" "${package_name}" "${version}"
  echo "[publish-npm-packages] Publishing tested tarball ${tarball} with npm tag ${npm_tag}"
  npm publish "${tarball}" --ignore-scripts --access public --registry "${registry}" --tag "${npm_tag}"
done < <(node scripts/trust-registry-workspace-catalog.mjs --publish-workspaces)
