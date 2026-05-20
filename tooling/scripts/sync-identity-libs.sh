#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
LIBS_DIR="${1:-$ROOT_DIR/libs}"
DID_ROOT="${MIDNIGHT_DID_ROOT:-$ROOT_DIR/../midnight-did}"
VC_ROOT="${MIDNIGHT_VC_ROOT:-$ROOT_DIR/../midnight-verifiable-credentials}"
KNOWN_PACKAGES=(
  "@midnight-ntwrk/midnight-did"
  "@midnight-ntwrk/midnight-did-contract"
  "@midnight-ntwrk/midnight-did-domain"
  "@midnight-ntwrk/midnight-did-jubjub-schnorr"
  "@midnight-ntwrk/midnight-did-credentials"
  "@midnight-ntwrk/midnight-did-credentials-openid"
  "@midnight-ntwrk/midnight-did-credentials-status-registry"
)
BUILT_WORKSPACES=()
SYNCED_PACKAGES=()
REQUIRED_PACKAGES=()

mkdir -p "$LIBS_DIR"

array_contains() {
  local needle="$1"
  shift
  local value=""

  for value in "$@"; do
    if [[ "$value" == "$needle" ]]; then
      return 0
    fi
  done

  return 1
}

package_source_root() {
  case "$1" in
    "@midnight-ntwrk/midnight-did"|\
    "@midnight-ntwrk/midnight-did-contract"|\
    "@midnight-ntwrk/midnight-did-domain"|\
    "@midnight-ntwrk/midnight-did-jubjub-schnorr")
      printf '%s\n' "$DID_ROOT"
      ;;
    "@midnight-ntwrk/midnight-did-credentials"|\
    "@midnight-ntwrk/midnight-did-credentials-openid"|\
    "@midnight-ntwrk/midnight-did-credentials-status-registry")
      printf '%s\n' "$VC_ROOT"
      ;;
  esac
}

package_workspace() {
  case "$1" in
    "@midnight-ntwrk/midnight-did")
      printf '%s\n' "did"
      ;;
    "@midnight-ntwrk/midnight-did-contract")
      printf '%s\n' "contract"
      ;;
    "@midnight-ntwrk/midnight-did-domain")
      printf '%s\n' "domain"
      ;;
    "@midnight-ntwrk/midnight-did-jubjub-schnorr")
      printf '%s\n' "jubjub-schnorr"
      ;;
    "@midnight-ntwrk/midnight-did-credentials")
      printf '%s\n' "core/primitives/credentials"
      ;;
    "@midnight-ntwrk/midnight-did-credentials-openid")
      printf '%s\n' "protocols/openid"
      ;;
    "@midnight-ntwrk/midnight-did-credentials-status-registry")
      printf '%s\n' "registry/status-registry"
      ;;
  esac
}

package_namespace_dir() {
  case "$1" in
    "@midnight-ntwrk/midnight-did"|\
    "@midnight-ntwrk/midnight-did-contract"|\
    "@midnight-ntwrk/midnight-did-domain"|\
    "@midnight-ntwrk/midnight-did-jubjub-schnorr")
      printf '%s\n' "midnight-did"
      ;;
    "@midnight-ntwrk/midnight-did-credentials"|\
    "@midnight-ntwrk/midnight-did-credentials-openid"|\
    "@midnight-ntwrk/midnight-did-credentials-status-registry")
      printf '%s\n' "midnight-verifiable-credentials"
      ;;
  esac
}

list_required_packages() {
  node --input-type=module - "$ROOT_DIR" <<'NODE'
import fs from "node:fs";
import path from "node:path";

const rootDir = process.argv[2];
const manifestPaths = [
  path.join(rootDir, "package.json"),
];

for (const workspaceRoot of ["contracts", "packages"]) {
  const absoluteWorkspaceRoot = path.join(rootDir, workspaceRoot);
  if (!fs.existsSync(absoluteWorkspaceRoot)) continue;
  for (const entry of fs.readdirSync(absoluteWorkspaceRoot, {
    withFileTypes: true,
  })) {
    if (!entry.isDirectory()) continue;
    manifestPaths.push(
      path.join(absoluteWorkspaceRoot, entry.name, "package.json"),
    );
  }
}

const dependencyFields = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
];

const packageNames = new Set();

for (const manifestPath of manifestPaths) {
  if (!fs.existsSync(manifestPath)) continue;
  const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  for (const field of dependencyFields) {
    for (const packageName of Object.keys(manifest[field] ?? {})) {
      if (packageName.startsWith("@midnight-ntwrk/")) {
        packageNames.add(packageName);
      }
    }
  }
}

for (const packageName of [...packageNames].sort()) {
  console.log(packageName);
}
NODE
}

list_local_package_dependencies() {
  local package_manifest="$1"

  node --input-type=module - "$package_manifest" <<'NODE'
import fs from "node:fs";

const manifestPath = process.argv[2];
const dependencyFields = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
];

const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const packageNames = new Set();

for (const field of dependencyFields) {
  for (const packageName of Object.keys(manifest[field] ?? {})) {
    if (packageName.startsWith("@midnight-ntwrk/")) {
      packageNames.add(packageName);
    }
  }
}

for (const packageName of [...packageNames].sort()) {
  console.log(packageName);
}
NODE
}

sync_package() {
  local package_name="$1"
  local source_root
  source_root="$(package_source_root "$package_name")"
  local workspace
  workspace="$(package_workspace "$package_name")"
  local namespace_dir
  namespace_dir="$(package_namespace_dir "$package_name")"

  if [[ -z "$source_root" ]] || [[ -z "$workspace" ]] || [[ -z "$namespace_dir" ]]; then
    return 0
  fi

  if [[ ! -d "$source_root" ]]; then
    echo "[sync-identity-libs] source repo not found at $source_root" >&2
    exit 1
  fi

  local build_key="$source_root::$workspace"
  if ! array_contains "$build_key" "${BUILT_WORKSPACES[@]-}"; then
    echo "[sync-identity-libs] Building $package_name ($workspace) from $source_root"
    (
      cd "$source_root"
      npm run build -w "$workspace"
    )
    BUILT_WORKSPACES+=("$build_key")
  fi

  local source_dir="$source_root/$workspace/"
  local dest_dir="$LIBS_DIR/$namespace_dir/$workspace/"

  echo "[sync-identity-libs] Syncing $package_name -> $dest_dir"
  rm -rf "$dest_dir"
  mkdir -p "$dest_dir"
  rsync -a \
    --delete \
    --exclude '.turbo' \
    --exclude 'coverage' \
    --exclude 'node_modules' \
    --exclude 'reports' \
    --exclude 'src/managed' \
    --exclude '*.tsbuildinfo' \
    "$source_dir" \
    "$dest_dir"

  cat > "$dest_dir/README.md" <<EOF
# Vendored Package Copy

This directory is a repository-local copy of \`$package_name\`, synced from:

- source repo: \`$(basename "$source_root")\`
- workspace: \`$workspace\`

Refresh it with:

\`\`\`bash
./upgrade-libs.sh --destination .
\`\`\`
EOF

  if ! array_contains "$package_name" "${REQUIRED_PACKAGES[@]-}"; then
    REQUIRED_PACKAGES+=("$package_name")
  fi
}

enqueue_required_package() {
  local package_name="$1"

  if [[ -z "$(package_workspace "$package_name")" ]]; then
    return 0
  fi

  if array_contains "$package_name" "${SYNCED_PACKAGES[@]-}"; then
    return 0
  fi

  sync_package "$package_name"
  SYNCED_PACKAGES+=("$package_name")

  local source_root
  source_root="$(package_source_root "$package_name")"
  local workspace
  workspace="$(package_workspace "$package_name")"
  local package_manifest="$source_root/$workspace/package.json"

  while IFS= read -r local_dependency; do
    [[ -z "$local_dependency" ]] && continue
    enqueue_required_package "$local_dependency"
  done < <(list_local_package_dependencies "$package_manifest")
}

remove_stale_synced_packages() {
  local package_name=""

  for package_name in "${KNOWN_PACKAGES[@]}"; do
    if array_contains "$package_name" "${REQUIRED_PACKAGES[@]-}"; then
      continue
    fi

    local namespace_dir
    namespace_dir="$(package_namespace_dir "$package_name")"
    local workspace
    workspace="$(package_workspace "$package_name")"
    local stale_dir="$LIBS_DIR/$namespace_dir/$workspace"
    rm -rf "$stale_dir"
  done
}

while IFS= read -r package_name; do
  [[ -z "$package_name" ]] && continue
  enqueue_required_package "$package_name"
done < <(list_required_packages)

remove_stale_synced_packages
