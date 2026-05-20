#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
DESTINATION=""

usage() {
  cat >&2 <<USAGE
Usage: $0 --destination <path>

Refresh local DID and VC dependency copies from sibling Midnight identity
repositories into the target repo `libs/` tree, grouped by source repo.

Arguments:
  --destination <path>  Target repo root, libs root, or concrete output dir
USAGE
}

resolve_dest_dir() {
  local destination="$1"

  if [[ -d "$destination/libs" ]] || [[ -f "$destination/package.json" ]]; then
    printf '%s/libs\n' "$destination"
  elif [[ "$(basename "$destination")" == "libs" ]]; then
    printf '%s\n' "$destination"
  else
    printf '%s\n' "$destination"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --destination)
      DESTINATION="${2:-}"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[upgrade-libs] Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if [[ -z "$DESTINATION" ]]; then
  usage
  exit 1
fi

LIBS_DEST="$(resolve_dest_dir "$DESTINATION")"
"$ROOT_DIR/tooling/scripts/sync-identity-libs.sh" "$LIBS_DEST"
echo "[upgrade-libs] Identity library copies refreshed in $LIBS_DEST"
