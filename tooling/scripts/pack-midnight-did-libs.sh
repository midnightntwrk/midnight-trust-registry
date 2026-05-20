#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
DID_ROOT="${MIDNIGHT_DID_ROOT:-$ROOT_DIR/../midnight-did}"
DEST_DIR="${1:-$ROOT_DIR/tooling/vendor/midnight-did}"

if [[ ! -d "$DID_ROOT" ]]; then
  echo "[pack-midnight-did-libs] midnight-did repo not found at $DID_ROOT" >&2
  exit 1
fi

mkdir -p "$DEST_DIR"
rm -f "$DEST_DIR"/midnight-ntwrk-midnight-did-jubjub-schnorr-*.tgz

echo "[pack-midnight-did-libs] Packing jubjub-schnorr -> $DEST_DIR"
(
  cd "$DID_ROOT"
  npm pack --pack-destination "$DEST_DIR" -w jubjub-schnorr
)
