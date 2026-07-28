#!/usr/bin/env bash
set -euo pipefail

registry="${REGISTRY:-https://registry.npmjs.org}"
version="${VERSION:-}"

if [[ -z "${version}" ]]; then
  echo "::error::VERSION is required to smoke test published packages." >&2
  exit 1
fi

node scripts/smoke-published-artifacts.mjs \
  --version "${version}" \
  --registry "${registry}"
