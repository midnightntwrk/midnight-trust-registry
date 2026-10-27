#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

source_file=contracts/trust-registry/src/trust-registry.compact
dist_file=contracts/trust-registry/dist/trust-registry.compact
managed_file=contracts/trust-registry/dist/managed/trust-registry/contract/index.js
if [[ ! -f "$dist_file" || ! -f "$managed_file" ]] || ! cmp -s "$source_file" "$dist_file"; then
  echo "Prebuilt Compact contract is absent or differs from current source; prepare it in a disposable checkout." >&2
  exit 1
fi

# Only rebuild TypeScript and UI workspaces; never replace generated Compact keys.
pnpm -r \
  --filter @midnight-ntwrk/trust-registry-domain \
  --filter @midnight-ntwrk/trust-registry-client \
  --filter @midnight-ntwrk/trust-registry-integration \
  --filter @midnight-ntwrk/trust-registry-cli \
  --filter @midnight-ntwrk/trust-registry-api \
  --filter @midnight-ntwrk/trust-registry-admin-console \
  --filter @midnight-ntwrk/trust-registry-applicant-portal \
  --filter @midnight-ntwrk/trust-registry-trqp-adapter \
  --filter @midnight-ntwrk/trust-registry-openid-federation-adapter \
  run build
