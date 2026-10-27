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

# The contract helper imports generated declarations from src/managed. Restore
# only this small contract module from the preserved dist copy when absent.
source_managed=contracts/trust-registry/src/managed/trust-registry/contract
dist_managed=contracts/trust-registry/dist/managed/trust-registry/contract
if [[ -L "$source_managed" || -L "$(dirname "$source_managed")" ]]; then
  echo "Generated contract source must not be a symlink." >&2
  exit 1
fi
if [[ ! -e "$source_managed" ]]; then
  mkdir -p "$(dirname "$source_managed")"
  cp -R "$dist_managed" "$source_managed"
fi
if ! diff -qr "$source_managed" "$dist_managed" >/dev/null; then
  echo "Generated contract source differs from preserved dist artifacts; prepare a source-matched bundle." >&2
  exit 1
fi

# Compile contract TypeScript helpers in place without invoking its Compact build.
pnpm --filter @midnight-ntwrk/trust-registry-contract exec tsc -p tsconfig.build.json

# Rebuild downstream TypeScript and UI workspaces; never replace generated Compact keys.
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
