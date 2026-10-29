#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Preserve full Compact outputs in artifact-bearing checkouts. This verifies
# their source and completeness, but does not independently prove provenance.
pnpm run contract:check-full-artifacts

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

pnpm --filter @midnight-ntwrk/trust-registry-integration run integration
pnpm --filter @midnight-ntwrk/trust-registry-api run integration
pnpm --filter @midnight-ntwrk/trust-registry-applicant-portal run integration
pnpm --filter @midnight-ntwrk/trust-registry-admin-console run integration

node scripts/demo-governed-registry.mjs
node scripts/demo-auditor-admission.mjs smoke
for role in issuer verifier auditor maintainer; do
  node scripts/demo-signed-membership-journey.mjs "$role"
done
node scripts/demo-signed-journey.mjs

pnpm run contract:check-full-artifacts
