#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

# Preserve full Compact outputs in artifact-bearing checkouts. This verifies
# their source and completeness, but does not independently prove provenance.
pnpm run contract:check-full-artifacts

bash scripts/build-prebuilt-runtime.sh

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
