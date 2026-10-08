# Trust Registry Operator CLI

Local operator CLI for `midnight-trust-registry`.

Current scope:

- create a deterministic demo snapshot backed by the local simulator harness
- create a mutable operator workspace backed by an append-only CLI action journal
- inspect registry, policy, authorization, recognition, and epoch records from a
  saved snapshot or a saved operator workspace
- submit, approve, activate, suspend, revoke, and archive issuer, verifier,
  auditor, and recognition records without raw simulator access
- publish a registry epoch anchor from the local operator workspace
- export anchored issuer, verifier, auditor, and recognition evidence bundles as JSON
- inspect historical issuer, verifier, auditor, recognition, and epoch state at a
  specific timestamp
- render deterministic human-readable audit reports from a saved snapshot or a
  saved operator workspace

Build the workspace first from the repo root:

```bash
./run.sh --light
```

Example usage from the repo root:

```bash
node packages/trust-registry-cli/bin/trust-registry.mjs init-demo \
  --output ./artifacts/trust-registry/demo-snapshot.json

node packages/trust-registry-cli/bin/trust-registry.mjs init-workspace \
  --workspace ./artifacts/trust-registry/workspace.json

node packages/trust-registry-cli/bin/trust-registry.mjs summary \
  --snapshot ./artifacts/trust-registry/demo-snapshot.json

node packages/trust-registry-cli/bin/trust-registry.mjs submit \
  --workspace ./artifacts/trust-registry/workspace.json \
  --kind issuer \
  --label passport \
  --json

node packages/trust-registry-cli/bin/trust-registry.mjs approve \
  --workspace ./artifacts/trust-registry/workspace.json \
  --kind issuer \
  --id auth:issuer:passport:v1

node packages/trust-registry-cli/bin/trust-registry.mjs activate \
  --workspace ./artifacts/trust-registry/workspace.json \
  --kind issuer \
  --id auth:issuer:passport:v1

node packages/trust-registry-cli/bin/trust-registry.mjs export-evidence \
  --workspace ./artifacts/trust-registry/workspace.json \
  --kind issuer \
  --id auth:issuer:passport:v1 \
  --output ./artifacts/trust-registry/passport-issuer-evidence.json

node packages/trust-registry-cli/bin/trust-registry.mjs inspect \
  --snapshot ./artifacts/trust-registry/demo-snapshot.json \
  --kind issuer \
  --id auth:issuer:passport:v1 \
  --at 2026-05-20T00:30:00Z

node packages/trust-registry-cli/bin/trust-registry.mjs report \
  --workspace ./artifacts/trust-registry/workspace.json \
  --kind full
```

The unreleased v1 operator snapshot requires a separate `auditorEntries`
collection. CLI and API role lookups never treat a verifier entry as an
auditor grant. The returned lifecycle state must be checked: archived evidence
preserves history but does not establish current authorization.
