# Trust Registry Operator CLI

Local operator CLI for `midnight-trust-registry`.

Current scope:

- create a deterministic demo snapshot backed by the local simulator harness
- create a mutable operator workspace backed by an append-only CLI action journal
- inspect registry, policy, authorization, recognition, and epoch records from a
  a saved snapshot or a saved operator workspace
- submit, approve, activate, suspend, revoke, and archive issuer, verifier, and
  recognition records without raw simulator access
- publish a registry epoch anchor from the local operator workspace
- export anchored issuer, verifier, and recognition evidence bundles as JSON
- render deterministic human-readable audit reports from a saved snapshot or
  workspace

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

node packages/trust-registry-cli/bin/trust-registry.mjs report \
  --workspace ./artifacts/trust-registry/workspace.json \
  --kind full
```
