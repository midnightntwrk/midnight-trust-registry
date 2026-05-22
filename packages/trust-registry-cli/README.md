# Trust Registry Operator CLI

Local operator CLI for `midnight-trust-registry`.

Current scope:

- create a deterministic demo snapshot backed by the local simulator harness
- inspect registry, policy, authorization, recognition, and epoch records from a
  saved snapshot
- export anchored issuer, verifier, and recognition evidence bundles as JSON

Build the workspace first from the repo root:

```bash
./run.sh --light
```

Example usage from the repo root:

```bash
node packages/trust-registry-cli/bin/trust-registry.mjs init-demo \
  --output ./artifacts/trust-registry/demo-snapshot.json

node packages/trust-registry-cli/bin/trust-registry.mjs summary \
  --snapshot ./artifacts/trust-registry/demo-snapshot.json

node packages/trust-registry-cli/bin/trust-registry.mjs export-evidence \
  --snapshot ./artifacts/trust-registry/demo-snapshot.json \
  --kind issuer \
  --id auth:issuer:passport:v1 \
  --output ./artifacts/trust-registry/passport-issuer-evidence.json
```
