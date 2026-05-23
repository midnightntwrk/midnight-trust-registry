# Trust Registry Admin Console

Local admin review console for `midnight-trust-registry`.

Current scope:

- inspect registry summary and epoch metadata from the API
- review issuer, verifier, and recognition records grouped by lifecycle status
- approve, activate, suspend, revoke, and archive governed records
- publish registry epochs from the same console
- keep the first UI slice static and local-first instead of introducing a
  separate frontend build service

Run locally from the repo root:

```bash
./run.sh --light

node packages/trust-registry-cli/bin/trust-registry.mjs init-workspace \
  --workspace ./artifacts/trust-registry/workspace.json

node packages/trust-registry-api/bin/trust-registry-api.mjs serve \
  --workspace ./artifacts/trust-registry/workspace.json \
  --port 4400

npm run serve -w @midnight-ntwrk/trust-registry-admin-console -- --port 4173
```

Open:

- `http://127.0.0.1:4173/?apiBase=http%3A%2F%2F127.0.0.1%3A4400`

Notes:

- the console expects the API server to run on loopback
- the API package now serves permissive CORS headers for this local-only UI
- this slice is admin-only: applicant submission and public inspection stay in
  the later portal slice
