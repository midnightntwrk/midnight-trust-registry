# Trust Registry Applicant Portal

Local applicant and public-inspection portal for `midnight-trust-registry`.

Current scope:

- submit issuer, verifier, or recognition applications through the existing API
- inspect the current active registry surface for issuer, verifier, and
  recognition records
- keep the first portal slice static and local-first instead of adding a second
  backend or browser persistence layer

Run locally from the repo root:

```bash
./run.sh --light

node packages/trust-registry-cli/bin/trust-registry.mjs init-workspace \
  --workspace ./artifacts/trust-registry/workspace.json

node packages/trust-registry-api/bin/trust-registry-api.mjs serve \
  --workspace ./artifacts/trust-registry/workspace.json \
  --port 4400

npm run serve -w @midnight-ntwrk/trust-registry-applicant-portal -- --port 4175
```

Open:

- `http://127.0.0.1:4175/?apiBase=http%3A%2F%2F127.0.0.1%3A4400`

The `apiBase` query parameter is a session-only override for local testing. It
does not replace the saved default URL in browser storage.
