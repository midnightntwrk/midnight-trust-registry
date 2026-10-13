# Trust Registry Admin Console

Local admin review console for `midnight-trust-registry`.

Current scope:

- inspect registry summary and epoch metadata from the API
- review issuer, verifier, auditor, and recognition records grouped by lifecycle status
- prepare policy-bound Compact approval and activation contexts for issuer,
  verifier, auditor, and recognition cards; paste externally produced public
  signer entries and submit them through the optional governed-action API port
- prepare an issuer application proposal from a redacted signed evidence
  envelope, then submit external maintainer signatures and a separate
  registered evidence-verifier JubJub signature through the optional governed
  issuer-proposal API port
- require explicit confirmation before submitting signed actions; the contract
  remains responsible for current-policy, signer-membership, and quorum checks
- retain separate local fixture mutation and epoch controls for the deliberately
  unsafe workspace demo, not for public or production governance
- keep the first UI slice static and local-first instead of introducing a
  separate frontend build service

Run locally from the repo root:

```bash
./run.sh --light

node packages/trust-registry-cli/bin/trust-registry.mjs init-workspace \
  --workspace ./artifacts/trust-registry/workspace.json

node packages/trust-registry-api/bin/trust-registry-api.mjs serve \
  --workspace ./artifacts/trust-registry/workspace.json \
  --unsafe-demo-mutations \
  --port 4400

pnpm --filter @midnight-ntwrk/trust-registry-admin-console run serve -- --port 4173
```

Open:

- `http://127.0.0.1:4173/?apiBase=http%3A%2F%2F127.0.0.1%3A4400`

Notes:

- the console expects the API server to run on loopback
- the API package now serves permissive CORS headers for this local-only UI
- the packaged CLI does **not** configure `governedMembershipActions`, so the
  Compact action panel receives 503 in this basic workspace setup. It also
  does not configure `governedIssuerProposals`, so issuer proposal preparation
  receives 503 until an embedding server injects the Compact-backed port. The
  server must submit supplied signatures, never fall back to fixture replay.
  The browser accepts only redacted evidence and externally produced signatures;
  it does not handle private keys or persist evidence/signatures in browser
  storage. Prepared proposal context is discarded when the issuer ID, evidence,
  API connection, or board changes. The contract rechecks current policy,
  sequence, evidence, verifier identity, and quorum at submission
- the governed proposal panel currently supports issuers only. Do not use it
  to infer on-chain evidence-verifier coverage for verifier, auditor, or
  maintainer proposals
- `--unsafe-demo-mutations` enables the old fixture controls only on loopback;
  remove that flag when the signed mutation and Compact ports are wired for a
  real deployment
- auditor cards show the exact composite request-resource ID, policy, epoch,
  evidence state root, and lifecycle status. The full request-scope preimage
  is not present in the operator snapshot and is not inferred from the hash;
  archived cards are historical evidence, not active authorization
- this slice is admin-only: applicant submission and public inspection stay in
  the later portal slice
