# Trust Registry Admin Console

Local admin review console for `midnight-trust-registry`.

Current scope:

- inspect registry summary and epoch metadata from the API
- review issuer, verifier, auditor, and recognition records grouped by lifecycle status
- prepare policy-bound Compact approval and activation contexts for issuer,
  verifier, auditor, and recognition cards; paste externally produced public
  signer entries and submit them through the optional governed-action API port
- prepare issuer, verifier, auditor, or maintainer proposals from a redacted signed evidence
  envelope, then submit external maintainer signatures and a separate
  registered evidence-verifier JubJub signature through the optional governed
  role-specific proposal API ports; recover a lost submit receipt by querying
  the matching Compact proposal event without replaying the action
- require explicit confirmation before submitting signed actions; the contract
  remains responsible for current-policy, signer-membership, and quorum checks
- prepare threshold-policy revision and subsequent evidence-verifier key
  registration as separate Compact actions with external maintainer signatures;
  warn while the second action remains pending in the current browser session
- load a no-cache workspace mutation context and submit an externally signed
  maintainer action envelope after explicit confirmation. This local file-backed
  workspace path is not a Compact quorum action and does not establish network
  finality. The page clears the pasted envelope and never handles private keys
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
  does not configure governed proposal ports, so proposal preparation and
  resolution receive 503 until an embedding server injects Compact-backed ports. The
  server must submit supplied signatures, never fall back to fixture replay.
  The governed policy panel also requires an injected `governedPolicyActions`
  port. Its pending-registration warning is session-local; after reload, the
  operator must inspect ledger state before accepting new application evidence.
  The browser accepts only redacted evidence and externally produced signatures;
  it does not handle private keys or persist evidence/signatures in browser
  storage. Prepared proposal context is discarded when the role, target ID, evidence,
  API connection, or board changes. The contract rechecks current policy,
  sequence, evidence, verifier identity, and quorum at submission
- a `not-observed` proposal is not proof that submission failed. The console
  does not retry automatically; a host must determine finality before any
  further action. Simulator observation is not network finality
- `--unsafe-demo-mutations` enables the old fixture controls only on loopback;
  remove that flag when the signed mutation and Compact ports are wired for a
  real deployment
- auditor cards show the exact composite request-resource ID, policy, epoch,
  evidence state root, and lifecycle status. The full request-scope preimage
  is not present in the operator snapshot and is not inferred from the hash;
  archived cards are historical evidence, not active authorization
- this slice is admin-only: applicant submission and public inspection stay in
  the later portal slice
