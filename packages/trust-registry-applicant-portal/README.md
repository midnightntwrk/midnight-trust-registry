# Trust Registry Applicant Portal

Local applicant and public-inspection portal for `midnight-trust-registry`.

Current scope:

- submit issuer, verifier, or recognition applications through the existing API
- inspect current active issuer, verifier, auditor, and recognition records
- do not offer auditor submission in this portal until challenge-bound evidence
  admission and authenticated mutation routes are available. This UI restriction
  is not an authorization boundary: the local demo API still accepts unsigned
  auditor writes and must not be exposed as a public governed mutation service.
- keep the first portal slice static and local-first instead of adding a second
  backend or browser persistence layer

The portal client also has `issueApplicationChallenge` and
`submitApplicationPresentation` methods for a future authenticated same-origin
host. They send the nonce/hash and raw VP only in the submission request, then
return the server's signed redacted evidence and receipt. Private-route errors
discard the server response body so a failing verifier cannot echo claims into
the UI. The page does not expose a VP form, and neither presentation nor
challenge is saved to browser storage. The packaged API CLI does not mount the
required applicant-authenticated verifier port; these methods are not a public
membership flow on their own.

Run locally from the repo root:

```bash
./run.sh --light

node packages/trust-registry-cli/bin/trust-registry.mjs init-workspace \
  --workspace ./artifacts/trust-registry/workspace.json

node packages/trust-registry-api/bin/trust-registry-api.mjs serve \
  --workspace ./artifacts/trust-registry/workspace.json \
  --port 4400

pnpm --filter @midnight-ntwrk/trust-registry-applicant-portal run serve -- --port 4175
```

Open:

- `http://127.0.0.1:4175/?apiBase=http%3A%2F%2F127.0.0.1%3A4400`

The `apiBase` query parameter is a session-only override for local testing. It
does not replace the saved default URL in browser storage.
