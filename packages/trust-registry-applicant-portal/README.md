# Trust Registry Applicant Portal

Local applicant and public-inspection portal for `midnight-trust-registry`.

Current scope:

- submit issuer, verifier, or recognition applications through the existing API
- inspect current active issuer, verifier, auditor, and recognition records
- show an authenticated, server-owned canonical scope for a pending auditor
  application, issue a one-use VP challenge, and submit the presentation to
  receive redacted signed evidence and a receipt. The VP is never placed in
  browser storage or rendered back into the page.
- register a pending auditor application with an externally signed Midnight DID
  `apply` intent. The browser accepts a signed request, never a private key.
- do not offer label-only auditor submission. The demo API's unsigned mutation
  route is not a governed admission boundary and must not be publicly exposed.
- keep the first portal slice static and local-first instead of adding a second
  backend or browser persistence layer

The pending-auditor panel is enabled only when the portal and API are hosted at
the same HTTPS origin (or the same localhost origin for development). The host
must inject a `PendingAuditorRegistrationPort` and an `ApplicationVpHttpPort`
with applicant authentication, a trusted
pending-application resolver, VP verifier, authorized evidence signer, atomic
challenge store, and redacted evidence persistence. The packaged API CLI does
not mount this port; the default two-port demo below only supports public
inspection and unsafe local fixture submissions. Private-route errors discard
the server response body so a failing verifier cannot echo claims into the UI.
Challenge and VP data are held only in the current page session; a rejected VP
requires a new challenge. The `apply` step registers only an off-ledger
pending record and its server-owned binding; it does not create a governed
proposal or approve membership. The reference in-memory registration port is
single-process and non-durable. A production host must provide atomic pending
persistence, a live policy view, and an authorized evidence verifier before
exposing this flow.

To demonstrate the private panel without a production host, run
`pnpm run demo:auditor` from the repository root and open its loopback URL.
Paste the signed fixture application printed in the terminal. After the panel
issues a challenge, run `node scripts/demo-auditor-admission.mjs vp <nonce>`
in another terminal and paste the generated fixture VP. This reference host
uses a single local fixture applicant, an in-memory session and evidence store,
and a fixed virtual clock. It never activates membership and must not be
exposed on a public interface. `pnpm run demo:auditor:smoke` verifies the same
HTTP flow without a browser.

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
