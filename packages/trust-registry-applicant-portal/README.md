# Trust Registry Applicant Portal

Local applicant and public-inspection portal for `midnight-trust-registry`.

Current scope:

- submit issuer, verifier, or recognition applications through the existing API
- inspect current active issuer, verifier, auditor, and recognition records
- show an authenticated, server-owned canonical scope for a pending auditor
  application, issue a one-use VP challenge, and submit the presentation to
  receive redacted signed evidence and a receipt. The VP is never placed in
  browser storage or rendered back into the page.
- do not offer label-only auditor submission. The demo API's unsigned mutation
  route is not a governed admission boundary and must not be publicly exposed.
- keep the first portal slice static and local-first instead of adding a second
  backend or browser persistence layer

The pending-auditor panel is enabled only when the portal and API are hosted at
the same HTTPS origin (or the same localhost origin for development). The host
must inject an `ApplicationVpHttpPort` with applicant authentication, a trusted
pending-application resolver, VP verifier, authorized evidence signer, atomic
challenge store, and redacted evidence persistence. The packaged API CLI does
not mount this port; the default two-port demo below only supports public
inspection and unsafe local fixture submissions. Private-route errors discard
the server response body so a failing verifier cannot echo claims into the UI.
Challenge and VP data are held only in the current page session; a rejected VP
requires a new challenge. The panel does not create an application or approve
membership. A trusted admission host must create and bind the complete auditor
scope and Midnight DID before the applicant enters its application ID here.

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
