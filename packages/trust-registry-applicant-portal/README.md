# Trust Registry Applicant Portal

Local applicant and public-inspection portal for `midnight-trust-registry`.

Current scope:

- submit issuer, verifier, or recognition applications through the existing API
- inspect current active issuer, verifier, auditor, and recognition records
- export an exact DID/role/governed-resource authorization claim at a supplied
  RFC3339 timestamp. The portal labels its status and bundle as an unverified
  API claim; a relying party must use an independently authenticated historical
  ledger anchor and the client verifier before accepting it as evidence.
- export an external recognition claim by authority DID, registry, scope
  resource, optional exact context map, and timestamp. Omitted context selects
  only context-free records. Recognition never grants local membership.
- show an authenticated, server-owned canonical scope for a pending membership
  application, issue a one-use VP challenge, and submit the presentation to
  receive redacted signed evidence and a receipt. The VP is never placed in
  browser storage or rendered back into the page.
- recover accepted redacted evidence and its receipt by application ID when an
  HTTP response was lost. Recovery is a same-origin authenticated GET, not a
  second VP submission or a membership approval.
- register a pending issuer, verifier, auditor, or maintainer application with
  an externally signed Midnight DID `apply` intent. The browser accepts a
  signed request, never a private key.
- prepare canonical issuer, verifier, and maintainer requests from structured
  fields. The maintainer scope and governed resource both use the registry ID
  returned by the host's current mutation context; an applicant cannot select
  a different registry in the form. External signing and governance approval
  remain separate steps.
- enter the complete auditor request scope (profile, purpose, credential-scope
  commitment, attributes, predicates, and disclosure level), application IDs,
  and applicant Midnight DID authentication method. The portal fetches the
  current workspace/epoch and host evaluation time, generates a fresh nonce,
  and displays the exact canonical resource, `tr-mutation-intent-v1` JSON, and
  SHA-256 digest bytes for an external JubJub signer. Paste only the resulting
  canonical 96-byte signature; the browser constructs the signed request and
  never receives a private key. The host rechecks the DID signature, current
  context, nonce, and complete scope. If signing context expires or the
  workspace changes, refresh and sign the newly prepared digest.
- look up an auditor authorization by ID and distinguish pending or unrecorded
  applications from current active grants and archived or expired records.
  Historical activation is never displayed as current trust.
- load a no-cache workspace mutation context and submit an externally signed
  issuer or verifier `submit` envelope. This local workspace flow is separate
  from the governed VP application and Compact quorum approval path. The
  browser clears pasted envelopes after submission and does not retain keys.
- do not offer label-only auditor submission. The demo API's unsigned mutation
  route is not a governed admission boundary and must not be publicly exposed.
- keep the first portal slice static and local-first instead of adding a second
  backend or browser persistence layer

The private pending-application panel is enabled only when the portal and API are hosted at
the same HTTPS origin (or the same localhost origin for development). The host
must inject a `PendingApplicationRegistrationPort` and an `ApplicationVpHttpPort`
with applicant authentication, a trusted
pending-application resolver, VP verifier, authorized evidence signer, atomic
challenge store, and redacted evidence persistence. The packaged API CLI does
not mount this port; the default two-port demo below only supports public
inspection and unsafe local fixture submissions. Private-route errors discard
the server response body so a failing verifier cannot echo claims into the UI.
Challenge and VP data are held only in the current page session; a rejected VP
requires a new challenge. Accepted evidence is displayed only in page memory;
the recovered record contains no raw VP. If the server has no accepted receipt,
the applicant must not infer that the previous submission failed or automatically
resubmit it. The `apply` step registers only an off-ledger
pending record and its server-owned binding; it does not create a governed
proposal or approve membership. The reference in-memory registration port is
single-process and non-durable. A production host must provide atomic pending
persistence, a live policy view, and an authorized evidence verifier before
exposing this flow.

To demonstrate the private panel without a production host, run
`pnpm run demo:auditor` from the repository root and open its loopback URL.
The terminal prints a signed fixture application for the advanced JSON field
and the same fixture's values for the auditor form. To use the form, enter the
printed draft values, select **Prepare signing digest**, run
`node scripts/demo-auditor-admission.mjs sign-digest <digest>` in another
terminal, and paste its signature. The demo smoke test signs the digest from
this same form preparation code and registers the result through the HTTP API.
After registration, issue a challenge, run
`node scripts/demo-auditor-admission.mjs vp <nonce>`, and paste the fixture VP.
The `sign-digest` command uses a fixed fixture key and must never sign a real
application. A DOM-driven integration test also runs the form against the
loopback HTTP host: it rejects a forged signature, accepts a valid one, issues
a challenge, and submits the one-use VP. This is not a browser-engine or
live-network test. This reference host uses a single local fixture applicant,
an in-memory session and evidence store,
and a fixed virtual clock. It never activates membership and must not be
exposed on a public interface. `pnpm run demo:auditor:smoke` verifies the same
HTTP flow without a browser.

For the auditor-specific form, fill the exact scope and applicant DID fields,
select **Prepare signing digest**, sign the displayed digest bytes using the
applicant DID authentication key outside the browser, and paste the returned
`0x`-prefixed 96-byte JubJub signature. The advanced full-JSON field remains
available for an external signer that constructs the complete envelope. The
portal rejects a different role or scope before sending it. A successful
registration shows `pending`, not `active`; after governance acts, use the
authorization ID lookup to inspect the public current status. The label-only
demo form intentionally does not offer auditor submission. The reference
`demo:auditor` host uses a fixed virtual clock; the prepared intent uses that
host's evaluation time, not the browser clock or Midnight epoch counter.

The issuer, verifier, and maintainer forms follow the same external-signature flow. An
issuer must name the exact credential family, schema and semantic version,
credential definition, status method, and the resource type it seeks to
govern. A verifier must name the complete request profile, purpose,
credential-scope commitment, allowed attributes and predicates, and disclosure
level. The portal derives role-specific governed resource IDs and includes the
whole scope, selected resource, registry context, and nonce in the signed
digest. A changed host binding is rejected before the page reports `pending`.
For a maintainer, the host registry ID is the scope and resource; it is not
editable in the form. The signer still owns the DID key outside the browser;
registering and presenting eligibility evidence does not activate membership.
For a loopback walkthrough, run
`node scripts/demo-auditor-admission.mjs serve 4400 issuer` or substitute
`verifier` or `maintainer`, then use its printed draft and the fixture-only `sign-digest` and
`vp <nonce> <role>` commands. The demo does not make an issuance or
presentation decision on the network.

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
