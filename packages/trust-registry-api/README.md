# Trust Registry API

HTTP query and governed-application surface for the local Midnight
trust-registry reference
implementation.

Current scope:

- serve registry, epoch, authorization, recognition, and evidence endpoints
  from a saved operator snapshot or mutable operator workspace
- expose TRQP-compatible authorization and recognition routes by reusing the
  existing adapter package
- expose governed applicant submission and maintainer action routes backed by
  the existing mutable operator workspace journal
- keep the first service slices file-backed and local-first instead of
  introducing a separate database or runtime persistence layer

Current route set:

- `GET /health`
- `GET /v1/registry`
- `GET /v1/registry/summary`
- `GET /v1/registry/mutation-context` (workspace source only; advisory signer preimage)
- `GET /v1/epochs/current`
- `GET /v1/epochs/resolve?at=<timestamp>`
- `GET /v1/epochs/:epochId`
- `GET /v1/authorizations/:role`
- `GET /v1/authorizations/:role/:authorizationId`
- `GET /v1/authorizations/:role/:authorizationId/evidence`
- `POST /v1/authorizations/evaluate`
- `POST /v1/authorizations/resolve`
- `GET /v1/recognitions`
- `GET /v1/recognitions/:recognitionId`
- `GET /v1/recognitions/:recognitionId/evidence`
- `POST /v1/recognitions/evaluate`
- `POST /v1/recognitions/resolve`
- `GET /v1/trqp/metadata/:authorityId`
- `POST /v1/trqp/authorizations/query`
- `POST /v1/trqp/authorizations/evidence`
- `POST /v1/trqp/recognitions/query`
- `POST /v1/trqp/recognitions/evidence`
- `POST /v1/applications`
- `POST /v1/applications/:target/:id/approve`
- `POST /v1/applications/:target/:id/activate`
- `POST /v1/applications/:target/:id/suspend`
- `POST /v1/applications/:target/:id/revoke`
- `POST /v1/applications/:target/:id/archive`
- `POST /v1/epochs/publish`

Authorization `:role` supports `issuer`, `verifier`, and `auditor`. Issuer
lookups require a canonical `tr:issuer-resource:v1:<sha256>` ID; verifier and
auditor lookups require a canonical `tr:request-resource:v1:<sha256>` ID
derived from the complete role-specific request scope. A bare request-profile
ID is rejected. The auditor role is not mapped to TRQP `issue` or `verify`.
Current and historical API responses include lifecycle status and evidence;
an archived response is not a current active trust decision.

TRQP evidence selects the matching epoch and a bundle for that
record from the current entry or the snapshot's `evidenceArchive`. The archive
must retain the prior bundle and epoch commitment before later lifecycle
changes; otherwise the query returns 424 rather than attaching a later proof
to an earlier decision. Snapshot parsing checks archive record identity,
uniqueness, and internal Merkle/epoch consistency. Consumers still need an
independently trusted epoch anchor and quorum verification before accepting
the exported bundle as cryptographic proof. Each workspace operation retains
the prior snapshot's displaced bundles and epochs; importing an external
snapshot still requires its producer to supply the archive explicitly.
Local snapshot/workspace JSON created before `evidenceArchive` was introduced
must be regenerated; the unreleased format has no legacy-field fallback.

Run locally against a saved workspace:

```bash
pnpm --filter @midnight-ntwrk/trust-registry-api run build
npx trust-registry-api serve --workspace ./tmp/operator-workspace.json --port 4400
```

The read-only mutation context returns the current registry ID, predecessor
epoch ID, and full workspace revision commitment. It is never cached. A signer
must still expect a stale-context rejection if the workspace changes before
the mutation is admitted.

`POST /v1/mutations` accepts `{ "intent": ..., "signature": ..., "operation": ... }`.
The intent signs the exact workspace operation, registry, actor DID/key, role,
scope commitment, nonce, workspace revision, epoch, and five-minute validity
window. The server requires an injected Midnight DID resolver, checks the
appropriate DID relationship (`authentication` for applicants,
`capabilityInvocation` for maintainers), and persists the consumed nonce in
the same workspace revision as the operation. The local workspace source uses
an exclusive lock file and atomic replacement for API writes. A crashed writer
leaves the lock in place and requires operator inspection before removal; it
does not silently break a lock. Invalid signatures return 401; unauthorized
or substituted actors/scopes return 403; replay, stale state, and lock
contention return 409. Failed requests do not append an operation or consume
a nonce.
Operator workspaces created before `consumedMutationNonces` existed must be
regenerated; this unreleased format has no compatibility default.

The packaged CLI does not yet configure a production DID resolver, so it
serves reads but returns 503 for signed writes. The integration harness
injects a ledger-backed DID resolver fixture and exercises the signed route.
This API is a local reference gateway, not a claim that its fixture replay
passes external maintainer signatures into a live Compact contract.

Legacy workspace-backed application and epoch routes are disabled by default.
For the deliberately unsigned local UI smoke demo only, start with
`--unsafe-demo-mutations`; never expose that mode on a public listener.
Those demo routes:

- require `--workspace`, not `--snapshot`
- reuse the CLI workspace replay model instead of maintaining separate server
  state
- currently support issuer, verifier, auditor, and recognition workflows plus registry
  epoch publication
- bypass actor authorization and are unsuitable for real membership decisions
- serialize in-process requests and reject cross-process lock contention
- return permissive local CORS headers plus `OPTIONS` preflight responses so the
  admin console can call the same loopback API from a separate port

The exported application-challenge service and
`consumeChallengeAndSubmitApplication` reference intake are not HTTP routes.
Their binding requires the versioned role-specific scope object, a separately
checked governed resource, and a matching canonical scope commitment; an
arbitrary 32-byte scope digest is not accepted. The caller must supply a
policy-authorized VP verifier, evidence signer, authorized verifier keys,
and a trusted proposal binding. It parses the verifier-produced envelope
before consuming the challenge; after atomic consumption, signing or proposal
failure does not make the challenge reusable. A different live binding for the
same registry/application is rejected rather than evicting the prior challenge.
Public issuance still requires applicant authentication and rate limits even
for same-binding retries.
The VP verifier must derive the nonce and subject DID from the verified proof,
not echo the expected callback arguments. The reference tests use a fixture
verifier, not a production VC/VP verifier. Static policy configuration and the
nonce/hash pair are checked before VP work; only the store's atomic consume
decides whether a challenge is spent. The process-local store uses the same
injected clock for timer reclamation and consume, copies records on insertion,
and reports whether issuing a new challenge superseded a live one for that
application. Capacity, invalid-clock, expiry-range, and collision failures
have stable `code` and `name` fields. A production route still needs an
authenticated per-applicant quota, durable atomic storage, request limits,
and VP verification timeouts before public exposure.
The existing `POST /v1/applications` route is a local operator workspace route,
not a public VC/VP-verified membership endpoint.

Run the reference challenge-to-Compact proposal scenarios without adding
their simulator cost to the light gate:

```bash
pnpm --filter @midnight-ntwrk/trust-registry-api integration
```

Example applicant submission:

```bash
curl -sS http://127.0.0.1:4400/v1/applications \
  -H 'content-type: application/json' \
  -d '{"target":"issuer","label":"degree"}'
```

Example maintainer approval:

```bash
curl -sS -X POST \
  http://127.0.0.1:4400/v1/applications/issuer/<authorization-id>/approve
```

Example timestamp-based authorization evaluation:

```bash
curl -sS http://127.0.0.1:4400/v1/authorizations/evaluate \
  -H 'content-type: application/json' \
  -d '{
    "role":"issuer",
    "subjectDid":"did:midnight:testnet:issuer",
    "resourceId":"tr:issuer-resource:v1:0000000000000000000000000000000000000000000000000000000000000000",
    "at":"2026-05-20T00:30:00Z"
}'
```

The resource ID above illustrates the required syntax, not a real grant.
Relying parties must derive the ID from the authenticated scope preimage and
check the returned registry, policy, epoch, lifecycle, and evidence before
accepting the decision.
