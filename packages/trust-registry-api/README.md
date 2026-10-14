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
- `GET /v1/governed/:role/:targetId/actions/:action` (Compact signer context; optional port)
- `POST /v1/governed/:role/:targetId/actions/:action` (external signatures; optional port)
- `POST /v1/application-evidence/:applicationId/challenges` (VP challenge; optional trusted port)
- `POST /v1/application-evidence/:applicationId/submissions` (verified VP intake; optional trusted port)
- `GET /v1/application-evidence/:applicationId/binding` (applicant-authorized pending binding; optional trusted port)
- `GET /v1/application-evidence/:applicationId/receipt` (applicant-authorized accepted redacted evidence and receipt recovery; optional trusted port)
- `POST /v1/pending-applications` (signed pending registration; optional trusted port)
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
- `POST /v1/governed/policy/thresholds/prepare` and `/submit` (optional Compact-backed port)
- `POST /v1/governed/policy/evidence-verifier/prepare` and `/submit` (optional Compact-backed port)

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
The signed HTTP test holds the real workspace lock in a separate Node process,
asserts the `workspace-locked` problem, then retries after release. This is a
same-host, shared-filesystem exclusion guarantee only: it is not a distributed
lock or crash-durable transaction protocol. Operators must inspect stale locks
before removal.
Operator workspaces created before `consumedMutationNonces` existed must be
regenerated; this unreleased format has no compatibility default.

The packaged CLI does not yet configure a production DID resolver, so it
serves reads but returns 503 for signed writes. The integration harness
injects a ledger-backed DID resolver fixture and exercises the signed route.
This API is a local reference gateway, not a claim that its fixture replay
passes external maintainer signatures into a live Compact contract.

The separate governed-action route accepts `issuer`, `verifier`, `auditor`,
`maintainer`, and `recognition` targets with `approve` and `activate` actions
only when the server is constructed with `governedMembershipActions`. Without the port it
returns 503 and never falls back to workspace replay. `GET` returns the
current registry, authorization, policy, action, sequence, predecessor event,
and evidence commitments for off-server signing. `POST` accepts
`{ "prepared": <exact GET response>, "signers": [{ "keyId": "0x...",
"publicKey": { "x": "...", "y": "..." }, "signature": "0x..." }] }`.
Each signature must be canonical JubJub Schnorr over the policy-bound action
digest. The injected port must submit the supplied signatures to Compact,
which rechecks current state, active maintainer membership, and quorum;
the API does not sign for maintainers. For `maintainer`, the path's
`authorizationId` is the candidate's maintainer membership ID, and the
candidate cannot count toward the existing-maintainer approval quorum.
For `recognition`, the path's `authorizationId` is the recognition ID; an
active recognition is not a local issuer, verifier, auditor, or maintainer
authorization. The recognition port must preserve the recognized authority,
external registry, and exact scope bound by the prepared Compact digest.
A stale context returns 409, invalid
signer bundle 403, malformed signature 400, and accepted transition 202 with
the Compact event hash. A 202 is not network finality; a network-backed port
and asynchronous query projection remain future work. The packaged CLI does
not configure this optional port. The reference integration test injects the
local simulator and projects that *same* simulator into the read API after
each transition.

Threshold revision is a two-action workflow. Prepare with
`{ "thresholds": { "default": "3", "emergency": "2", "archival": "2" } }`;
submit the exact prepared context, the same thresholds, and external signer
entries. The old policy and sequence govern this signature. After acceptance,
prepare and submit evidence-verifier registration with a new signature set
under the new policy and next sequence. The server recomputes each context;
stale contexts return 409, malformed requests 400, rejected Compact quorum
403, and missing `governedPolicyActions` port 503. The first 202 is not enough
to accept new application evidence, and neither 202 proves network finality or
an atomic two-action transaction. The packaged CLI does not inject this port.

The governed issuer proposal route is `POST /v1/governed/issuer/:id/proposal/prepare`
with `{ "evidence": <signed application evidence> }`, followed by
`POST /v1/governed/issuer/:id/proposal/submit` with the same evidence, the
exact prepared response, external maintainer `signers`, and an
`evidenceVerifierSignature`. It is available only when the embedding server
injects `governedIssuerProposals`; the packaged CLI returns 503. The port
must recheck the already verified, one-use-challenge evidence and current
Compact context. Compact verifies the registered evidence-verifier key and
maintainer quorum for the proposal digest. Raw VC/VP payloads are not accepted
by this API, and a 202 is simulator acceptance, not network finality.
An embedding host may also provide a ledger-backed `resolve` method for
`POST /v1/governed/:role/:id/proposal/resolve` with the same accepted
`{ "evidence": ... }`. The API returns `observed` with the proposal event
hash only when the ledger record's evidence commitment matches the admitted
application. `not-observed` is not proof that a submitted transaction failed;
clients must not automatically submit it again. The route returns 503 when
the host has no role-specific resolution port. This read-only recovery path does not make
the private admission file and ledger transactional or establish network
finality.
Verifier, auditor, and maintainer proposals use the same prepare/submit pattern at
`/v1/governed/:role/:id/proposal/{prepare,submit}` with independently
injected `governedVerifierProposals`, `governedAuditorProposals`, and
`governedMaintainerProposals` ports. For maintainers, `:id` is the candidate
membership ID; the prepared context binds the registry-scoped maintainer
application and candidate key to the evidence verifier's current key.
Each role's prepared digest additionally
binds the registered evidence-verifier identity and active policy version;
the contract verifies that key's role-separated proposal signature and the
maintainer quorum. The packaged CLI does not inject any proposal port, so
all four routes return 503 without a Compact-backed host.
The integration journey verifies a published fixture VC/VP, consumes one
challenge, submits the resulting redacted evidence through this HTTP proposal
route, and then approves and activates the issuer with external 2-of-3 votes.

Legacy workspace-backed application and epoch routes are disabled by default.
For the deliberately unsigned local UI smoke demo only, start with
`--unsafe-demo-mutations`; the CLI accepts that mode only on literal loopback
listeners (`127.0.0.1` or `::1`) and never on a public listener.
Those demo routes:

- require `--workspace`, not `--snapshot`
- reuse the CLI workspace replay model instead of maintaining separate server
  state
- currently support issuer, verifier, auditor, and recognition workflows plus registry
  epoch publication
- bypass actor authorization and are unsuitable for real membership decisions
- serialize in-process requests and reject cross-process lock contention
- return permissive local CORS headers plus `OPTIONS` preflight responses for
  local operator routes so the admin console can use a separate port; private
  application VP routes do not return wildcard CORS headers

The application-evidence HTTP routes require an injected `applicationVp` port;
without one, both return 503. Its required `authorizeRequest(applicationId,
request)` callback must authenticate the caller and authorize access to the
current application, throwing on denial. It runs on both routes before the
request body is read or any challenge or VP work begins. Denials return a
generic 403 without exposing callback errors. Reverse-proxy authentication
alone is not an API authorization seam; the port must still bind the
authenticated principal to the application and enforce CSRF protection where
cookie credentials are used. Host the applicant frontend and these routes on
the same origin or provide a narrowly configured authenticated reverse proxy;
the reference server does not grant cross-origin browser access to raw VPs.
Challenge issuance accepts only `{}`. Submission
accepts exactly `{ "nonce": "0x...", "challengeHash": "0x...", "presentation": <VP> }`.
The server never accepts a caller-supplied binding, policy, verifier list, or
evaluated timestamp. The trusted port must resolve the current pending
application and authorized verifier policy at issuance and submission, derive
the subject DID, nonce, and scope from a genuine verified VP, sign canonical
redacted evidence, and atomically persist only that evidence. The server
re-resolves the binding and verifier policy just before persistence. Policy
rotations must update the binding's policy version so challenges issued under
old policy cannot be reused; the port must also recheck pending status and
policy atomically at persistence. A 202 response contains only signed evidence
and a validated redacted receipt, not the VP or its claims. Errors from VP
verification and storage are intentionally generic and do not echo exception
messages or raw request data. Challenges are one-use and expire after five
minutes according to the injected server clock; signing or persistence failure
after consumption does not make a challenge reusable. The optional port owns
the challenge store, which must provide durable atomic consumption in a
multi-process deployment. No fixture verifier is installed by default.

If the same server configures both `applicationVp` and any governed membership
proposal port, it must also configure `proposalAdmission`; startup fails
without it. The port resolves the original signed pending record separately
from committed VP evidence by the same application ID. Both proposal
`prepare` and `submit` reject unless the signed record's requested target,
role, original binding, exact redacted signed evidence, and validated receipt
match. This prevents a
combined host from submitting a proposal that bypassed its VP intake. A
proposal-only host may instead rely on its own trusted external evidence
pipeline, but its Compact-backed proposal port must still verify all governed
evidence and signer requirements. The accepted-record lookup is an off-ledger
join, not an assertion that the applicant is already a member.

`FileApplicationChallengeStore` is a local reference adapter for the port. It
stores only challenge, binding, and application hashes with issuance/expiry
instants in a versioned private (`0600`) file. A shared cross-process lock
serializes replacement and one-use consumption; a second instance can read and
consume the same challenge, but cannot consume it twice. It fails closed on
malformed or insecurely permissioned files, bounds capacity, and leaves stale
locks for operator recovery. Atomic rename does not guarantee crash-durable
writes, and this adapter does not provide distributed transactions, VP
verification, applicant authentication, rate limits, or atomic pending-state
persistence. The packaged API CLI still leaves `applicationVp` unconfigured.

The optional `POST /v1/pending-applications` accepts an externally signed
Midnight DID `apply` intent for an issuer, verifier, auditor, or maintainer,
with the exact canonical role scope, governed resource, application ID, and
requested authorization ID
bound into its payload commitment. The host-owned registration port verifies
the applicant signature and current workspace context and returns a pending,
policy-scoped binding. This is not a governed Compact proposal or active
membership. The exported `InMemoryPendingApplicationRegistrationPort` serializes registrations within one
process for local tests only; it does not provide durable atomic persistence,
live policy updates, or proof that the configured evidence-verifier DID is
currently authorized. The packaged CLI does not install this port and returns
503. `GET /v1/application-evidence/:applicationId/binding` requires the VP
port's applicant authorization callback and returns the current server-owned
binding with `Cache-Control: no-store`. Neither route advertises cross-origin
browser access, including error and preflight responses.
The optional `nonApiGetHandler` composes static assets on the same origin
without intercepting `/v1` API routes. The loopback-only
`scripts/demo-auditor-admission.mjs` host uses it for a fixture applicant
journey; it is not installed by the packaged API CLI. The host also supplies
`authorizePendingApplicationRegistration` so its deterministic signed fixture cannot
be submitted without the same loopback session and Origin checks as the VP routes.

`FileApplicationAdmissionStore` is a private local adapter for signed pending
registration, consumed application nonces, accepted redacted evidence, and
receipt lookup. It uses a cross-process lock, validated versioned state,
`0600` file permissions, atomic replacement, and file/directory sync; separate
instances can reopen the same state and replayed registration or evidence is
rejected. Its workspace callback must return the current simulator-derived
policy and epoch, and the store rechecks that view before committing a signed
application. It does not store raw VPs. The joined issuer/verifier/auditor/maintainer demos combine it with
`FileApplicationChallengeStore` and a 2-of-3 Compact simulator. These two files
and the Compact ledger are not one atomic transaction; stale locks require
operator recovery, and the adapter is not configured in the packaged CLI.

The exported application-challenge service and
`consumeChallengeAndSubmitApplication` remain the implementation behind these optional routes.
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
have stable `code` and `name` fields. Before public exposure, the embedding
gateway must implement the port's applicant authorization callback, enforce per-applicant challenge quotas
and VP verification timeouts, and provide a durable challenge store and atomic
pending-application persistence.
The existing `POST /v1/applications` route is a local operator workspace route,
not a public VC/VP-verified membership endpoint.

Run the reference challenge-to-Compact proposal scenarios without adding
their simulator cost to the light gate:

```bash
pnpm --filter @midnight-ntwrk/trust-registry-api integration
```

The focused published-VC fixture test now continues one consumed challenge
through externally signed 2-of-3 Compact proposal, then HTTP approval and
activation with externally supplied signatures. It projects that **same
simulator** into the API snapshot model, resolves the active grant over HTTP,
rejects a wrong-scope lookup, and independently checks the HTTP evidence
bundle against the simulator. The test uses a trusted test credential-family
adapter and local DID fixtures, not a production status verifier or
authenticated HTTP VP intake. Run just this journey with:

```bash
pnpm --filter @midnight-ntwrk/trust-registry-integration build
pnpm --filter @midnight-ntwrk/trust-registry-cli build
pnpm --filter @midnight-ntwrk/trust-registry-api exec vitest run src/integration-test/published-vp-simulator-proposal.integration.test.ts --testTimeout 120000
```

The governed-action HTTP integration test covers externally signed 2-of-3
approval and activation, stale and malformed requests, cross-role identifier
substitution, and independently verified issuer, verifier, and auditor
evidence on one simulator. It is a reference journey; the VP intake above is
only mounted when a trusted host injects the full authenticated port. The
packaged CLI does not mount it, and this journey does not use an arbitrary VP
submitted to that endpoint.

### Recognition authority challenge primitive

`RecognitionAuthorityChallengeService` issues a five-minute challenge bound to
the target registry, recognition ID, Midnight authority DID, external registry,
and exact resource scope. It reuses the API's atomic challenge-store interface,
verifies the authority's current DID assertion key and signed tuple, rejects
statements outside the challenge window, and consumes the nonce once. A failed
signature or tuple check does not consume it. The process-local store is a
reference adapter; a multi-process host needs durable atomic storage.

This library primitive is **not mounted as public HTTP intake**. It proves DID
key control and replay resistance only. The accreditation commitment in the
statement remains an unverified reference; public recognition intake must also
validate an independently trusted accreditation source and governed local
evidence-verifier policy before proposing a ledger transition.
The joined governed demo exercises issue, invalid assertion rejection, valid
consumption, replay rejection, and the resulting Compact proposal.

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
