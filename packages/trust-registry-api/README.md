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

Snapshot and operator-workspace modes are fixture-backed and loopback-only,
including read-only listeners. They are not a substitute for a finalized local
ledger. The signed local-ledger mode is the only CLI mode that can request
cluster binding; that capability alone does not qualify a release deployment.

`assertLocalLedgerEvidenceMatchesSnapshot` is a building block for the
separate local-ledger mode tracked in #219. Given a caller-authenticated
finalized Compact ledger, contract address, and sequence-to-time mapping, it
checks that candidate issuer, verifier, auditor, recognition, and epoch maps
are complete, compares represented record fields, and verifies each included
evidence bundle against its Compact epoch and publication signer. It does not
authenticate the checkpoint or prove that off-chain metadata, request-scope
preimages, DID/VC status authority, or a historical archive is complete. The
CLI now has a separate guarded, read-only local-ledger mode, but simulator
tests are not deployment evidence and this mode is not yet release-qualified.

`createLocalLedgerBoundSource` can be injected into the HTTP server for
read-only queries. It requires a pinned local-deployment address, a reader that
authenticates each finalized checkpoint against an independently approved
genesis, an independently approved SHA-256 digest of the exact snapshot file
(covering snapshot-only metadata), and a trusted mapping from Compact governance
sequences to timestamps.
It re-reads and verifies the entire candidate snapshot for each request and
fails closed if the view is missing or mismatched, or the file differs from its
approved digest or the finalized Compact projection. The CLI constructs these
inputs from a reviewer-signed runtime plan and the local checkpoint/indexer
reader. Current-map coverage does not prove that a historical evidence archive
contains every transition. In local-ledger mode, historical authorization and
recognition evaluation plus TRQP decision/evidence routes return 501 with
`historical-decisions-out-of-scope`. They are deferred from the local-only
0.1.0 profile, not temporarily unavailable current decisions. Fixture modes retain
their development behavior. This source still has only simulator and
test-double coverage, not
proof of a real local-ledger deployment, finalized readback, offline actor
journey, or 0.1.0 release qualification.
An embedded local-ledger server refuses demo mutations and unjournaled governed
proposal ports. Proposal ports require a configured one-attempt journal,
admission source, and finalized proposal observation; the operator must supply
a durable journal and independently authenticated reader. Presence checks alone
are not qualification. Other governed action ports remain disabled until they
have an equivalent durable submission path.

For local-ledger mode, a reviewer must detach-sign a `tr-local-api-runtime-v2`
JSON plan. Write it as compact JSON with an optional final newline, or as
two-space-indented JSON with a final newline. Duplicate keys, alternative
escaping, and other noncanonical encodings are rejected even if signed. The
operator supplies the exact plan, detached signature, a private
public-key keyring, and the out-of-band approved signing-key fingerprint:

```sh
trust-registry-api serve \
  --local-ledger-plan /run/trust-registry/api-plan.json \
  --local-ledger-signature /run/trust-registry/api-plan.sig \
  --local-ledger-keyring /run/trust-registry/reviewer-keyring \
  --local-ledger-reviewer '<approved-40-character-GPG-primary-fingerprint>' \
  --serve-portals \
  --host 127.0.0.1 --port 4400
```

The plan pins `undeployed`, the source revision, absolute install-inventory,
release-manifest and snapshot paths plus their SHA-256 digests, nonzero approved
genesis and contract hashes, exact local RPC/indexer endpoints and allowed
hosts, the exact release-manifest verifier-key catalog, the ordered maintenance
committee public keys, threshold and decimal counter, a contiguous
governance-sequence-to-UTC-timestamp map covering the finalized governance
count, and a validity window no longer than 90 days. The v1 plan no longer
authorizes local API startup, and v3 install inventories without an API image
pin are unsupported in all local-ledger API modes. The
plan and signature must be regular files owned by root or the runtime user, and the
reviewer keyring must be a private directory with its approved public key in
`pubring.kbx`. The CLI verifies private copies of the exact plan bytes it
parses and copies the read-only public keyring into private GPG scratch space;
the pinned fingerprint is the approved primary signing-key fingerprint. A
signature made by its signing subkey is accepted only when GnuPG reports that
same primary fingerprint and the reported signer key ID or fingerprint matches
the signing key. Any valid signing subkey of that primary can approve
the plan; an earlier configuration pinned to one signing subkey must be
re-approved with the primary fingerprint before upgrading. This profile
requires a version-4 40-character fingerprint, a detached binary-document signature,
and SHA-256, SHA-384, or SHA-512 as its signature hash. It checks the install
bytes, constructs the pinned local reader,
and requires a successful finalized Compact readback and snapshot match before
listening. Every query rechecks the snapshot digest, finalized projection,
verifier-key bytes, and maintenance authority in the same finalized contract
read; a key or committee change requires a new manually reviewed signed plan.
missing sequence timestamps or an expired plan fail closed. Ledger read and
projection failures return a generic 503 without exposing provider or file details.
After any failed finalized read, including a transient provider outage, the
process stays unavailable until an operator-controlled restart. Restoring old
snapshot bytes or replaying an older view cannot silently make that process
healthy again. A restart must use a newly reviewed plan if finalized state
changed; this in-process latch is not durable rollback protection across restarts.
Any governed mutation changes the finalized action count, so the current
signed plan and snapshot become stale until an independently reviewed
replacement is signed and installed. `/health` fails closed during that gap;
the local Helm readiness probe uses this endpoint. This manual rotation has
not been exercised as a live local-ledger actor journey.
For each governed mutation, stop or drain query traffic, wait for an independently
authenticated finalized checkpoint, prepare a new snapshot and complete ordered
sequence timestamp map, and have the reviewer inspect the exact source, install,
genesis, contract, checkpoint, snapshot digest, verifier keys, maintenance
authority, map and validity window before
detached-signing a new canonical plan. Install the new snapshot, plan and signature
as one immutable versioned set; change the service's paths to that set and restart
the API. Before switching traffic, run `trust-registry-api check-local-ledger-plan`
with the same four `--local-ledger-*` arguments shown above. It checks the
detached signature, source/install pins, current finalized ledger view, and
snapshot without opening a listener; it does not check the running image,
authenticate finality independently, or qualify the release. Do not overwrite
a running plan or snapshot in place. Startup must pass
signature, pin and finalized-readback checks, then `/health` and current actor
queries must pass before restoring traffic. If any check fails, leave the API
unavailable and reconcile the finalized ledger; never roll back to a plan whose
governance count is stale or restart in fixture mode. Preserve both signed versions
for audit. This is an operator procedure, not an automated signer or live test.
For a read-only proposal spot-check after that rotation, run
`trust-registry-api observe-local-proposal` with the same four signed-plan
arguments plus `--role issuer` (or another governed role) and the exact
`--authorization-id`. It reads the pinned current finalized source without a
listener and prints the event/evidence commitments after checking the proposal
signature and ledger-record consistency. `present-and-verified` does not mean
the record matches the private submission journal. `not-observed`
is not proof of failure and never permits retry; compare the result with the
private journal under the recovery procedure. Its report sets
`releaseQualified: false` and does not advance the journal.
Before the first submission, run `trust-registry-api init-local-proposal-journal`
with the four signed-plan arguments and an absolute `--submission-journal`
path. It binds an empty private journal to the reviewed genesis, registry ID,
and contract address. A nonempty unbound journal cannot be retroactively bound.
Back up the journal, its `.binding` sidecar, and any referenced segments as
one private unit. After a post-mutation signed plan has passed its preflight,
use `trust-registry-api reconcile-local-proposal` with
the same signed-plan arguments, exact `--role` and `--authorization-id`, and
an absolute `--submission-journal` path. It marks an entry `observed` only
when the verified ledger record matches the journal's evidence commitment
and any recorded event hash. A different deployment binding fails closed
before readback. Output distinguishes `observed` from `not-observed`; absence
leaves the attempt pending and never permits a retry.
Even an `observed` entry does not prove transaction identity after a lost
response, independently authenticate finality, or qualify the release.
For a read-only current-route check against a running loopback listener, run
`trust-registry-api observe-local-ledger-api` with the same four signed-plan
arguments and `--api-origin http://127.0.0.1:4400`. It compares registry,
current epoch, all bounded issuer/verifier/auditor/recognition records,
not-found behavior, and historical-route rejection with the signed source.
Its JSON report has `releaseQualified: false`: it does not attest the API
process or image, independently authenticate finality, perform actor mutations,
or prove browser, DID/VC/status, egress-denied, or recovery behavior.
All local-ledger HTTP responses use `Cache-Control: no-store` so intermediaries
and browsers are not instructed to reuse stale authorization decisions.
With `--serve-portals`, the API serves packaged admin and applicant assets at
`/admin/` and `/applicant/` on its own origin. Startup fails if either portal's
HTML or JavaScript entry point is absent. In these paths the portals ignore
stored or query-selected API URLs and use their current origin, so the
applicant's private-evidence requests do not require cross-origin access.
Do not put an ingress that routes those paths to a different image in front of
this mode; TLS, authenticated exposure, and offline browser journeys still
require deployment validation. Without the flag, the API does not serve portals.
File-backed snapshot/workspace mode
cannot be combined with local-ledger mode, and demo mutations are forbidden.
By default local-ledger mode binds only to loopback. Guarded `--cluster-bind` can
expose the signed mode on all interfaces with an API image source-revision check,
but does not by itself satisfy local deployment or offline-runtime gates.

The signed map is a reviewer attestation, not proof that timestamps were
derived from authenticated ledger history. The plan's `sourceRevision` is not
yet bound to a reviewed running API image, and a signed plan cannot currently
be revoked before expiry. The local indexer's contract state is not yet
verified against the authenticated checkpoint state root. No live local deployment, signer
journey, DID/VC/status authority, egress-denied browser flow, or restart/restore
test has been completed through this CLI. Do not expose it as the 0.1.0 RC API
until those independent gates and the first-run approval workflow are complete.

Current route set:

In local-ledger mode, only `GET /v1/epochs/current` is available for epoch
queries. `GET /v1/epochs/resolve` and `GET /v1/epochs/:epochId` return 501
because the current-map projection does not prove a complete historical epoch
archive. Fixture-backed modes retain those historical routes.
Current authorization and recognition resolution in local-ledger mode selects
only IDs from the verified finalized current-scope indexes, not the most recent
snapshot timestamp. A broad query matching multiple current scopes returns 409;
an unavailable current-index read returns 503. The local HTTP observation also
checks the signed snapshot generation time, registry summary, and current
resolution against the finalized selection. Its counts include all by-ID
records, not only current IDs; it remains readback only, not deployment or
actor-journey qualification.

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
- `POST /v1/recognition-evidence/:recognitionId/challenges` (private accredited-recognition challenge; optional trusted port)
- `POST /v1/recognition-evidence/:recognitionId/submissions` (private signed VC/VP plus authority assertion verification; optional trusted port)
- `POST /v1/governed/recognition/:recognitionId/proposal/prepare` (private-receipt-gated Compact context; optional trusted port)
- `POST /v1/governed/recognition/:recognitionId/proposal/submit` (receipt-gated, externally signed recognition proposal; optional trusted port)
- `POST /v1/pending-applications` (signed pending registration; optional trusted port)
- `GET /v1/epochs/current`
- `GET /v1/epochs/resolve?at=<timestamp>`
- `GET /v1/epochs/:epochId`
- `GET /v1/authorizations/:role`
- `GET /v1/authorizations/:role/:authorizationId`
- `GET /v1/authorizations/:role/:authorizationId/evidence`
- `POST /v1/authorizations/evaluate`
- `POST /v1/authorizations/evaluate/evidence`
- `POST /v1/authorizations/resolve`
- `GET /v1/recognitions`
- `GET /v1/recognitions/:recognitionId`
- `GET /v1/recognitions/:recognitionId/evidence`
- `POST /v1/recognitions/evaluate`
- `POST /v1/recognitions/evaluate/evidence`
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

For governed evidence-verifier registration and rotation, a host may wrap its
Compact-backed policy port with `createDidBoundEvidenceVerifierPolicyPort`.
The wrapper checks the candidate Midnight DID assertion method, key and DID
commitments, and exact Compact action payload at prepare and again before
execution. Candidate readers must use trusted current registry state, and the
resolver must read independently finalized DID state. The host must serialize
the final authority check with execution; this wrapper does not itself prove
public-network finality or supply a production authority source. DID resolution
outage returns 503; a mismatched or retired method rejects the action.

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
Workspace format 3 stores each consumed signed-mutation nonce identity as a
SHA-256 key with a hashed actor identity and the signed intent's expiry.
Entries remain replay-protected
until that expiry (at most five minutes after issue) and are pruned during the
next successful exclusive mutation. Lookup is keyed, not a scan. A single
actor may retain at most 512 live nonces; that actor receives
`429 mutation-actor-nonce-capacity` without blocking other actors. At 10,000
simultaneously live nonces across actors the API returns
`503 mutation-nonce-capacity` rather than evicting a valid replay marker.
These are local reference-gateway limits, not ledger or network throughput
claims. Workspace formats 1 and 2 are unsupported pre-release snapshots and
must be recreated from trusted source data; there is no compatibility default
or silent migration.
The persisted nonce clock records the latest successful signed mutation. If
the host clock moves backward, the gateway returns
`503 mutation-nonce-clock-rollback` without consuming an intent. Operators
must correct the clock and confirm it has reached the recorded timestamp;
never delete nonce history or lower the recorded clock to resume writes.
`node scripts/bench-mutation-nonce-lookups.mjs` measures the in-memory lookup
shape at 10,000 entries. On Node 24.14.0/darwin-arm64, 5,000 last-key lookups
took 0.17 ms keyed versus 647.2 ms with the former array scan. This is an
illustrative microbenchmark, not end-to-end write latency: loading, validation,
and expiry pruning still process the bounded window.

The packaged CLI does not yet configure a production DID resolver, so it
serves reads but returns 503 for signed writes. The integration harness
injects a ledger-backed DID resolver fixture and exercises the signed route.
This API is a local reference gateway, not a claim that its fixture replay
passes external maintainer signatures into a live Compact contract.

The separate governed-action route accepts `issuer`, `verifier`, `auditor`,
`maintainer`, and `recognition` targets with `approve`, `activate`, `suspend`,
`revoke`, and `archive` actions
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
Archiving a proposed target is a quorum-signed denial. The archived record
remains in history and has neither an approval nor an activation timestamp.
The authorization and recognition evidence routes may return that archived
record for audit, but a relying party must reject it as a current active
grant. Timestamped evaluation reports `trustedAtTime: false` for both its
proposed and archived states.
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
For audit tooling, `resolveCompactProposalEvidenceSnapshot` joins a proposal
record to its registered verifier key in an independently finalized ledger
view. It exposes the DID/key and policy snapshot for all five proposal roles;
it also rejects a finalized view whose authorization record has a different
evidence commitment and includes the subject and grant-policy commitments.
The role-specific signed payload is reconstructed and its registered JubJub
signature must verify. This is not a standalone finality or inclusion proof.
The check uses the retained key record, so later key retirement does not
invalidate an otherwise valid historical proposal signature.
An embedding host may
inject `readFinalizedProposalLedger` to expose the same projection at
`GET /v1/governed/:role/:id/proposal/evidence`; without that reader the route
returns 503. A missing record in the supplied finalized view returns 404,
not proof that an in-flight proposal failed.
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

An embedding host may inject `proposalSubmissionJournal` alongside
`proposalAdmission` for issuer, verifier, auditor, and maintainer proposals,
or alongside the matching accreditation admission store for recognition.
The private file adapter reserves the role, authorization ID, and accepted
evidence commitment before calling the Compact-backed port. A journaled
recognition port must also supply a side-effect-free `preflightSubmission`
that rejects known-invalid current-ledger signatures and quorum before
reservation. It must recheck at execution; preflight is not finality.
Before reservation the API verifies that every supplied maintainer signature
signs the current prepared action digest and rejects duplicate key IDs.
This preflight cannot establish active maintainer membership, quorum, or the
registered evidence-verifier key; Compact remains authoritative for those
rules. A later rejection remains an uncertain submission and needs recovery.
Duplicate attempts return 409 `proposal-submission-uncertain`, including
after process restart. A returned event hash means `submitted`, not finalized.
Any failure after the reservation returns 503 `proposal-submission-uncertain`,
even if the underlying Compact port reported a validation error; the HTTP
response cannot establish that no submission occurred.
`/proposal/resolve` can mark an attempt `observed` only after the host's
role-specific resolution port supplies a matching finalized record. A
`not-observed` response is not permission to submit again. A thrown Compact
or network error remains reserved even if it looks like a validation error:
the journal cannot prove whether the call crossed the submission boundary.
An operator must reconcile or establish definitive non-submission before
recovering that attempt. The adapter is single-host/shared-filesystem only;
the packaged CLI does not configure it or a network-finality reader. It
stores neither raw VC/VP nor maintainer or verifier signatures. See
`docs/plans/governed-proposal-submission-handoff.md` for the state model and
remaining production requirements.
The local adapter has an explicit 10,000-attempt capacity. At capacity it
returns 503 `proposal-submission-capacity` before calling the Compact port;
operators must preserve and reconcile the journal before a controlled
rotation. The same pre-submission check reserves room for a future event hash
under the 4 MiB file limit. It never silently evicts unresolved attempts.

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
An archived Compact proposal does not automatically clear its private
registration reservation. The embedding host must call `recordArchived` with
an observation matching the original application ID, authorization ID,
registry, applicant DID, role, scope commitment, and governed resource. Its
verifier callback must independently authenticate the archived Compact event
and finality and return its authenticated lifecycle event hash. The transition
requires that hash to match the observation. There is no public HTTP route for this
transition. The original application and nonce remain recorded, its pending
VP binding is no longer served, and a new application **and** authorization ID
may then reuse the scope. A missing or failed verifier leaves the reservation
pending and fails closed.
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
application. Its `recordArchived` transition persists the same host-verified
terminal observation under the file lock; it does not infer archival from an
HTTP request or from a mutable workspace flag. It does not store raw VPs. The joined issuer/verifier/auditor/maintainer demos combine it with
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

The DID-only primitive is not public intake: it proves key control and replay
resistance, not accreditation. An opt-in `recognitionAccreditation` server port
adds private HTTP challenge/submission routes. The host must authenticate each
request and provide the current policy record, Compact policy commitment, DID
resolver, and status source from trusted server-side state. Neither the anchor
nor status decision can be supplied by the HTTP caller. Failed proof or stale
policy leaves the challenge usable; a successful submission returns only a
redacted evidence commitment and expiry. This reference route has no durable
acceptance receipt unless the host configures the optional file recognition
admission store. With that store, the authenticated private accepted endpoint
can recover the redacted receipt after a lost response. The challenge and
receipt share one file transaction; the host must pass the exact governance
workspace path used by all policy writes so the final recheck holds its write
lock. This is not a proposal-admission transaction. The service rereads
trusted governance after asynchronous proof verification and before nonce
consumption, and binds the current policy commitment into the evidence hash;
the later ledger write must still revalidate policy atomically. The optional
`governedRecognitionProposals` port now exposes prepare/submit with only
`receiptId` and `evidenceCommitment` as evidence inputs. The server obtains
the exact binding under the governance lock and current policy from its trusted
port, checks the receipt
and governed anchor under the same workspace writer lock, and retains that
lock while the port rechecks the Compact context and executes the signed
proposal. Submit additionally requires the exact prepared context, external
maintainer signatures, and a separate evidence-verifier signature. If intake
and proposal ports coexist, they must share one admission store or server
startup fails. The simulator integration rejects absent/substituted receipts,
wrong evidence, one-of-two quorum, wrong evidence-verifier key, and stale
sequence before accepting a valid proposal. The port MUST use the same lock
path as policy writes and MUST perform current ledger record, quorum, key,
and sequence checks without reacquiring the lock. No resolve/finality route
is exposed for recognition proposals yet. Both routes are disabled in the
CLI and must not be exposed as production public intake. The local
workspace-backed signed and unsafe recognition submit routes reject creation
when the governed recognition port is installed, so they cannot bypass its
admission check. Direct CLI fixture mutation is a separate local-only path
and must not be exposed alongside an accredited production host. The local
signed-status fixture authenticates an authority statement, not live
status-registry state. Production intake still needs live status evidence,
durable distributed admission, and network-finality reconciliation after a
ledger transition. The joined governed demo exercises issue,
invalid assertion rejection, valid consumption, replay rejection, and the
resulting Compact proposal.

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
