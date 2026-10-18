# Demo And Release Guide

Updated: 2026-10-13

This guide is the public operator walkthrough for the local demo path, package
artifact boundaries, and the manual release automation currently checked into
`midnight-trust-registry`.

## Demo Workflow

Prepare a mutable operator workspace:

```bash
pnpm run demo:prepare
```

Prepare a deterministic read-only snapshot for fixture-driven demos:

```bash
pnpm run demo:prepare:snapshot
```

Start the local surfaces in separate terminals:

```bash
pnpm run demo:serve:api
pnpm run demo:serve:admin-console
pnpm run demo:serve:applicant-portal
```

Default local endpoints:

- API: `http://127.0.0.1:4400`
- Admin console: `http://127.0.0.1:4173`
- Applicant portal: `http://127.0.0.1:4175`

The documented demo lane is smoke-tested with:

```bash
pnpm run demo:smoke
```

That command:

- builds the CLI, API, and local UI packages
- seeds a workspace and a deterministic snapshot
- starts the API on loopback
- submits and approves an issuer application
- publishes an epoch
- verifies that the resulting trust state is queryable
- starts both UI servers on ephemeral loopback ports and fetches their HTML,
  recursively emitted JavaScript modules, and CSS assets; missing relative
  imports fail before HTTP probing, while empty type-only modules are allowed

Each default run uses a unique temporary directory under
`artifacts/trust-registry/demo-smoke/`, so retained or interrupted runs do not
block later smoke runs. Pass `--keep-artifacts` to retain the generated files;
the command prints their location. An explicit `--workspace` path is never
overwritten, and cleanup removes only files created by that run.
An interrupted default run can leave a `run-*` directory under
`artifacts/trust-registry/demo-smoke/`; inspect those directories before
manually removing them. The smoke runner never recursively removes a
user-provided `--workspace` directory. If shutdown needs SIGKILL, the command
warns but still succeeds when the child exits. An unresponsive child or failed
cleanup fails the command and reports the original failure and any retained
artifact path.

The main and milestone CI workflows run the same smoke command after
`./run.sh --light`, so missing build outputs or broken local startup fail from a
clean checkout without repeating the full proving build. On failure, the smoke
command includes captured API and UI process output.

### Signed Mutation Journey

Run the local signed-mutation demonstration:

```bash
pnpm run demo:signed
```

It builds the light packages, starts an API server with a temporary operator
workspace and fixture Midnight DID resolver, and signs applicant and maintainer
mutation intents with separate JubJub keys outside the UI clients. The applicant
portal and admin console clients fetch non-cacheable mutation contexts and
submit already-signed envelopes through their public API methods. The sequence
submits an issuer, approves and activates it, publishes an epoch, then suspends
it and publishes another epoch. Public temporal lookup and TRQP query/evidence
must agree on the active decision and inclusion commitment at the same
historical instant. Both query paths must deny after suspension while the
earlier active-time decision remains true. The script also checks that unsigned
writes, an invalid signature, replay, a stale context, an invalid transition,
and a wrong-scope lookup are rejected with structured HTTP problems. A second
process holds the workspace write lock during approval: the API rejects the
conflicting signed write with 409, then accepts the same intent after unlock.
It prints a
compact JSON transcript and deletes its temporary workspace on exit.

This is a **local fixture demonstration**, not a live-network or proving demo:
finality is simulated, the workspace has one fixture maintainer rather than a
2-of-3 Compact-backed approval bundle, and the script does not issue or verify
a VC/VP or independently verify a Compact proof. The reported epoch root is
operator-workspace evidence, not a network-finality claim.
The cross-process check covers one shared local filesystem, not a distributed
multi-writer deployment. The applicant and admin pages now expose this public
client path: load a fresh signing context, paste an externally signed envelope,
and submit without handing either page a private key. Their DOM-handler tests
cover accepted and stale-context paths; a real-browser signed-intent smoke
remains separate #59 work.

### Auditor Applicant Form

Run `pnpm run demo:auditor` and open the loopback URL. The terminal prints
the fixture draft values for the structured auditor form. Enter those values,
prepare the signing digest, sign it with
`node scripts/demo-auditor-admission.mjs sign-digest <digest>`, and paste the
signature into the form. Then issue a challenge and generate its VP with
`node scripts/demo-auditor-admission.mjs vp <nonce>`. The form binds the exact
auditor request profile, purpose, predicates, disclosure level, registry
workspace commitment, epoch, and one-use nonce before requesting a signature.
The fixed-key signer and virtual clock are **fixture-only**; never use them for
real applications. `pnpm run demo:auditor:smoke` sends an envelope prepared by
the same form code through the HTTP registration and VP intake, including
rejections for unauthorized registration, changed payload, wrong scope, and
replayed VP. The portal's DOM-driven live-host test also exercises forged
signature rejection and recovery through its form handlers. Neither test uses
a browser engine or demonstrates Midnight-network finality. Successful
evidence intake does not activate membership.

The applicant portal also has structured issuer and verifier forms. Issuer
preparation binds the credential family, schema/version, definition, status
method, and selected issuer resource type; verifier preparation binds the
complete request profile, purpose, credential-scope commitment, allowed
attributes and predicates, and disclosure level. Both use a fresh host context
and an externally signed Midnight DID digest. Their DOM-to-HTTP integration
tests register each role with the fixture DID key and complete VP evidence
intake through the live loopback API. These are pending records only, not
governance approval or Midnight network finality.

To demonstrate one of those forms interactively, start
`node scripts/demo-auditor-admission.mjs serve 4400 issuer` or replace `issuer`
with `verifier`. Enter the printed draft, sign the displayed digest with
`node scripts/demo-auditor-admission.mjs sign-digest <digest>`, then generate
the challenge-bound presentation with
`node scripts/demo-auditor-admission.mjs vp <nonce> <role>`. The demo key and
role-scoped VP generator are fixtures only.

To exercise the file-backed, quorum-governed issuer path through the public
applicant and admin clients, run `pnpm run demo:signed-issuer`. Before accepting
the applicant's VP, this command rejects a forged credential signature, a
validly signed credential for another family, revoked fixture status, and an
expired status decision over the same issued challenge. No rejected attempt
produces an acceptance receipt. The original challenge then accepts the valid
VP exactly once, after which 2-of-3 maintainers approve and activate the
issuer, publish an epoch, and retain independently checked active-time evidence
through suspension and revocation. The fixture status decisions and ledger
finality are simulated; this is not a general-purpose VC status verifier or a
live-network transaction.

### Compact-Governed Registry Journey

Run the separate quorum-backed reference demo:

```bash
pnpm run demo:governed
```

For issuer, verifier, auditor, and maintainer membership, it verifies published
fixture VC/VP signatures against Midnight DID keys, consumes a separate one-use
application challenge through the authenticated VP HTTP intake, and submits
only its redacted signed evidence through the governed HTTP proposal route.
Each proposal requires a registered evidence-verifier signature
and external 2-of-3 maintainer votes. The signed fixture credential body carries
the role-specific scope; a mismatched signed scope or altered body is rejected.
The signed fixture presentation body must name that credential body root and
holder DID. The HTTP journey rejects a validly signed presentation for another
credential and a revoked fixture-status decision without persisting evidence.
The local host uses independent random per-applicant bearer secrets, rejects
missing or another applicant's secret before reading a body, and closes the
pending application when evidence is persisted. A validly signed wrong-scope
credential is rejected without closing it. Reuse of a consumed challenge or a
fresh challenge after acceptance is rejected. Neither credential nor
presentation body appears in the evidence response, persisted demo evidence,
or scrubbed report.
External-recognition proposal remains fixture-signed because third-party
accreditation proof is not implemented. Each approval and activation then uses the
governed HTTP prepare and submit endpoints with two independently produced
JubJub signatures from existing maintainers. The script rejects one-signer,
candidate self-vote, replayed context, cross-role ID, and wrong-scope requests.
It independently verifies active issuer, verifier, auditor, and recognition
evidence returned by the API; recognition never becomes local membership. The
new maintainer then co-signs another issuer proposal. The issuer journey checks
the published epoch root plus wrong-registry and expired-epoch rejection. Issuer,
verifier, auditor, and recognition each check current and historical API
evaluations across active, suspended, and revoked states. Historical trust at
the active instant remains verifiable after both lifecycle changes; recognition
remains external authority recognition, not local membership.
After those actor journeys, the simulator demo raises the ordinary decision
threshold from 2-of-3 to 3-of-4, rejects a two-signer proposal, and accepts a
three-signer proposal. It then suspends the new maintainer using the emergency
threshold, rejects that maintainer's later vote, and accepts a proposal from
the three still-active maintainers. The independent integration suite also
rejects self-voted removal and non-self removal that would leave fewer active
maintainers than the configured threshold. These are local Compact
simulator assertions, not proof of network finality.
For the issuer, the same Midnight DID uses separate authentication and assertion
keys: the authentication key signs the application VP, and the assertion key
signs a subsequent VC. The demo registers a governed VC authority key, converts
the active issuer epoch and DID assertion-method observation into decision
evidence, installs a quorum-gated signer descriptor in the compiled Compact VC
consumer, and verifies a credential signed by that issuer. It rejects a
wrong-schema credential and a forged issuer signature. This proves the
schema-level issuer trust path; credential definition and status remain separate
checks. The descriptor readers use simulator ledger and DID fixtures, not a
production authenticated Midnight finality source.
The verifier follows the same governed descriptor path using its Midnight DID
authentication key and exact approved request-profile commitment. A compiled
consumer accepts the signed request and rejects a different profile or forged
request signature. It also rejects independently signed requests that expand
attributes or predicates, change purpose, or increase disclosure relative to
the approved profile. The issuer and verifier examples use separate local
consumer instances; they do not authorize a holder presentation on their own.
The issuer consumer also installs newer authority-signed suspended and revoked
descriptors from independently checked registry epoch, grant, and DID evidence.
After each update the prior credential proof fails in the consumer. The demo
replays the accepted descriptor history into a fresh local consumer instance;
it does not imply that registry status changes appear synchronously in a
deployed consumer. The authority signer rejects inactive evidence on its
active-only path, and status updates require an explicit target state.
The verifier consumer follows the same descriptor-update sequence; its
previously authorized request proof fails after suspension and revocation.
Both roles reject stale descriptor replay and a fixture-signed attempt to
reactivate a terminally revoked descriptor. These are local consumer checks,
not a promise that a deployed consumer has received the latest registry event.
The auditor path verifies an exact mandate from the public HTTP evidence bundle
against the simulator-backed epoch context. A changed audit purpose fails, and
the mandate is denied after suspension or revocation. The scrubbed report
contains only mandate identifiers and commitments; it does not request or
return verifier-held information.
`./run.sh integration` runs this scenario after the package integration
tests. The scrubbed JSON report contains identifiers, commitments, epoch roots,
governance event hashes, and one actor row with policy version, epoch ID,
activation signer key IDs, and expected/observed result. Issuer, verifier,
auditor, and recognition rows use their record-specific active evidence epoch;
the maintainer row uses the epoch of its active membership snapshot. These
can differ from the newest registry epoch. The report omits signatures, VP
transcripts, claims, and holder secrets.
Eligibility and status decisions use trusted fixture adapters; the negative
suspension and revocation fixtures are contract-backed but are not submitted
through the external-signature HTTP action port. Finality is simulated, not a
transaction submitted to Midnight. The fixture credential-family verifier uses
test-only issuer eligibility and status decisions; it is **not** a verifier for
arbitrary uploaded VPs. This demo must not be exposed as a public applicant
endpoint.

The JSON output now includes a partial `tr-adversarial-matrix-v1` report.
Each recorded case names the violated invariant, boundary, expected category,
observed result, and a `passed` or `failed` status. The report includes
`summary.total`, `summary.passed`, and `summary.failed`. A failed case records
a fixed, redacted reason rather than a response body or thrown message. The
governed demo checks that the report still contains 171 cases and exits
nonzero if any recorded case fails or the count changes. API cases assert the
exact problem-type slug as well as
HTTP status; TRQP adapter cases assert the exact problem type and status.
Temporal decision cases record `decision:allow` or `decision:deny`, with the
API lifecycle status where available. Issuer public API and TRQP decisions are
compared at activation, suspension, revocation, and the earlier active instant
after each later transition. The report also records public historical
decisions for verifier, auditor, and recognition.
Compact/integration/client cases assert a rejection pattern and report the actual thrown
error type on success, not a product error category. Failed Compact approval must also
leave the governance action count unchanged. The JSON report is emitted before
the final aggregate assertion, so a failed recorded case remains inspectable;
unrecorded setup or state assertions can still abort the monolithic demo.
The report contains no credential or VP bodies. It covers four-role challenge replay and unauthorized challenge access,
issuer VP scope/body/status failures, governed proposal and action quorum,
self-vote, duplicate/removed Compact signer, unauthorized evidence verifier,
last-active-maintainer protection, altered proposal commitment and signed
Compact evidence hash, duplicate signer rejection, policy-threshold
replay, historical evidence under old and new policy snapshots, client evidence
checks, signed evidence expiry/policy-ID substitution, exact public scope
queries, and TRQP unknown
scope, unavailable epoch evidence, and contradictory source data. Issue #60
remains open for the missing combinations documented in the
[coverage map](../plans/adversarial-matrix-coverage.md). After building the
light packages, generate the machine-readable report locally with:

```bash
node scripts/demo-governed-registry.mjs > /tmp/tr-governed-report.json
```

The `adversarialMatrix` member is the checked case report; the other members
are the demo transcript. The output is deterministic in case IDs and categories,
but local epoch identifiers and event hashes are fixture-dependent.
Issue #216 is extracting the demo cases into independent tests with fresh
fixtures and positive controls. The current runner has 66 such tests across
Compact/integration/client, public HTTP, and TRQP adapter boundaries; it does not yet replace
the 171-case demo or make every monolithic setup failure independent.

## Artifact Boundaries

The repository currently distinguishes between two artifact classes.

Local artifact packages:

- `@midnight-ntwrk/trust-registry-contract`
- `@midnight-ntwrk/trust-registry-domain`
- `@midnight-ntwrk/trust-registry-client`
- `@midnight-ntwrk/trust-registry-integration`
- `@midnight-ntwrk/trust-registry-cli`
- `@midnight-ntwrk/trust-registry-api`
- `@midnight-ntwrk/trust-registry-admin-console`
- `@midnight-ntwrk/trust-registry-applicant-portal`
- `@midnight-ntwrk/trust-registry-trqp-adapter`
- `@midnight-ntwrk/trust-registry-openid-federation-adapter`

Remotely publishable core packages:

- `@midnight-ntwrk/trust-registry-contract`
- `@midnight-ntwrk/trust-registry-domain`
- `@midnight-ntwrk/trust-registry-client`
- `@midnight-ntwrk/trust-registry-trqp-adapter`
- `@midnight-ntwrk/trust-registry-openid-federation-adapter`

Local-only artifact packages for now:

- `@midnight-ntwrk/trust-registry-integration`
- `@midnight-ntwrk/trust-registry-cli`
- `@midnight-ntwrk/trust-registry-api`

Those packages remain private, local-only artifacts while their public
packaging and deployment policy is finalized. They are packed into
`artifacts/npm/` for downstream workspace use and smoke-tested there; DID and
VC dependencies come from npm. The UI artifacts export only their API clients
for Node consumers, not their browser entry points.

Pack and validate local artifact tarballs:

```bash
pnpm run artifacts:pack
pnpm run packages:check-contents:light
pnpm run packed-artifacts:smoke
```

The fast smoke runner installs the tarballs in a temporary consumer directory,
imports each selected package entry point, and runs an issuer/verifier scenario
through the packed local integration harness and simulator client. It verifies
active evidence and rejects a substituted issuer resource. This checks package
boundaries and a local consumer workflow; it does not run the HTTP actor demo
or establish public-network finality. The integration harness is a local-only
artifact, not a supported public runtime dependency.

`./run.sh --light` also runs `demo:governed:check` and the packaged
`--vc-consumer` smoke after the light build. These catch API and VC-consumer
fixture failures before the expensive full Compact proving-key build without
printing the demo's large JSON report on success. They do not replace
`./run.sh integration`.

For the full local actor-consumer and packaged Ledger 8 fixture gate, run:

```bash
pnpm run packed-artifacts:smoke -- --actor-journey --vc-consumer
```

This runs the signed issuer, verifier, auditor, and maintainer HTTP journeys
from the temporary tarball install, including the packed portal and admin API
clients. The optional `--vc-consumer` path also requires the pinned Compact
compiler, compiles the integration package's exported consumer fixture against
the published VC Compact package, and checks its pinned authority domain,
issuer/verifier proof acceptance, and forged-signature, replay, and scope
rejection. The source integration test separately binds signer descriptors to
verified Trust Registry decisions. These remain simulator tests, not finalized
network reads or deployed cross-contract calls.
The actor path also runs `scripts/packed-recognition-journey.mjs`: it checks
accreditation VC/VP intake, a governed recognition proposal, the retained
verifier signature through the public read-only evidence route, a missing
proposal and unavailable-ledger rejection, and suspension. Run that script
directly to inspect its scrubbed JSON report. It contains commitments, signer
key IDs, policy version, epoch, and expected rejection categories, not the VP
or authority assertion.

For a full release build, run `pnpm run build` and then
`pnpm run packages:check-contents`; the latter requires proving keys and ZK IR.
On a clean, signed/DCO candidate revision, repack the full build and generate
its local artifact manifest:

```bash
pnpm run build
pnpm run packages:check-contents
pnpm run artifacts:pack
pnpm run packed-artifacts:smoke
pnpm run artifacts:release-manifest
```

The manifest at `artifacts/release-candidate/<source-sha>/manifest.json` records the exact
source SHA, Compact pin, lockfile hash, DID/VC dependency versions, contract
source/generated hashes, and SHA-256/size for each intended npm or local-only
package. Generation refuses a dirty or unsigned source commit, incomplete
full Compact outputs, and a contract tarball lacking its circuit ZKIR and
prover/verifier pairs. A manifest is an artifact inventory, **not** evidence
that the full tests, network finality, owner approval, or publish rollback gate
passed. Retain those results separately for the same source SHA. Light-build
tarballs cannot qualify as a release candidate.

From a clean consumer checkout, verify the approved manifest against the
received tarballs before the smoke runner installs them:

```bash
pnpm run packed-artifacts:smoke -- --manifest artifacts/release-candidate/<source-sha>/manifest.json --artifacts-dir artifacts/npm --actor-journey --vc-consumer
```

With `--manifest`, the runner does not generate missing packages; a missing,
extra, duplicated, truncated, or hash-mismatched artifact fails before npm
installation. Obtain the manifest through the reviewed release channel: its
hashes do not authenticate an attacker-supplied manifest by themselves.

## Release Workflow

### Public-network security gate

The simulator demos and package smoke tests below do **not** qualify a public
Midnight deployment. Before promoting 0.1.0 as public-network ready, the release
owner must record evidence for all of the following:

- Deploy with the registry identity, initial policy, bootstrap maintainer key,
  threshold, and nonzero network commitment in the constructor. There must be
  no externally callable first-run initializer; test that a hostile first
  caller cannot replace the constructor state.
- Authenticate the target network and deployed contract address through the
  deployment provider independently of a caller-supplied label or evidence
  bundle. Verify the constructor's declared network commitment against that
  network, and read finalized ledger state before distributing the signing
  domain to maintainers. The Compact contract does not attest to chain identity.
- Provision maintainer signing clients with that pinned network commitment and
  contract address. Confirm a quorum action succeeds on the target deployment
  and fails at the same sequence on another address and another network. Never
  use the constructor initialization event alone as proof of the deployed
  address; only post-deployment governed events bind it.
- Qualify a non-conflicted emergency and archival recovery path, including
  2-of-2 and 3-of-3 policy proposals, subject exclusion, and maintainer
  suspension, revocation, and archival. Do not approve a policy that strands
  removal without a separately authorized, tested recovery mechanism.
- Run `./run.sh --light`, full `./run.sh integration`, documentation checks,
  and the published-artifact smoke tests at the exact release candidate. Retain
  finality evidence, deployment parameters, validation logs, and independent
  review alongside the release decision.

Issue [#200](https://github.com/midnightntwrk/midnight-trust-registry/issues/200)
tracks the remaining public-network qualification and recovery model. Until its
criteria are met, this repository's 0.1.0 result is a simulator-validated
reference implementation, not a public-network security claim.

The repo currently exposes two manual GitHub Actions workflows:

- `Publish Packages`
- `Published Package Smoke`

`Publish Packages` performs the following sequence:

1. stamps a release version across the root and workspace manifests
2. validates manifest and package-content expectations
3. builds the repository
4. packs release tarballs and smoke-tests them locally
5. publishes the remotely publishable core packages
6. smoke-tests the published packages from the configured registry

The publish workflow only runs from the `develop` branch and pauses at the
protected `npm-publish` environment. Configure required reviewers and the
`NPM_TOKEN` secret on that environment before using the workflow in a public
repository.

`Published Package Smoke` reruns only the final published-package import smoke
for a specified version.

Local helpers used by the workflow:

```bash
node scripts/release-set-version.mjs --version 0.1.0-rc2
pnpm run published-artifacts:smoke -- --tarball-dir artifacts/npm-release
```

The publish workflow expects `NPM_TOKEN` to be configured as a repository
secret. The default registry is `https://registry.npmjs.org`.

## Dependency Refresh

Current supported DID baseline:

- `@midnight-ntwrk/midnight-did@0.7.0`
- `@midnight-ntwrk/midnight-did-contract@0.7.0`
- `@midnight-ntwrk/midnight-did-domain@0.7.0`
- `@midnight-ntwrk/midnight-did-jubjub-schnorr@0.7.0`

Current VC baseline is `@midnight-ntwrk/credential-compact@0.2.0` and
`@midnight-ntwrk/credential-did-midnight@0.2.0` from npm. The retired private
VC/status package tarballs are not supported. VC `0.2.0` does not include the
old status-helper API; live status-registry evidence needs a separate adapter.
Issuer evidence now includes a governed status-policy commitment in its signed
authorization leaf and a client-verified preimage naming the accepted registry
and authority method. The legacy `referencedStatusRegistryId` hint is rejected
for issuer decisions. This does not prove a credential is unrevoked: a separate
adapter must verify status-authority DID state and a fresh authenticated VC
status proof before consumers accept a non-revocation claim.

Refresh the published DID and VC versions with validation:

```bash
pnpm run refresh:identity-dependencies -- --did-version 0.7.0 --vc-version 0.2.0 --validate light
```

Useful variants:

```bash
pnpm run refresh:identity-dependencies -- --did-version latest --skip-vc --validate none
pnpm run refresh:identity-dependencies -- --skip-did --vc-version 0.2.0 --validate integration
```
