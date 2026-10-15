# Trust Registry Knowledge Base

Status: working knowledge snapshot
Updated: 2026-10-14

## Purpose

This document is the repo-local execution snapshot for
`midnight-trust-registry`.

It records the current code surface, validation baseline, dependency posture,
backlog posture, and the next implementation direction. It is intentionally
shorter-lived and more action-oriented than the normative specification.

## October 2026 Local Functional Stack

- The next #78 slice has an executable recognition accreditation VC/VP plan:
  a separately governed accreditor DID/method and status source, exact
  authority/registry/scope claims, shared proof core, atomic challenge
  consumption after both proofs, and one redacted commitment carried through
  Compact and public evidence. The plan explicitly forbids treating the
  existing DID-control assertion or a self-signed Federation terminus as
  accreditation. No implementation or public route is claimed yet.
- #60's joined adversarial matrix now calls the Compact simulator directly
  with otherwise valid recognition signatures but a substituted external
  registry or resource commitment. Both reject without advancing governance
  state; a valid proposal still succeeds afterward. This is scoped-signature
  evidence, not proof that the external accreditation is valid. Retrospective:
  direct simulator mutation is needed for this case because the harness
  preflight rejects stale contexts before Compact sees them.
- #59's signed HTTP mutation test now uses a separate Node process to hold
  the real workspace lock. The request returns a typed 409 without consuming
  the nonce, then succeeds after release. This proves same-host
  shared-filesystem exclusion in the reference adapter, not distributed
  locking or crash-durable transactions. Retrospective: the first child helper
  left IPC open after releasing its lock and the test hung; explicit IPC
  disconnect plus a bounded release wait made the focused 8-second test
  reliable. Prefer a focused process test before the broad API suite.
- The API library now has a recognition-specific, one-use Midnight DID
  authority challenge primitive over the existing atomic challenge-store
  interface. It binds the exact recognition tuple, rejects pre-challenge and
  future statements, and consumes only after DID assertion verification.
  The joined governed demo now issues that challenge, rejects bad assertions,
  consumes it once, rejects replay, and carries the verified commitment into
  the Compact proposal. It is not mounted on HTTP and does not validate
  external accreditation; #78 remains open. Retrospective: the membership
  challenge binding cannot represent recognition, but its low-level atomic
  store can be reused without weakening the membership schema. A focused API
  test runs in about one second; run it before the much broader API suite.
- The joined governed demo now proposes recognition from a verified Midnight
  DID authority assertion, a separately signed local evidence-verifier proof,
  and 2-of-3 maintainer signatures. It rejects a wrong external registry,
  wrong-scope signature, and one-maintainer attempt before mutation, then
  carries the proposal through approval, activation, and public trust checks.
  The accreditation commitment remains an unverified reference and the
  evidence verifier is fixture-held; this is not external accreditation or
  network finality. Retrospective: extend the existing joined demo rather
  than adding a disconnected happy-path test, and use its focused run before
  the broader light lane.
- Local #78 continuation after signed `10ebdf6`: the integration package now
  has a bounded Midnight DID authority assertion for recognition, with exact
  registry/authority/scope/challenge checks, assertion-method JubJub signature
  verification, a 24-hour maximum statement lifetime, and a commitment to
  the signed envelope plus observed DID state version and evaluation instant.
  A distinct harness method prepares a Compact proposal from that verified
  commitment. Focused tests cover substitution, expiry, key rotation, wrong
  DID relationship, stale proposal context, and a positive 2-of-3 proposal.
  It does not verify the referenced accreditation or consume a challenge, so
  #78 remains open and public intake must not use this fixture as proof of
  external trust.
- Iteration retrospective: promoting the DID Schnorr package from dev to
  runtime dependency required a lockfile update; the first typecheck read
  stale domain output until the domain package was rebuilt. Use dependency-
  ordered Turbo builds for the broad gate, direct package tests for the inner
  loop. TypeScript also caught a test reaching private bootstrap keys; use
  public maintainer onboarding and 2-of-3 signatures instead.

- Local #78 recognition-evidence slice is in progress after `452627c` on
  `codex/trust-registry-operator-applicant-e2e`. Compact now verifies a
  registered active evidence-verifier Schnorr signature over the complete
  scoped recognition proposal and stores a separate proof snapshot. Approval
  and activation recheck that verifier key and policy. The simulator's
  externally signed execution method requires the verifier signature; only
  the fixture convenience path signs from a test seed. Contract and integration
  tests reject bad evidence signatures, substituted registry scope, and
  suspended-key approval. This is local attestation, not independent external
  accreditation; the fixture evidence commitment remains synthetic.
- Iteration retrospective: `compact:light` and contract typecheck completed in
  about one second each, a focused contract negative test in about one second,
  the external-recognition integration test in under two seconds, and the
  complete `./run.sh --light` lane in about 48 seconds. A broad patch context
  initially placed new arguments in the wrong simulator method; inspect each
  diff before compiling and use method-specific patch contexts. Keep full
  proving (previously about 24 minutes for 65 circuits) for a coherent
  publication checkpoint, not each small recognition edit.

- Local `codex/trust-registry-operator-applicant-e2e` now has signed/DCO commits
  `9591889` and `d85dffa` for externally signed two-action quorum revision.
  The first action changes thresholds under the old policy; the second
  registers the evidence-verifier key under the new policy. The governed HTTP
  demo uses the injected Compact simulator port rather than the fixture helper
  for this transition, while other fixture paths remain. The admin page warns
  about the intermediate state only within its browser session; operators must
  inspect ledger state after reload. The packaged CLI still returns 503 without
  an injected port. These local checks do not establish transaction atomicity
  or network finality.

- The local `codex/trust-registry-adversarial-matrix` branch is stacked on the
  VC authority slice and is not yet published. Its governed demo now emits a
  checked `tr-adversarial-matrix-v1` with 90 cases across API, Compact simulator,
  integration preflight, client, and TRQP adapter boundaries. The [coverage map](../plans/adversarial-matrix-coverage.md)
  names the remaining #60 gaps; do not close #60 on the current report.
- The fastest local loop for script-only adversarial work is the matrix unit
  test plus `node scripts/demo-governed-registry.mjs` (about six seconds for the
  demo). Run `./run.sh --light` and `./run.sh integration --light` before a
  signed checkpoint; do not repeat the full proving-key build without a
  contract or generated-artifact change.
- The threshold-revision matrix has separate outcomes: old-policy applicant
  evidence fails simulator preflight, old policy-bound signatures fail direct
  Compact execution, historical evidence verifies at its original instant,
  and replay at the new policy's effective instant fails. These are local
  simulator-time claims, not wall-clock or network-finality claims.
- Validly signed applicant evidence with a substituted policy ID or an elapsed
  24-hour validity window is rejected before governance mutation. The matrix
  also distinguishes exact issuer/verifier API resource lookup and TRQP
  external-recognition tuple matching from client bundle verification.
- The direct Compact boundary now rejects a changed issuer evidence hash and
  both attempts to remove the last active maintainer; API actions reject
  duplicate signer entries across all five governed roles. Candidate self-vote
  rejection is observed, but a separate witness is still needed to prove the
  explicit Compact self-DID exclusion rather than an earlier inactive-key gate.

- PR #171 and the later admission groundwork are merged to
  `milestone-0.1.0`; local signed work continues on
  `codex/trust-registry-role-admission` without waiting for another merge.
- Signed pending `apply` requests cover issuer, verifier, auditor, and
  maintainer roles. The applicant now signs the requested authorization ID as
  well as the application ID, canonical scope, and governed resource. The
  pending record retains that target; duplicate pending targets are rejected.
- A server combining VP intake and governed proposal routes requires an
  accepted-application admission port. Prepare and submit compare the role,
  target, binding, exact redacted evidence, and receipt before Compact-backed
  proposal work. The four-role simulator demo exercises rejected cross-role,
  wrong-target, and missing-receipt attempts.
- This remains a local reference boundary. The signed registration demo and
  2-of-3 Compact governance demo still use separate state paths; durable
  pending/evidence persistence, live verifier authorization, and one joined
  applicant-to-epoch public journey remain milestone work.

## Current Milestone

- `develop` includes the release/demo and DID `0.5.0-rc2` slice from PR #71.
- The [0.1.0 profile](../spec/milestone-0.1.0.md) defines a simulator-based,
  DID/VC-backed governed trust journey and names each actor's authority.
- The [issue plan](../plans/milestone-0.1.0-issues.md) reuses #39, #45, #49,
  #58-#60, #67, and #73 and tracks the missing scope, evidence, mutation, and
  multi-role integration slices as #75-#79.
- The main blockers are real evidence-verifier signature checks in Compact,
  official VC/VP eligibility verification, authenticated API mutations,
  independently verified VC signer-descriptor and authority-proof production,
  and cross-surface
  positive/negative scenarios.
- Ledger 8 portable signer descriptors (#73) are in 0.1.0; synchronous
  cross-contract calls and production hosting remain outside it.

## Historical Branch Snapshot

The branch and implementation notes below are retained as a July 2026
snapshot. They are not the current release plan.

### July 2026 Branch State

- upstream baseline branch:
  - `develop`
- current local implementation branch:
  - `codex/trust-registry-public-readiness`
- branch purpose:
  - uplift published identity dependencies
  - harden the repository for public consumption
  - expose root demo and operator entrypoints
  - switch the backlog from stack-only tracking to issue-backed tracking

### July 2026 Implementation Baseline

Merged on `develop` before the July 2026 local slice:

- domain package:
  - `packages/trust-registry-domain`
- Compact contract package:
  - `contracts/trust-registry`
- simulator-first integration package:
  - `packages/trust-registry-integration`
- client package:
  - `packages/trust-registry-client`
- adapters:
  - `adapters/trqp`
  - `adapters/openid-federation`
- operator and API surfaces:
  - `packages/trust-registry-cli`
  - `packages/trust-registry-api`
- local UI surfaces:
  - `packages/trust-registry-admin-console`
  - `packages/trust-registry-applicant-portal`

Implemented functional baseline on `develop`:

- governed issuer lifecycle:
  - `proposed`
  - `authorized`
  - `active`
  - `suspended`
  - `revoked`
  - `archived`
- governed verifier lifecycle with scoped request profiles
- governed recognition lifecycle for external authorities and registries
- governed auditor authorization family
- governed maintainer membership lifecycle
- multi-maintainer quorum execution with scoped thresholds
- typed governance policy templates and decision bindings
- published epoch anchoring and historical evidence export
- simulator-backed local integration scenarios
- query client verification for active and historical evidence
- read-only query API plus workspace-backed governed mutation API
- local admin console and applicant portal over the existing API

## Current Identity Dependency Posture

Trust Registry consumes published Midnight DID and VC packages from npm. No
VC package tarballs are tracked or seeded into clean-consumer tests.

Current DID package baseline:

- `@midnight-ntwrk/midnight-did@0.7.0`
- `@midnight-ntwrk/midnight-did-contract@0.7.0`
- `@midnight-ntwrk/midnight-did-domain@0.7.0`
- `@midnight-ntwrk/midnight-did-jubjub-schnorr@0.7.0`

Current VC dependency posture:

- `@midnight-ntwrk/credential-compact@0.2.0` and
  `@midnight-ntwrk/credential-did-midnight@0.2.0` provide the current VC core
  signer-authorization and DID-binding surface for #73
- retired VC 0.1.0 status helpers are not part of the new VC core; status
  authority evidence and a live TR-to-VC anchor still require follow-up work
- legacy `referencedStatusRegistryId` and status-policy URI bundle hints are
  outside the signed leaf; the issuer verifier rejects them
- the local #90 slice defines a strict V1 preimage and fixed digest vector for
  status-registry ID, authority DID method, and policy identity/content; the
  governed issuer proposal signs its digest, the ledger retains it through
  lifecycle changes, and the epoch-authenticated issuer leaf carries it
- the client checks the supplied preimage against the anchored leaf before
  exposing the accepted status registry and authority identifier; this does
  not verify the DID method's current key state or any VC status proof
- the VC status-registry package still documents prototype authority and
  root-verification limitations; do not represent its current helpers as a
  supported non-revocation proof until those upstream gates are satisfied
- Trust Registry remains the owner of governance and authorization logic
- `midnight-did` remains the owner of DID lifecycle and resolver behavior
- `midnight-verifiable-credentials` remains the owner of VC/VP and status
  semantics

Local validation on 2026-10-05: frozen pnpm install, `pnpm audit --audit-level
low`, `./run.sh --light`, and `./run.sh integration` passed. The full lane
spent about 19 minutes compiling the 54-circuit contract, while the focused
integration package passed 22 tests before the review fix that removed the
tautological status-reference test; the focused package then passed 21 tests.
#76 tracks anchoring the status reference and restoring live status-authority
and revocation coverage.

Dependency decision:

- do not import source files from sibling repositories at runtime
- do not keep copied Schnorr helper code inside the TR contract package
- consume published package artifacts through local manifests

## Public-Readiness Hardening

Merged PR #71 added the following repository hardening:

- root package-manager baseline:
  - `pnpm@10.34.1`
- root `.npmrc` with strict engine enforcement
- `Dependabot` updates for `npm` and GitHub Actions
- semantic pull-request checks for titles and non-empty bodies
- quality workflow for build, typecheck, and audit lanes
- contributor and PR-template updates for public review hygiene
- root ignore rules for generated demo artifacts

## Root Demo And Operator Surface

The repo now exposes root orchestration commands for the existing contract,
backend, and UI skeleton:

- `pnpm demo:prepare`
- `pnpm demo:prepare:snapshot`
- `pnpm demo:serve:api`
- `pnpm demo:serve:admin-console`
- `pnpm demo:serve:applicant-portal`
- `pnpm quality`
- `pnpm audit`

Default local endpoints:

- API:
  - `http://127.0.0.1:4400`
- admin console:
  - `http://127.0.0.1:4173`
- applicant portal:
  - `http://127.0.0.1:4175`

## Validation Baseline

Current required local gate for code-bearing changes:

```bash
pnpm install --frozen-lockfile
./run.sh --light
./run.sh integration
git diff --check
```

Historical July 2026 validation snapshot (not the current milestone result):

- `pnpm install --frozen-lockfile=false`
  - passed while updating the lockfile for DID `0.5.0-rc2`
- `./run.sh --light`
  - passed
- `./run.sh integration`
  - rerun after clearing a stale local compile hang; final status should be
    recorded with the branch summary when the slice is closed

Operational note:

- `./run.sh integration --light` runs the simulator integration suites and
  three demo smoke journeys against the `--skip-zk` contract build. On
  2026-10-14 it passed 89 integration tests and all demos in 30.43 seconds
  with a warm local Turbo cache.
- The full integration lane spent more than 6 minutes 28 seconds in
  `zkir compile-many` before tests began in the same worktree. That run was
  stopped after confirming the cost; it was not a full-lane pass. The compiler
  exposes no `compile-many` parallelism flag. Reserve the full lane for
  contract/proving changes and publication checkpoints, never substitute the
  light lane for proving-key or network-finality validation.
- run `./run.sh --light` and `./run.sh integration` sequentially, not in
  parallel

## Backlog Posture

Planning has shifted from stack-only notes to GitHub issue tracking.

The first 20 issue-backed work items are #29 through #48. The next alignment
issue is #49. The current 0.1.0 blocker set is the
[milestone plan](../plans/milestone-0.1.0-issues.md), not this older tranche.

These cover:

- maintainer lifecycle completion
- quorum and governance hardening
- query API and governed write API
- admin console and applicant portal maturation
- historical evidence and proof-bundle hardening
- reproducible demo packaging
- release readiness and dependency refresh automation
- documentation and knowledge-base synchronization

Canonical backlog file:

- `docs/plans/trust-registry-backlog.md`

## Historical July 2026 Execution Order

This list is retained for context and is not the current recommendation.

1. close the public-readiness branch locally
   - confirm `./run.sh integration`
   - finalize knowledge-base sync
2. split the next implementation wave into large reviewable slices
   - contract completion
   - backend persistence and operator workflows
   - application UX and demo packaging
3. keep new slices issue-backed first, then stack PRs on top of the issue set

## Knowledge Synchronization Rule

When a meaningful TR slice lands or materially changes direction, update:

1. this repo-local knowledge base
2. the workspace-root knowledge base under
   `midnight-identity-workspace/research/`
3. the global `trusted-registry` Obsidian vault

## Milestone delivery train (2026-10-05)

`milestone-0.1.0` was created from `develop` at `0b7f620`. Its minimal
repo-local harness is specified in
`docs/plans/milestone-0.1.0-delivery-harness.md`: issue-backed PRs, documented
exact-head review, light, Quality, and scan gates, bounded review rounds, and
guarded merging. PR #82's receipt gate was rejected as a self-declared policy
check; replacement PR #91 removes it. `.github/CODEOWNERS` plus required
code-owner review protects workflow and policy changes after the bootstrap.
The bootstrap itself is not yet protected by those controls; a canary must be
blocked before autonomous milestone merges start. Only the milestone branch
permits zero-general-human-review product merges. Policy changes still require
code-owner review; `develop` and `main` remain human-controlled.

## Application evidence signing slice (2026-10-06)

The simulator's former `SHA-256(commitment:keyId)` signature stand-in has been
replaced by a real, test-key JubJub Schnorr signature over a Compact-generated,
domain-separated digest of the canonical application-evidence commitment and
the assertion key id commitment. A fixture test resolves the corresponding native
assertion key through the published Midnight DID/VC adapter and verifies the
signature. Domain validation also binds the exact application id, rejects
invalid evaluation timestamps, and rejects evidence evaluated before its
`verifiedAt` instant.

This is not completion of #76 or #67: the simulator still creates synthetic
evidence hashes rather than verifying a VC/VP, its verifier key is not looked up
from a DID during proposal, and the Compact contract does not yet check the
evidence-verifier signature. Full integration passed with a fresh Compact build
and 23 integration tests; the pinned light gate and low-level audit passed.

## Application evidence checkpoint (2026-10-06)

- PR #99 merged to `milestone-0.1.0` as `97a66ca`, followed by PR #100 as
  `4163c25`. PR #100 delivered a partial #76 DID JubJub evidence-signature
  slice, removed pre-release compatibility paths, and set the initial contract
  format to version 1. It passed Nix-pinned light and full integration locally
  with 23/23 simulator tests, but did not complete VC/VP eligibility or the
  #67 on-ledger evidence-verifier authorization path. Issue #101 tracks broader
  signature-ingress auditing. Issue #98 remains open because its independent
  contract/security review criterion is not evidenced by PR #100 reviews.
- The unpublished `codex/trust-registry-evidence-challenges` branch is now
  based on the merged milestone head. It adds a five-minute, one-use off-ledger
  challenge service.
  Its storage interface requires atomic insert and consume; the included
  in-memory adapter is for local testing, not a public multi-replica API. A
  public endpoint still needs durable storage, abuse controls, and actual VP
  challenge verification. After the latest rebase, a fresh Nix-pinned full
  integration build passed all 23 simulator tests on this branch. The Nix-pinned
  light gate passed all 19 tasks before publication.
- PR #99 Quality run 37362856813 was cancelled twice before any step after
  about 15 minutes queued. The later exact-head run 37417727434 succeeded.
  Issue #84 records the CI queue evidence; a cancelled run was not a green gate.
- The challenge TTL is enforced by the evidence verifier's off-ledger clock;
  the Midnight contract does not independently provide wall-clock time.

## Published VC Compact composition (2026-10-06)

The published `@midnight-ntwrk/credential-compact@0.2.0` module requires
Compact 0.31.1 and `@midnight-ntwrk/compact-runtime@0.16.0`. Compact 0.30.0
can parse the module but emits a runtime 0.15.0 guard that fails at load time.
The registry now pins 0.31.1 in `.compact-version` and Nix for both supported
platforms, and no longer rewrites generated runtime checks or circuit tables.
The integration package compiles a small VC/VP envelope-relation module directly
from the published package export and executes matching and mismatching
fixtures in the light and full integration lanes. The generic relation does
not compare holder bindings; that is intentionally left to the family layer.
This establishes a composition
prerequisite for #76, not VC/VP evidence verification or a live trust anchor.

## Applicant and decision-evidence checkpoint (2026-10-14)

PR #182 merged to `milestone-0.1.0` at `473c031` after exact-head light,
Quality, scan, GPG/DCO, and independent review. It combines an independently
checked TR decision-evidence reader with challenge-bound published DID/VC proof
fixtures, redacted signed application evidence, and an authenticated loopback
auditor applicant journey. The four-role governed demo takes VP evidence through
quorum proposals and epoch-backed decisions, but its family and status decisions
remain fixture-supplied. This does not complete #76, #79, #152, or the VC
consumer descriptor/proof work in #73.

The local follow-on stack now accepts externally signed pending issuer,
verifier, auditor, and maintainer applications with exact role scope and
governed resource. The same-origin portal handles all four roles through
challenge and redacted VP receipt. Its in-memory registration port is a
single-process reference, not a durable public service or active grant.
Three GPG/DCO-signed commits are rebased onto the merged milestone; light,
full integration (fresh 59-circuit build), demo smoke, and audit passed locally.
The next functional boundary is to persist pending/evidence state and bind it
to a governed proposal without promoting an applicant signature into approval.

The local signed-issuer journey now exercises that binding through the HTTP
proposal route: signed pending registration, one-use VP receipt, receipt-gated
Compact proposal, 2-of-3 maintainer approval and activation, epoch publication,
and client-verified public evidence lookup. It rejects proposal preparation and
submission when the accepted receipt is unavailable, and rejects one-signature
governance actions without advancing the ledger. Registration preflight and
public API snapshots project one simulator state. A private file-backed
adapter now persists pending applications, spent nonces, and accepted redacted
evidence across store restarts. It does not atomically join challenge
consumption, evidence acceptance, and Compact governance; this is not live VC
status verification or network finality.

The next local slice adds applicant-authorized recovery of already accepted
redacted VP evidence and its receipt by application ID. The private GET does
not verify the VP again or consume another challenge; an absent receipt is
ambiguous and is not an automatic retry signal. The portal shows only escaped
redacted evidence in page memory. The signed-issuer demo discards the VP
submission response, recovers the accepted record, and still completes the
governed proposal journey. This is same-host crash/response recovery, not a
transaction across the private stores and Compact ledger.

For API/UI iterations, run direct package Vitest targets first (the focused
application VP HTTP file took about 3 seconds), then `./run.sh integration
--light` (19 seconds warm for 89 simulator tests and three demos), and finally
`./run.sh --light` (about 55 seconds for 20 tasks on this slice). Full
integration compiles 59 ZK circuits and spent over six minutes in
`zkir compile-many` before tests started in the last measured attempt; reserve
it for contract/proving changes and prepublication validation, not each
API-only edit. The fast lane compiles Compact with `--skip-zk` but still runs
the same simulator integration and demo suites.
The four-role governed demo also discards all four accepted VP response bodies,
uses applicant-authorized receipt lookups for issuer, verifier, auditor, and
maintainer, and still rejects a repeated one-use submission.

The signed, private-file-backed membership journey now runs separately for
issuer, verifier, auditor, and maintainer through one shared harness. Each role
uses an externally DID-signed pending application, published-package VP proof
fixture, recovered redacted receipt, exact admission check, 2-of-3 Compact
proposal and lifecycle decisions, and epoch publication. Issuer, verifier,
and auditor output independently verified public bundles; maintainer output
checks the Compact membership record and a one-member active-count increase.
The maintainer candidate cannot co-sign its own proposal or pre-activation
decision. The fixture family/status decisions remain test-supplied, and the
two private files and Compact ledger are not transactionally joined.

The governed-action HTTP prepared context now exposes `targetId`, not the
issuer-specific `authorizationId`. The serializer selects the native
`authorizationId`, `maintainerId`, or `recognitionId` field based on role and
rejects a missing or malformed target. This removes the old demo/test adapter
that copied maintainer or recognition IDs into `authorizationId`; the
repository is unreleased, so there is no compatibility alias. Focused API
serialization/HTTP tests passed 11/11. The four-role `./run.sh integration
--light` passed in about 25 seconds and `./run.sh --light` passed 20/20 tasks,
including 145 API light tests, in about 51 seconds. The full proving lane
remains a prepublication gate.

The local #73 candidate bridge now calls the trusted current-registry and DID
readers before constructing a VC `AuthorizedSignerDescriptor`. It carries the
observed decision sequence, active state, policy root, authorization ID, and
exact native DID method/key/relationship/state version into the published VC
adapter. At this checkpoint it required a caller-supplied TR-to-VC scope
mapping and rejected TR scope substitution; that unsafe mapping input is
superseded by the corrective slice below. It did not yet issue an authority proof or provide
a pinned Ledger 8 consumer. The old bundle-only VC test remains a candidate
example, not an authority test. Focused typecheck/test took about 1–2 seconds,
fast integration about 25 seconds, and `./run.sh --light` about 50 seconds.
Self-review caught an issuer-only relationship check that would have allowed
verifier authentication/capabilityInvocation substitution; the bridge now
requires the exact independently observed relationship. Reserve the full
59-circuit proving build for a prepublication checkpoint.

The local #73 proof slice now uses the published VC Compact
`signerAuthorizationDecisionRoot`, `signerAuthorizationProofChallenge`, and
`assertValidSignerAuthorizationProof` rather than a copied transcript. An
injected authority signer port receives the checked decision root and logical
sequence; the local fixture uses published DID JubJub primitives to sign.
The initial domain hash used a versioned, six-field, length-prefixed UTF-8
preimage; the independent review below found this was not Compact-verifiable
against the executing consumer address, so it was replaced before release.
Consumer verification takes an independently pinned domain/key and requires
either an authenticated previous descriptor or explicit first-install `null`;
negative tests cover domain, key, scope, proof time, stale sequence, DID
rollback, and revoked-to-active replay. This does not establish a governed
authority-key lifecycle, production finality, durable consumer state, or a
Ledger 8 consumer circuit. Retrospective: the focused proof test took about
two seconds and the fast integration lane about 25 seconds; the full proving
build is reserved for prepublication validation of the accumulated stack.

The local Ledger 8 VC consumer fixture now compiles from the published VC
`composable.compact` import. Its constructor writes the authority domain,
method, and key to ledger, with no mutation circuit. Installation checks the
VC authority proof and stores a descriptor by authorization ID; updates use
the VC monotonic sequence, DID-version, and terminal-revocation circuit.
The simulator-derived issuer proof installs successfully, a wrong ledger
anchor fails, a genuinely signed credential is accepted, and the same
metadata with a forged credential signature fails. A separately constructed
verifier descriptor derived from a simulator TR grant, publication witness,
and resolved DID state exercises the signed-request circuit and rejects a wrong
request scope. This is a local compiled/simulator fixture, not a production
deployed consumer; governed scope mapping,
finality, key lifecycle, and durable state remain open.

The independent PR #183 review found that a caller-selected nonzero VC scope
could be signed for an unrelated verified registry grant. The local corrective
slice removes that input: issuer VC `SchemaRef` is derived from the exact
registry family/schema identifiers and representable `major.minor.0` version;
verifier signed-request scope is the canonical full registry request-scope
commitment. The bridge rejects nonrepresentable issuer versions instead of
dropping a patch version or overflowing a VC `Uint<16>`. Tests cover changed
family, schema, version, and verifier predicate. Governed external VC schema
enrollment and signed-request payload construction remain follow-on work.
The same review found that maintainer bootstrap/proposal checked nonidentity
but not prime-order JubJub keys; the corrective contract check rejects a
nonidentity order-two key before membership or quorum activation. A separate
consumer-address replay question was resolved by a Compact-verifiable
seven-field authority domain commitment. The consumer recomputes it from
constructor-pinned fields, then checks its consumer address against
`kernel.self().bytes` at signer installation. A second deployment with the
same anchor now rejects a valid proof, and the local vector is fixed in tests.
The VC issuer descriptor is intentionally schema-scoped: changing only the
TR credential definition or status method changes the full registry scope
commitment but not VC `issuerScopeCommitment(SchemaRef)`. The consumer fixture
therefore names its circuit a schema-signer proof, not a complete credential
authorization decision. Any product claiming full trust must separately
verify definition, status method, and live status against the same grant and
credential.

Iteration timing: focused VC scope and decision tests took about three
seconds; fast integration including four demos took about 25 seconds; a broad
light run took about 50 seconds without contention. The exact-head full lane
started a second 59-circuit `zkir compile-many` after a broad light lane,
indicating the current Turbo/output sequence invalidates the proving cache.
Do not overlap broad light and full proving runs on one laptop, and do not
repeat full proving for a TypeScript-only edit. Reserve it for the final
contract-bearing batch after focused and light gates.

The local #73 follow-on now records VC authority keys in a role-separate
Compact ledger map. Policy-bound maintainer signatures govern registration,
suspension, revocation, and atomic rotation; the old key becomes retired and
the successor current at one logical sequence, with zero registry overlap.
Historical records and predecessor IDs remain queryable. The registry
computes the seven-field VC authority domain from the committed registry ID
and its actual `kernel.self().bytes`, not a caller-supplied registry address.
Signer-side `createQuorumGatedVcAuthoritySigner` now requires an independent
current finalized authority-key reader and compares key ID, DID/method,
network, consumer, domain, public key, policy commitment, and effective
sequence before key custody. The reader interface is not itself a network
finality implementation; tests inject a fixture reader. Numeric contract
policy versions are distinct from semantic decision labels such as `v2`, so
the trusted reader must verify numeric current-policy currency.

Local timing: a full 64-circuit proving-key build took roughly 22 minutes;
`compact:light` generated simulator code in about one second, focused key
tests in two to three seconds, the contract suite in about 12 seconds, and
`./run.sh --light` in about 44 seconds. The first signing mismatch exposed a
simulator fixture bug: it regenerated `sampleContractAddress()` after each
circuit, making any `kernel.self()`-bound action appear to change deployment.
The simulator now holds one address for its lifetime. Use focused tests plus
`compact:light` for contract iteration and the full proving build only after
freezing the contract batch. PR #183's earlier Milestone Light timeout was a
TRQP test crossing Vitest's default five seconds under parallel CI load; a
targeted 20-second bound passed locally and on the rerun without weakening
assertions.

The #184 final-head review exposed a missing authority-DID freshness check:
the signer compared a governed method commitment with its pinned configuration
but did not re-read the authority's current DID document. The local signer now
uses the authenticated DID reader a second time, requires a live native
JubJub assertion method with the expected controller and public key, and
refuses key custody on removal, deactivation, relationship loss, or key
substitution. Published DID 0.7.0 JWK encoding differs from the newer source
checkout, so the comparison uses the installed package's public coordinate
codec rather than a copied conversion. The review's separate claim that the
controller comparison used two pinned values was false; the code already
compared request and pinned addresses, and a negative regression test confirms
it. A fresh 65-circuit proving build plus full integration passed before the
TypeScript-only DID check; focused, light, and fast integration gates passed
after it. Production finality and custody implementations remain open.

The next local #73 slice replaced the hand-built VC authority-key record in
the composed consumer test with a key registered by a 2-of-3 policy-bound
action in the Compact simulator. The signer reads that actual record, and a
governed suspension stops subsequent signing. Registration now uses
`prepareVcAuthorityKeyRegistration`: it checks canonical Midnight DID,
absolute method, network, consumer address, and exact registry ID/address
preimages before constructing the quorum-signed Compact payload. The helper
copies caller-owned key and commitment values so a prepared action cannot
drift through later input mutation. Focused tests took about 3.5 seconds,
integration-light about 25 seconds, and the broad light gate about 45 seconds,
primarily in existing API/CLI tests. A first local GPG commit returned a bad
verification result despite a successful signing command; it was replaced
before publication, and both retained commits verify as good with DCO.
Simulator ledger reads and action preparation do not establish production
network finality, durable consumer deployment, or governed key custody.

The signer reader now returns one `FinalizedVcAuthorityState` observation
instead of a standalone key record. The gate compares the observed registry ID
commitment and current policy commitment with the pinned registry and verified
decision, and requires the current key's numeric policy version to equal the
same observation's current numeric policy version. This closes the positive
but stale-version path without treating a semantic policy label as a contract
version. The simulator fixture supplies synchronous ledger state and negative
tests for missing, substituted, and stale observations. A production adapter
must still authenticate the exact contract and network finality; the typed
observation alone is not proof.

The #58 issuer-journey follow-on uses one applicant Midnight DID for both the
application VP and subsequent issuer assertion. The fixture DID state now
supports distinct native JubJub authentication and assertion method lists:
`#auth-1` signs the holder presentation and `#assertion-1` is available for
credential issuance. Cross-relationship resolution fails, and duplicate
method IDs with conflicting keys are rejected. This prevents a demo from
using an unrelated issuer DID or implicitly authorizing the holder key to
issue credentials. The local governed demo now carries the accepted issuer VP
through HTTP proposal and 2-of-3 approval to an active epoch, obtains a
schema-scoped signer descriptor with a governed VC authority signature, and
installs it in the compiled Compact VC consumer. That consumer accepts a VC
signed by the same DID's assertion key and rejects wrong schema and forged
signature. The authority and DID observations are simulator fixtures; this is
not a network-finality adapter or an arbitrary uploaded-credential verifier.

The #78 verifier follow-on reuses that decision evidence and VC authority gate
with the applicant DID's `#auth-1` relationship. Its governed demo installs a
verifier descriptor in a separate compiled consumer and proves an exact signed
request profile. Wrong-profile and forged request signatures fail. The request
decision does not replace independent holder VP or issuer trust evaluation.
The field-specific #78 checks sign altered request commitments under the
verifier's valid key and prove that excess attributes, predicates, changed
purpose, and increased disclosure still fail against the approved descriptor.

The issuer lifecycle follow-on adds an explicit inactive decision-evidence
reader for `suspended` and `revoked`. The default reader remains active-only.
The authority signer independently rechecks the selected inactive state,
current grant lifecycle root, policy, epoch quorum and DID method before
signing a monotonic VC descriptor update. The simulator demo installs active,
suspended, and revoked descriptors in order and confirms that the issuer proof
fails after the inactive updates. This proves local propagation only; a live
consumer needs an authenticated relayer/finality adapter and can be stale
until it receives the newer decision.

The #78 verifier lifecycle path now uses the same explicit inactive evidence
reader and authority signer, but checks `assertVerifierRequestAuthorized` after
each update rather than the issuer VC proof. The governed demo rejects the
previous request at suspended/revoked state, stale descriptor replay, and
fixture-signed reactivation after revocation. The same trust limitation holds:
these reads and relayer deliveries are simulator fixtures, not production
network-finality observations.

The UC-14 relying-party check now derives the auditor composite resource ID
from the full canonical audit request scope and verifies the public bundle
against a caller-authenticated epoch context. Its result contains mandate
identifiers and commitments only. The simulator client and HTTP-governed demo
reject changed audit purpose, cross-role evidence, and suspended/revoked
mandates. Disclosure policy, holder consent, and data exchange remain outside
the trust registry; an active grant is not blanket access.

The #78 recognition boundary is now exercised against the actual active
recognition evidence: the client accepts it as recognition but refuses to
interpret it as issuer or verifier authorization. The Compact simulator also
rejects the recognized authority DID as a local issuer and finds no local
maintainer membership for that DID. The governed HTTP demo repeats the issuer
and maintainer negatives. Recognition remains a scoped external-registry
statement, not transitive local membership; these are simulator checks, not
proof of another registry's independent accreditation process.

The #78 maintainer signed-journey fixture now tests a live threshold revision
from 2 to 3 after onboarding. Two votes fail without consuming a governance
sequence; three active votes succeed. After emergency suspension of the new
maintainer, its key cannot satisfy the revised quorum, while the three
remaining active maintainers can. The governed demo exports the policy-version
transition and event hashes; the existing last-active-maintainer test remains
separate. This does not introduce production key custody or relayer finality.

The #78 governed demo now emits an actor evidence table for issuer, verifier,
auditor, recognition, and maintainer. Each row includes policy version, an
epoch ID with its source, two activation signer key IDs, and the asserted
active outcome. The four public authorization/recognition rows use the epoch
from each verified record-specific bundle. The maintainer row uses an active
membership observation and its then-current snapshot epoch; it must not be
misrepresented as a public authorization bundle. No VP body, claim, private
key, or signature bytes are exported in this table.

The #59 local public-client slice exports the signed mutation envelope from
the API schema and uses it in both applicant-portal and admin-console clients.
Each client fetches the no-cache workspace context and forwards an externally
signed intent without handling a private key. The existing signed-workspace
demo now drives issuer submission, approval, activation, suspension, and two
epoch publications through those clients, then compares public temporal trust
with TRQP decision and inclusion evidence. Both query paths deny at the
suspension instant while retaining the prior active-time decision. Stale
context, invalid transition, replay, and invalid signature return structured
problems. A second process holds the shared local workspace lock during a
signed approval; the API returns 409 without consuming the intent, and the
same intent succeeds after release. The static applicant and admin pages now
load fresh signing context and accept externally signed envelopes. Their
DOM-handler tests cover the accepted path and stale context; real-browser
signed-intent smoke remains open acceptance work under #59. This fixture is
not a distributed multi-writer or live-network finality test.

The local #60 adversarial matrix branch was stacked on the signed-client
journey without rewriting its seven signed commits. Its governed demo now
records temporal API decisions for issuer, verifier, auditor, and recognition,
plus issuer TRQP parity at activation, suspension, revocation, and historical
active instants. The `tr-adversarial-matrix-v1` report still documents uncovered
combinations in `docs/plans/adversarial-matrix-coverage.md`; simulator outcomes
are not claims of network finality.
The issuer proposal API now has a matrix case for a correctly signed, admitted
receipt whose evidence has expired under the virtual evidence clock. The test
restores the original accepted fixture after asserting the exact governed
proposal rejection, so downstream successful decisions remain unchanged.

The local #78 accreditation composition branch now joins real Midnight DID
authority assertion, independent accreditor VC signature, and authority VP
signature under one recognition challenge. The authority signs a canonical
commitment to the exact VP submission, which is computable before registry
evaluation; it does not sign the later status decision. After checking the
governed tuple, DID relationships, fixture-pinned accreditation anchor, and
fixture status source, the registry combines both verified evidence commitments
and consumes the challenge once. The governed demo passes this combined hash
through the Compact recognition proposal and checks the public evidence bundle
and TRQP evidence projection retain it. The assertion field is `accreditationSubmissionCommitment`;
`evidenceCommitment` names the separate post-verification output. This is not
yet public accredited-recognition intake: anchor/status provisioning is still
fixture-only. Local `./run.sh --light`, `./run.sh integration --light`, and
`pnpm audit --audit-level low` passed after the naming change. Run light and
integration sequentially in one worktree because they share generated outputs;
reserve fresh proving-key generation for a coherent publication checkpoint.

The next local #78 slice binds recognition accreditor anchors into the
canonical governance policy content preimage. The simulator obtains a 2-of-2
maintainer quorum for a policy revision, reads the resulting Compact policy
commitment, and resolves the exact external-registry/resource anchor only when
the record hashes to that current commitment and both policy and anchor windows
are active. The private composed challenge no longer accepts a raw anchor:
it resolves the anchor from a policy record and the current ledger commitment
before VC/VP verification. The joined demo rejects stale policy commitments,
then binds the verified result to Compact, public API, and TRQP evidence.
Current simulator reuse of the threshold-policy revision circuit retains the
thresholds while changing policy content; a dedicated anchor-management
action and production policy reader remain open. Status verification still
uses a fixture source, so no public accredited-recognition route is mounted.

The subsequent local #78 slice replaces the default unsigned fixture status
decision with a five-minute, challenge-bound status attestation signed by the
policy-pinned status authority's Midnight DID assertion key. The verifier
checks registry, method, status handle, nonce hash, observation time, signature,
and current DID state version; the signed attestation commitment is included
in the redacted evidence. Tampered, replayed, revoked, substituted, and
future-dated status cases fail in focused tests, and the joined demo passes.
The fetcher is still a deterministic fixture, not a live status-registry
ledger reader. A trustworthy production fetcher and independent status-ledger
evidence remain necessary before public accredited-recognition intake.

An opt-in private `recognition-evidence` HTTP port now exposes the joined
challenge and signed accreditation verification to an authenticated local
caller. The host injects the current governed policy commitment, DID resolver,
and signed-status source; no policy or status decision is accepted from the
request body. Challenge issuance and submission reject stale policy, proof
failures do not spend the nonce, and successful verification returns only a
redacted commitment and expiry. The route is disabled without a trusted port
and is not mounted by the CLI. It does not persist a receipt or authorize a
Compact proposal; those are separate production admission requirements.

The next local #78 slice adds a private, opt-in recognition admission store.
It persists only a redacted receipt and challenge hashes in one private file;
under the configured governance-workspace writer lock, acceptance rereads the
active policy and atomically replaces the challenge with that receipt. A
private authenticated recovery route handles a lost HTTP response. It rejects
separate challenge and receipt stores, stale policy at the final read, duplicate
recognition IDs, and concurrent replays. The host must use the exact same
workspace lock path as all policy writers. A receipt is not a Compact proposal
grant: proposal-time policy/current-record validation, production DID/status
readers, and a live network finality source remain open.

The preceding accreditation branch bound the current governance commitment
into the verified VP evidence hash and reread the governed anchor before
challenge consumption. It passed fresh full integration (94 integration
tests and governed demos), local light (20/20), and audit; the initial Compact
proving-key generation took about 22 minutes. For TypeScript-only iterations,
package typechecks and focused tests take seconds and integration-light avoids
that proving cost. A maintainer simulator test passed alone in 1.6 seconds but
timed out twice at the five-second default under the parallel integration
suite; its explicit 15-second bound restored the full integration-light lane
without weakening assertions.

The proposal-admission gate is now available as a typed API helper. It
validates the exact accepted receipt ID, challenge binding and recognition
identity, combined evidence commitment, expiry, current governed policy
commitment, and exact active accreditor anchor while holding the governance
workspace writer lock through the caller's execution callback. Four focused
tests cover positive lock ownership and wrong receipt, evidence, scope,
expiry, anchor, and policy. `./run.sh --light` passed (20/20 tasks, 162 API
tests). The helper is not wired to a public proposal route or ledger adapter;
its callback must perform fresh Compact signature, quorum, sequence, and
record-state checks without reacquiring the lock. A private file receipt is
not a grant or distributed finality. This slice took one full light run of
about 41 seconds; avoid repeatedly running full integration with fresh
proving keys for TypeScript-only changes. The test fixture initially used an
invalid policy without all four decision families; reuse a valid shared
policy fixture in future tests to avoid schema-debugging iterations.

An opt-in governed recognition prepare/submit HTTP port now composes this
receipt gate with the simulator's current Compact proposal context, 2-of-3
maintainer signatures, and independent registered evidence-verifier key.
The private file-backed test verifies wrong receipt/evidence, raw VP fields,
insufficient quorum, wrong verifier key, stale context, replay, and no local
issuer grant. Both intake/proposal ports must use the same store. A second
opinion caught two P1 gaps: the binding was initially read before the
governance lock, and legacy workspace recognition-submit routes could create
a proposal without accreditation. The binding is now read inside the lock and
passed unchanged to the trusted adapter; signed and unsafe workspace submit
routes reject recognition creation while this port is configured. The
simulator test clock must advance beyond receipt acceptance time, because
the file store accounts for lock elapsed time; a frozen instant passed alone
but failed in the full integration suite. This is a test-clock issue, not a
reason to weaken the receipt's future-acceptance guard. Production status
ledger evidence, distributed admission/finality, and recovery after uncertain
network submission remain open.

The follow-on local proposal-resolution helper reads the immutable Compact
proposal-evidence map for issuer, verifier, auditor, and maintainer roles from
an injected finalized ledger view. HTTP recovery tests no longer rely on an
in-memory `proposed` flag. A deliberately stale finalized view returns
`not-observed` even after the simulator has accepted a write; only advancing
that view exposes the event. This narrows the recovery boundary but does not
provide a live-network finality reader or make a negative lookup retry-safe.

The joined private HTTP test now carries a signed Midnight accreditation VC/VP
and separate authority DID assertion through one-use challenge acceptance,
private receipt recovery, and the governed Compact recognition proposal. It
compares the exact redacted evidence commitment with the resulting ledger
record and confirms recognition did not grant local issuer authorization.
Separate integration tests exercise external 2-of-3 quorum negatives. The
joined test uses the simulator's one-signer policy because its short-lived VP
fixture window precedes later multi-action policy-effective times. Avoid
comparing parsed binding objects by reference (Zod clones them) or comparing
`Buffer` and `Uint8Array` objects directly; compare canonical binding hashes
and normalized hex commitments instead.

The local proposal recovery branch now covers all five proposal roles,
including recognition. The recognition HTTP resolver is private: it checks
the authority session, accepted accreditation receipt, canonical challenge
binding, and exact evidence commitment before reading an injected finalized
Compact view. It returns `not-observed` for stale/absent finalized records,
never an automatic retry signal. The applicant portal exposes this lookup
only on its existing authenticated same-origin private host; the admin
console remains maintainer-only. The portal sends receipt ID and evidence
commitment without storing raw VP, session material, or receipt inputs in
browser storage. Negative tests cover receipt substitution, denied access,
stale finality, ledger evidence mismatch, reader outage, and cross-origin UI
disablement. `./run.sh --light` passed (20/20 tasks) and `pnpm audit
--audit-level low` reported no vulnerabilities. A production finalized-ledger
reader and distributed admission store remain open; simulator confirmation
must not be described as network finality.

The applicant portal now wires the entire private recognition accreditation
interaction: one-use challenge, external authority assertion plus VP submission,
accepted-receipt recovery, and finalized-proposal lookup. The portal never
signs for the authority. It rejects a submission with the wrong challenge
nonce before sending, clears raw VP JSON after submit, and invalidates the
challenge and receipt view when the recognition ID changes. All four calls use
same-origin credentials and no-store; the UI disables them when the configured
API is cross-origin. The server remains responsible for actual DID assertion,
VC/VP/status, accreditor policy, and receipt verification. Focused portal
tests and `./run.sh --light` pass (20/20), docs build passes, and audit is
clean. The demo host still needs a real authenticated recognition port and
finality reader before this can be presented as live-network onboarding.

The next local #79 slice adds an optional public `GET
/v1/decision-evidence/{role}/{id}` query for issuer and verifier bundles.
The server accepts only structurally valid `tr-decision-evidence-v1` from an
injected finalized source, checks exact role, authorization ID, and registry
identity, and otherwise returns 404/503 without falling back to a mutable
snapshot. The response explicitly says `verification: client-required`.
`verifyDecisionEvidenceFromApi` then fetches over HTTPS or loopback HTTP and
composes the existing trusted-reader verifier. HTTP source trust is not an
accepted epoch, current grant, DID-state proof, or descriptor authority.
Focused tests reject missing/malformed/wrong-registry source data and absent
DID readers. Full light validation passed (20/20 tasks, about 57 seconds with
downstream client/API tests), docs build passed, and audit was clean. A real
finalized decision-evidence source remains a separate production integration.

The local #79 client builder `buildDecisionEvidenceClaim` now assembles issuer
and verifier decision-evidence claims from the evidence bundle, an independently
supplied accepted epoch, publication signatures, resolved DID method, scope,
and event references. It derives the policy snapshot and inclusion proof,
rejects other roles, and checks accepted-epoch, grant-inclusion, and policy
commitment consistency before returning. It does not authenticate the accepted
epoch, DID observation, maintainer keys, or current decision point; callers
must still use the trusted-reader verifier. Simulator tests exercise both roles
and reject a different accepted root or grant leaf.

The follow-on VC adapter `createVcSignerCandidateFromApi` connects the optional
public evidence query to the existing trusted-reader VC descriptor conversion.
It accepts only the client-required API envelope and independently checks the
finalized registry decision and DID state before constructing a descriptor.
The simulator journey covers valid API delivery, a false server-verification
claim, and an unavailable finalized reader. This is a compositional test, not
a live-network finalized-reader implementation.

The next local #73 slice connects verified API evidence to authority proof
issuance through `issueVcSignerAuthorizationFromApi`. It reuses pinned-domain
checks and proof verification, while the separately gated signer rechecks the
governed authority key before key custody. A simulator test verifies the
resulting proof and confirms missing finalized registry state cannot call the
signer. Schnorr proof bytes are not expected to be identical across valid
signings of the same decision. Production finality and authority key custody
remain open.

The governed simulator demo now exercises the optional public decision-evidence
query for both issuer and verifier, requires its `client-required` envelope,
verifies the claim against separately supplied simulator ledger/DID readers,
obtains a gated VC authority proof, and installs it in the compiled consumer.
The demo reader re-reads current ledger status and action sequence for every
verification; after suspension and revocation it rejects the previously served
active API claim before issuing an inactive transition proof.
The demo uses `buildDecisionEvidenceClaim` rather than duplicating envelope
assembly. Its injected evidence source and reader state are simulator fixtures;
they must not be described as a production finalized-ledger adapter. The
focused governed demo passes locally in about 14 seconds.

The next local #79/#73 slice introduces `createCompactLedgerDecisionReaders`.
It checks accepted epoch commitments against a supplied finalized Compact
ledger view, uses the current issuer/verifier on-chain scope index and record,
and derives current policy/status/action sequence from that same view. The
client reader now passes the claimed grant ID only as a lookup hint. A later
unrelated epoch is allowed only if the claimed epoch remains within its
sequence window and current policy and exact grant still match. Focused tests
reject a changed epoch root, current policy, wrong role, wrong grant ID, and
wrong verifier resource. The governed demo uses this projection and still
rejects four stale active API claims after suspend/revoke. This adapter does
not authenticate finality, historic signer sets, off-ledger time, or DID state;
the embedding network host must supply those independently.

The local source slice adds `createVerifiedDecisionEvidenceSource`: the
optional API route now has a reusable implementation that assembles a claim
from an indexed bundle, checks exact role/authorization ID, and verifies it
against a separately supplied reader port before serving. Consumers still
receive `client-required` and must reverify independently. The governed demo
uses this source for issuer and verifier; after either role is suspended or
revoked, the source returns an unavailable result (HTTP 503) rather than
serving its earlier active claim. Simulator fixtures remain the only current
source of ledger/DID observations, not production network finality.

The source now takes the expected registry, contract, DID, role, and scope
selection from the same trusted host context as its finalized readers. An
indexed candidate contains only builder input and cannot select a different
trust domain for its own verification. A negative simulator case substitutes
the trusted registry selection and fails before the claim is served. This is
still a host-port contract: the host must independently authenticate the
selection and reader provenance, and public consumers must verify again.

The simulator proves a pending proposal can be denied using the existing
quorum-governed archive circuit for issuer, verifier, auditor, recognition,
and maintainer membership. A live proposal blocks a duplicate scope or DID;
after archival a fresh ID can reuse it while the original ledger record stays
archived. A separate two-maintainer case proves one signer cannot archive a
pending issuer once the ordinary threshold is two. This resolves the spec's
earlier ambiguity without inventing an unreleased `rejected` status. Archival
does not record an off-chain denial reason.

The local governed-action API and admin console now expose `archive` alongside
the other externally signed lifecycle decisions. The simulator harness routes
the same prepared signer context to the role-specific Compact archive circuit
for all five roles; an HTTP issuer denial and a recognition denial both reject
insufficient signatures or replay. The domain parser accepts an archived
proposal without invented approval or activation timestamps, while retaining
timestamp requirements for records that progressed further. OpenAPI and the
endpoint guide describe this as a signed terminal denial, not a trust grant.
The follow-on conformance test exercises external quorum archival for proposed
issuer, verifier, auditor, and maintainer records, including one-signer and
replay rejection. Recognition has its own externally signed denial test.
The admin console also exposes the Compact-permitted archive action for an
already active record rather than requiring an artificial revoke first.
The next local HTTP/query test closes the denial observation loop. Both an
issuer and an external recognition are archived through external signatures,
then exposed as historical evidence without approval or activation timestamps.
Default client verification rejects both as non-active; explicit historical
verification succeeds, and timestamped query evaluation is never trusted.
Recognition does not create a local issuer entry.
The governed demo now prints `proposalDenial`: it rejects a duplicate live
scope and insufficient archive quorum, archives the pending issuer under two
external JubJub signatures, proves the old evidence cannot authorize current
trust, and permits a fresh ID to propose the same scope. Its fixture is a
simulator scenario, not network-finalized evidence or a production denial API.
Private pending-registration state previously had no terminal transition, so
an archived proposal could leave its scope reserved forever. The local
admission stores now expose host-only `recordArchived`, requiring a verifier
callback for an exact original binding and archived event. It preserves prior
application IDs and consumed nonces, disables the old pending VP binding,
and accepts a new DID-signed application plus authorization ID for the same
scope. The host must authenticate Compact finality; the packaged CLI still
does not wire a production registration or governed-action port.

The local application VP fixture now uses a DID-signed status attestation by
default rather than an unsigned boolean decision. Its verifier pins the
fixture status registry and authority method, binds credential root, status
handle, and one-use challenge, then checks assertion-key signature, DID state,
active flag, and five-minute freshness. The `statusDecision` fixture override
remains only for adversarial tests. This improves #76 intake evidence but does
not verify a live status-registry root or network finality; no public
non-revocation claim follows from the fixture. Focused integration tests cover
re-signed substitutions and unsigned tampering.
