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
