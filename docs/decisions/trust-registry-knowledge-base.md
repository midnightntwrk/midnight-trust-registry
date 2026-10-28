# Trust Registry Knowledge Base

Status: working knowledge snapshot
Updated: 2026-10-27

## Purpose

This document is the repo-local execution snapshot for
`midnight-trust-registry`.

It records the current code surface, validation baseline, dependency posture,
backlog posture, and the next implementation direction. It is intentionally
shorter-lived and more action-oriented than the normative specification.

## October 27 2026 Latest Local Qualification Handoff

- Signed/DCO source `779bfd1d` has a verified v6 bundle (inventory SHA-256
  `66f8d669eb2b06e90f3444c27a0c69f5368f007568f28b757e156229c7e6154d`)
  with ten packages, six images, and 18 proof-parameter files. Packed actor
  and VC consumer checks passed. The private `wizard-779bfd1` setup matched
  the three ledger images and passed bridge-scoped HTTP/DNS canary denial.
  A pre-deployment restart retained the node-reported checkpoint hash as the
  height advanced from 49 to 61. These are install and pre-deployment checks,
  not deployed standalone actor E2E.
- The untrusted node-derived genesis candidate and proposed pin are retained
  only in the private setup packet. The prerequisite checker stopped at
  `genesisApproved` (exit 2); the dedicated containers are stopped and their
  volumes preserved. No contract deployment, independently authenticated
  finality, approved maintenance transition, offline actor run, or deployed
  restore occurred. This knowledge-base change makes the bundle historical
  relative to the current source tree; do not present it as a final-head RC.
- Freeze the intended release source before asking the human reviewer to
  authenticate the actual chain specification and sign exact wizard approval
  bytes. A chat approval, node-reported candidate, or proposed pin cannot
  substitute for that signature. Approve the release committee roster and
  threshold separately. The [acceptance map](../plans/milestone-0.1.0-acceptance-map.md)
  records the packet digests and remaining gates.

## October 27 2026 Ambiguous Proposal Recovery Boundary

- The local `#220` recovery work can now produce a read-only, versioned v3
  candidate and verify a detached reviewer signature over a decision bound to
  that exact candidate and its retained finality-evidence bytes. The candidate
  includes the last observed governance action's kind and payload hash. A
  conflicting action is considered only when the observed action count is
  exactly one beyond the reserved sequence; a later count or the same payload
  remains inconclusive. Compact regression tests also cover rejection of an
  old proposal signature after its action sequence is consumed.
- This is an audit and review handoff, **not** an authenticated proof of
  finality or non-inclusion. The decision does not mutate the proposal journal,
  permit retry, deploy a contract, or close #220. A release-capable recovery
  path still needs an independently reviewed finality policy, a durable
  tombstone, a locked state transition with restart/replay tests, and human
  security review. Do not turn a null indexer result or elapsed time into
  permission to resubmit.

## October 27 2026 Installer And E2E Boundary

- The installer now uses strictly typechecked policies for its base Compose
  project, three service roles, and digest-pinned image references, plus the
  install inventory's exact ledger image roles and distinct archive pins.
  Malformed YAML shapes, extra or duplicate roles, duplicate archives, and
  floating image tags fail the focused tests. The install verifier still
  checks the Compose file's exact bytes and archive contents against the
  inventory. This proves a staged bundle constraint, not Docker's merged
  runtime topology or a deployed ledger. The rest of the bundle verifier and
  wizard I/O remain on the tracked non-strict type-migration list (#229).
- The local-only 0.1.0 E2E acceptance procedure remains
  [standalone-local-journey](../guide/standalone-local-journey.md). No actor
  journey has been recorded against a deployed, independently finalized
  standalone contract with egress denied. Do not relabel simulator, Playwright,
  packed-consumer, or injected-provider checks as that evidence (#219).
- The installed `@midnight-ntwrk/credential-compact` package does not expose a
  live status-authority verifier. The sibling status-registry package is
  private, so this repository cannot supply a supported VC-owned adapter by
  importing its source. #90 remains open until a versioned, consumable VC
  package and approved verification profile are available. A fixture status
  response must not be promoted into production non-revocation evidence.
- The real signed genesis/committee approval, authenticated finality and
  deployment readback, audited ambiguous-proposal recovery (#220), egress-denied
  actor journeys, deployed restart/restore, and independent human security
  review (#232) still gate the local RC. #198 stays draft; Preprod and Helm are
  deferred or optional, respectively.
- The merged #210 API code already uses a production Compact ledger type and
  distinguishes explicit recognition denial (403) from unavailable
  authorization dependencies (503). A later local #215 slice replaces the
  remaining five-way proposal-evidence bind/verify ternaries with one
  exhaustively typed role table. Its Compact-backed observation test covers
  all five roles; #215 remains open until this local slice is independently
  reviewed and merged.

## October 24 2026 API Egress Probe Checkpoint

The unpublished local API egress probe now uses one disposable bridge canary
for both TCP and synthetic DNS/UDP. Same-image positive controls before and
after the running API attempt make a failed route check meaningful without
requiring public Internet access. Its unit tests and a localhost DNS protocol
test pass, but no approved API is running on the b17 pre-deployment stack.
This is probe implementation, not observed offline API or actor evidence:
Docker embedded DNS recursion, other protocols, wallet/browser paths, and
independent finality remain unqualified. Kubernetes/Helm are optional and
not 0.1.0 release criteria.

## October 24 2026 Exact-Source b18 Staging Checkpoint

- The signed `8cd1de8` source has a separately verified v6 install bundle:
  inventory SHA-256 `10bfed0f812bb6f828d04609b40f09c33a1aa8034ad35148a801c3348ac13fa4`,
  ten packed packages, six OCI archives, and 18 proof-parameter files.
  Its packed API contains the current proposal-quorum preflight and recovery
  candidate modules. This establishes install-byte integrity, not deployment.
- The dedicated b18 node/indexer/prover bridge matched the pinned images and
  Compose bytes and passed a bridge-limited canary egress probe. The private
  node-reported genesis candidate and proposed pin remain untrusted; the
  temporary install relay was removed. The b17 and b18 containers are stopped
  with their volumes and private evidence preserved. No contract, API, or
  portal has been deployed to b18.
- The b18 private review packet records the source, inventory, candidate, and
  pin digests for human review. The reviewer must independently verify the
  chain-spec/genesis reference and detached-sign the later wizard-generated
  approval bytes. Neither a chat approval nor this packet closes that gate.
  #220 recovery, live finalized readback, maintenance approval, offline actor
  journeys, restore, and independent security review remain open.

## October 24 2026 Local Issuer Reservation Checkpoint

- The API now checks action-scoped maintainer quorum and current registered key
  state against its supplied finalized ledger before reserving any of the five
  governed proposal roles. A synthetic local-ledger HTTP test proves that an
  insufficient quorum or unavailable reader leaves the bound file journal
  untouched, and that finalized issuer resolve accepts the verified richer
  evidence snapshot. The supplied reader is not yet independently qualified;
  this is not real local-ledger deployment evidence or a #220 recovery approval.
- The local issuer SDK handoff now carries its prepared action sequence, kind,
  and payload hash into the private one-attempt journal. A missing local
  compiled circuit fails before journal reservation. The real file-journal
  integration test verifies that both submitted and ambiguous attempts retain
  context across reopen without a second SDK submission.
- The SDK, finalized reader, and provider identity are mocked in these tests.
  Persisted context is audit evidence, not proof of non-inclusion or authority
  to abandon a reservation. #220 remains a local RC blocker until the
  original action's inability to execute is independently authenticated and
  an operator-reviewed durable decision is security-reviewed. #219 still
  needs a real deployed API and offline actor journeys; Helm is optional.
- New reservations in a deployment-bound proposal journal must carry the
  prepared action sequence, kind, and payload hash. Missing context fails
  before any journal write or SDK call. Older context-free entries remain
  readable and blocking, not eligible for an inferred recovery decision.

## October 19 2026 Local Journal Recovery Checkpoint

- The unpublished `codex/trust-registry-proposal-journal-recovery` branch adds
  operator-triggered rotation for the private proposal journal. Observed
  attempts move to bounded, digest-checked segments; reserved and submitted
  attempts remain writable, and all historical role/authorization IDs remain
  non-submittable. Capacity metrics expose counts and projected receipt bytes
  without exposing proposal evidence. Focused tests cover restart, lost
  responses, corrupt archives, concurrent writers, and byte-boundary refusal.
- Rotation now requires a caller-supplied independently finalized reader to
  recheck every observed row before a manifest change. An absent, conflicting,
  or unavailable read stops rotation without dropping the attempt. This is a
  local trusted-storage protocol, not a distributed lock or a network-finality
  implementation. Issue #193 stays open for cross-host coordination,
  authenticated recovery/export, and full integration qualification. Public
  deployment and 0.1.0 promotion remain separately gated by #200/#213 and
  the concrete VC status-authority dependency in #90.
- The stacked local #67 preflight work retains accepted application evidence
  for each of the four applicant roles only after a successful Compact
  proposal. Before preparing approval or activation signatures, the simulator
  harness rechecks the current evidence policy and the proposal commitment.
  A governed verifier-key rotation retires the old fixture key: pending
  applications cannot prepare approval signatures, while fresh applications
  use the replacement key across all four roles. The fixture verifier also
  checks the governed key status and policy at signature admission, so
  suspended or revoked keys fail before proposal or decision signing. This
  closes the reported stale-policy signing-preparation gap in the simulator,
  but does not substitute for production DID/key authority or finalized-ledger reads.
- The next local #67 slice adds strict prepare/submit HTTP requests for
  evidence-verifier key rotation, suspension, and revocation. The submitted
  context must match a fresh Compact preparation before external maintainer
  signatures are admitted. The injected port remains responsible for
  replacement DID-key authentication and authorized finalized-ledger reads;
  the Compact-backed integration test uses the simulator port only. This is
  not a public-network authority adapter and does not close #67.
- A further local #67 adapter checks the active Compact evidence-verifier
  record against one resolved Midnight DID assertion method, including the
  expected network, DID/method commitments, prime-order public key, and DID
  version floor. Rotation tests reject the old DID method, accept the new one,
  and reject a suspended registry key. Callers still need a trusted finalized
  DID reader and must invoke the check at both prepare and submit; this local
  adapter is not proof of public-network finality.
- The local #67 `createDidBoundEvidenceVerifierPolicyPort` wrapper now uses a
  trusted candidate reader and DID resolver to check registration and rotation
  at both prepare and execution, including the exact Compact payload hash.
  Compact-backed tests cover a valid rotation, post-prepare DID-key change,
  and mismatched replacement. The host must still supply independently
  finalized DID/registry reads and serialize the final check with execution;
  the wrapper alone is not a public-network authority adapter.

## October 15 2026 Delivery Checkpoint

- PR #192 merged to `milestone-0.1.0` at `62de1aff`. It adds exact-scope
  historical evidence exports, independent anchored decision verification,
  portal lookups, TRQP evidence verification, and role journey coverage. The
  API's historical status remains a claim until a caller verifies its bundle
  against independently obtained anchors. The sibling VC status-registry
  package is private; the current DID-signed status attestation is not a
  general VC non-revocation proof.
- The local `codex/trust-registry-proposal-handoff` stack adds a private
  file-backed one-shot submission journal for issuer, verifier, auditor, and
  maintainer governed proposals. It reserves before Compact execution and
  never assumes a dropped response means failure. Cryptographic vote preflight
  rejects malformed or duplicate maintainer signatures before reservation;
  active membership, quorum, and evidence-verifier authority remain Compact
  decisions. Issue #193 tracks bounded journal rotation and recovery after
  the three planned review rounds.
- The admin console clears prepared context and pasted signatures after an
  ambiguous submit while retaining the redacted evidence and target needed
  for manual receipt recovery. Four Playwright journeys use the real admin
  bundle, API, journal, and Compact simulator to observe successful issuer,
  verifier, auditor, and maintainer proposals whose HTTP responses were lost,
  then reconcile from a later simulator ledger view. Each first rejects a
  forged maintainer vote without reserving the journal or executing Compact.
  This exercises the local integration boundary, not Midnight network finality.
- At local signed head `b4b40f7`, `./run.sh --light` passed 20/20 tasks,
  `./run.sh integration` passed the 66-circuit build plus API/simulator suites
  and actor demos, `pnpm audit --audit-level low` found no vulnerabilities,
  and the full Playwright suite passed 9/9 once proof compilation had ended.
  The full run spent about 23 minutes primarily in `zkir compile-many` key
  generation; the 8.5 MiB ZKIR directory yielded more than 1.5 GiB of keys.
  Focused API/DOM/Chrome checks and cached light builds remain the practical
  inner loop; keep one full proving run per coherent publication batch.
- The stacked local #59 journey now serves all four signed membership demos
  from a fresh private file-backed operator workspace, not a memory API
  snapshot. Governed epoch publication projects the Compact result into the
  workspace file while holding its cross-process lock. A second process
  holding that lock causes 409 before Compact advances. Unsafe fixture
  mutation routes stay disabled. A separate read-only process then reopens
  the workspace and recovers the final epoch and the historical active/current
  revoked decisions for issuer, verifier, and auditor. A regression test found
  that projecting a missing per-grant historical epoch after an externally
  signed epoch could move Compact's latest pointer backward. The fixture now
  materializes grant evidence before preparing the signed epoch; the CLI
  projector preflights the required grant epochs and rejects a missing one
  before it can mutate the ledger after a signed publication. This
  closes one local-host gap but does not
  make admission plus governance atomic or establish network finality.

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
- The direct Compact boundary now rejects a changed issuer evidence hash,
  self-voted removal, and non-self removal below the configured threshold; API actions reject
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
check; replacement PR #91 removes it. On 2026-10-12, the operator clarified
that this temporary milestone branch does not need GitHub branch protection.
Its manual merge gates are green current-head CI and documented current-head
LLM review, internal or external. `CODEOWNERS` routes review but does not
require approval on the milestone branch. The earlier code-owner canary and
protection plan is superseded; `develop` and `main` remain human-controlled.

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

The next #76 boundary now requires issuer eligibility to return a full
status-policy binding rather than a boolean. `verifyApplicationVp` checks the
credential registry against that binding before status lookup and forwards the
same binding and challenge context. A reference adapter obtains it from
`verifyDecisionEvidenceWithTrustedReaders`, checking the active issuer DID,
assertion key, and registry. The host must still provide authenticated
finality-aware readers; the VP fixture remains deliberately non-governed.
The HTTP fixture exposed a live-nonce integration boundary: the local status
authority must sign the actual one-use challenge for the pinned credential
root, registry, and handle rather than reusing an attestation signed when the
fixture was constructed. Its deterministic fetcher now does that, and the
auditor apply -> VP HTTP test passes. Parallel Compact signer tests exceeded
Vitest's default five-second case limit under the repository integration
runner; the integration package now uses a 15-second per-case limit without
changing product timeouts. Full `./run.sh integration --light` passed after
both adjustments.
The #76/#79 composition now verifies a signed fixture credential and
presentation against the same Midnight DID assertion key as an active
simulator issuer decision. The status adapter consumes that decision's exact
policy binding and a challenge-specific status signature; a suspended current
grant fails before evidence issuance. The fixture supports a separate status
method under the issuer DID and a chosen DID state version solely for this
cross-surface local test. Production finality and status-registry root
verification remain open.

The redacted application evidence envelope now requires a
`statusDecisionCommitment` computed from the verified signed status statement,
observed authority DID state version, and full governed issuer status-policy
binding. This binds the status decision to
the evidence-verifier signature without publishing the private witness. The
admin console's strict envelope allowlist must be updated whenever a required
redacted field is added. The commitment is not an independently verifiable
non-revocation proof: a later auditor needs the retained signed statement,
authenticated historical DID state, and an appropriate status-registry trust
anchor. The local fixture has none of the latter network-finality guarantees.
The `verifyApplicationStatusDecisionWitness` helper revalidates the exact
private signed witness against the redacted commitment and an independently
obtained issuer status-policy binding and historical DID resolver. The demo
now retains the actual fetched fixture witness for each challenge; a prebuilt
copy of the same status statement was not sufficient because its Schnorr
signature bytes can differ. The public receipt still contains only hashes.

OpenID Federation authorization subordinate statements now carry the issuer
status-policy binding and its leaf commitment with the TR evidence bundle.
The adapter rejects a substituted binding and strips legacy unanchored status
hints. This is a publisher claim, not a trust decision: the relying party must
verify the bundle against an independent accepted epoch and current grant.
The consumer-side federation helper now correlates the signed issuer claim
with a separately verified decision-evidence claim. Its simulator test uses
real epoch publication signatures and a current-grant read; it rejects
publisher substitution, unrelated evidence, and a suspended current grant.
The embedding host must still establish federation-key provenance and network
finality for both registry and DID readers.

PR #191 review questioned whether an older issuer epoch could remain current
after a newer one was published. The first global-latest guard failed the
governed demo because simulator epochs are single-statement commitments: a
newer unrelated epoch does not supersede an unchanged issuer grant. The
Compact reader instead compares the selected epoch event root with the
current grant lifecycle root. A two-epoch regression accepts the unchanged
grant while its window is open and rejects the same epoch after that grant is
suspended. Production implementations still need an authenticated latest
applicable epoch index if policy requires rejecting duplicate publications
of an unchanged statement.

The native HTTP API now offers timestamped evidence export for authorization
and recognition, matching TRQP's archived-bundle selection. It evaluates the
record and selects its bundle from one snapshot, returns 404 for no matching
statement, and returns 424 when the statement exists without epoch-bound
evidence at that instant. The returned bundle remains a claim until independently
verified against an accepted epoch.

The native evidence response must report the *selected bundle's* epoch, not
the generic temporal query's latest epoch: an unrelated later publication can
overlap the same timestamp. The client now checks exact authorization or
recognition scope, independently anchored epoch/root/signature/inclusion,
and recomputed status at the requested instant. These helpers do not establish
that the supplied epoch was canonical in ledger history or that its signer
was authoritative; the caller must authenticate those inputs independently.
Simulator-backed negative tests cover root, signature, scope, and server status
substitution. Keep client tests that use the integration harness in the
integration package to avoid a client-to-integration dependency cycle.
Independent review of the native historical verifier found that recognition
`scope.context` was not selected, the statement `policyId` was not tied to the
proved bundle policy, and response entry/signer fields could contradict the
verified bundle. The client now rejects context substitution, enforces the
policy-ID link in the shared bundle verifier, and checks response fields for
consistency. Native recognition lookups accept an optional exact `scopeContext`
map; the consumer verifier treats an omitted context as an expectation of no
context. An independently authenticated canonical historical epoch selection
remains a host responsibility, not a guarantee of the API or bundle.
The applicant portal now exposes the native historical authorization export
for issuer, verifier, and auditor records. It preserves exact query inputs,
does not cache the POST response, rejects a different role/DID/resource/epoch,
and prominently labels the result as unverified. It deliberately does not
perform browser-side proof verification without an independently authenticated
historical ledger reader.
Native recognition lookup now compares the context map unconditionally:
omitted context selects only context-free records, never a context-bound
record by accident. The applicant portal has a parallel recognition evidence
panel, validates the request through the API schema, and labels its result as
unverified. This keeps API and UI exact-scope semantics aligned while
production historical epoch authentication remains outside the browser.
Independent review of this slice found that TRQP could no longer select a
context-qualified recognition once native selection became exact. The named
TRQP `context.scope_context` extension now reaches the same selector, and the
adapter checks it against attached evidence. Review also found that an array
could masquerade as a string map in the portal's context comparison; the
response shape is now validated before comparison. The portal additionally
requires registry ID and resource type so its result cannot hide wildcard
selection of those scope dimensions.
The signed issuer, verifier, and auditor simulator demos now use the live
timestamped evidence API after lifecycle changes and verify each response
against separately read epoch and maintainer records. A substituted scope or
epoch root fails. This caught an overly strict response consistency check:
the current record's `evidenceHash` changes for suspension/revocation while
the archived statement keeps its original evidence commitment. Compare the
stable identity, scope, policy, and status-binding fields across those records,
but authenticate the historical `evidenceHash` through its signed epoch and
Merkle inclusion proof instead. Production epoch finality remains a separate
host responsibility.
The governed simulator demo now queries native historical recognition evidence
after suspension and revocation, verifies the original active statement
against a separate simulator epoch/signer read, and rejects substituted
recognized-registry and epoch-root inputs. It is reference conformance, not a
network-finality claim or transitive issuer authorization.
The public client now composes native historical HTTP fetch and proof
verification for both authorization and recognition. The caller supplies a
separately authenticated epoch record, publication key, and registry
commitment; the HTTP response is never allowed to supply its own anchor.
Remote fetch requires HTTPS, loopback HTTP is local-only, redirects are
rejected, and `404`/`424` remain errors rather than negative decisions.
Canonical historical epoch selection and network finality remain external.
The integration package now projects historical verification context from a
host-authenticated Compact ledger view rather than requiring demo callers to
manually combine epoch and signer map reads. It rejects wrong contract format,
registry commitment, missing epoch, uncommitted policy root/version, and
inconsistent publication signer. Signed issuer/verifier/auditor and governed
recognition demos now use this projection and the native HTTP fetch-plus-proof
client. The simulator supplies the ledger and deterministic counter-to-time
mapping; a production host must supply an authenticated finalized view and
its own historical epoch-selection/time provenance.
The signed journeys derive expected statement epochs from Compact status
sequences, and the recognition demo captures its expected epoch from the local
simulator before accepting API evidence. Neither demo lets the API select its
own anchor. This is a local fixture boundary, not a network-finality proof.
TRQP evidence verification is now exercised against those same live API
journeys: issuer/verifier and recognition proof responses must match exact
requests, ledger-selected epoch anchors, and independently recomputed temporal
decisions. Recognition remains a distinct result, not a local authorization.

The UC-14 auditor mandate check now requires the independently read current
active ledger record to match the verified grant's ID, DID, exact request
resource, governed policy commitment, trust level, evidence hash, and lifecycle
event. A substituted active record therefore cannot revive a stale audit
mandate. Compact's `AuditorAuthorizationRecord.policyId` holds the governed
policy commitment, so compare it to the verified statement epoch's policy
root rather than hashing the human-readable policy ID. Focused client tests,
`./run.sh --light`, `./run.sh integration --light`, and the dependency audit
passed. This remains simulator-backed evidence, not Midnight network finality.

The sibling VC repository's status-registry package remains a private
prototype and explicitly lacks authenticated mutation and in-circuit live-root
proof. Do not copy or import it as a production solution for #76/#90. The
published VC core provides status-reference shape and commitment checks; a
governed status authority plus authenticated current-state adapter is still a
separate functional deliverable.

The #90 reference integration now has an HTTP source for its DID-signed
application status attestation. It POSTs only registry/handle/body-root and
challenge commitments to an operator-configured HTTPS endpoint and passes the
untrusted response through the existing governed issuer binding, DID method,
signature, active-status, and freshness verifier. A full VC/VP application
test accepts the active response, returns only a redacted decision commitment,
and rejects a re-signed revoked response; focused transport tests reject
substitution, stale answers, insecure endpoints, and outages. This is not a
general VC status registry, an independent live-root proof, or network
finality. `./run.sh --light`, `./run.sh integration --light`, `./run.sh docs`,
and `pnpm audit --audit-level low` passed on the local stack.

The #152 auditor applicant portal now prepares a canonical `apply` intent from
structured IDs, DID authentication method, and the complete audit request
scope. It derives the composite governed resource, asks the current API for
workspace/epoch and host evaluation time, generates a fresh nonce, and shows
the digest bytes to sign outside the browser. It posts only the returned
canonical JubJub signature with the prepared envelope; the host still checks
the DID method, revision, nonce, exact scope, and later one-use VP evidence.
The API mutation context now exposes `evaluatedAt` from its configured host
clock so the fixed-time simulator demo and applicant preparation agree. This
is not a Midnight consensus timestamp. Focused browser/domain/API tests,
`./run.sh --light`, `./run.sh integration --light`, docs build, and audit pass.
Keep #152 open until publication, exact-head CI, independent security review,
and the remaining production authentication/availability boundaries are met.

The loopback auditor-admission demo now uses that same portal preparation
helper for its signed application instead of hand-building a parallel intent.
Its API source exposes the read-only workspace context needed by the form but
rejects governance writes. A fixture-only CLI command signs the displayed
32-byte digest with the demo DID key; the HTTP smoke prepares a fresh
signature from the form helper, registers it through the real admission route,
and then verifies the one-use VP evidence path and negative cases. Schnorr
signatures are randomized, so compare the canonical intent/scope rather than
signature bytes across preparations. The fixed key, virtual clock, and local
session remain strictly demo-only; acceptance is pending and does not confer
auditor membership.

The portal test harness now mounts the real auditor form against the loopback
demo host's HTTP routes rather than returning mocked application responses.
Its adapter carries the fixture session over Node HTTP because Happy DOM's
default window origin differs from the ephemeral loopback port. It proves a
forged signature is rejected without consuming the application, then signs
the displayed digest, registers the pending application, issues a VP
challenge, and verifies redacted evidence acceptance through the DOM.
This covers form-handler-to-API conformance, not an actual browser engine or
Midnight network submission.

Issuer and verifier applicant forms now construct the same canonical pending
application intent as auditor, with role-specific scopes and governed resource
IDs. Issuer includes schema semantic version, definition, status method, and
selected resource type; verifier includes full request purpose and disclosure
scope. The portal retains no signing key and rejects a host pending binding
whose complete canonical scope, commitment, or subject DID differs from the
prepared request. Domain and DOM tests cover field substitution; role-specific
DOM-to-live-HTTP tests verify fixture DID signatures and one-use VP intake.
These flows stop at pending admission and do not grant membership or prove
Midnight finality.
An independent read-only review found the response check initially omitted
registry ID. The portal now requires the pending binding registry to equal
the signed intent registry, and DOM tests reject both scope and registry
substitution before reporting `pending`.
The loopback demo now selects issuer, verifier, or auditor fixtures for its
serve/application/VP commands, so each structured applicant form can be
demonstrated with a matching externally signed fixture application and
challenge-bound presentation. The default remains auditor for existing smoke
calls. The role selector never changes production authorization rules.

The maintainer applicant form now uses the same externally signed pending
application path. Its `tr-scope-v1` registry ID and governed resource are
both derived from the host's current mutation context, not an editable form
field. The portal checks the returned canonical scope and registry against
the signed intent. Domain, DOM substitution, and DOM-to-live-HTTP tests cover
forged signature rejection, pending registration, and one-use VP evidence.
The loopback demo accepts `maintainer` for matching fixture application/VP
commands. This is pending admission only; existing maintainers still govern
approval, and the reference host has no network finality or production key
custody. The sibling VC status-registry package is still private and lacks
an independently authenticated current-root proof, so the DID-signed status
attestation remains a narrower authority statement rather than a general
non-revocation proof.

Real Chrome exposed that the applicant portal served unresolved workspace
package specifiers from TypeScript ESM output; Happy DOM tests had imported
the same modules through Node and missed the deployment failure. The normal
portal build now bundles the browser entry point with esbuild. A narrow
browser-safe domain export and API recognition-query schema entry avoid
pulling server-only Node modules and Midnight on-chain WASM into that bundle.
An optional Playwright suite drives all four role forms against the loopback
HTTP admission host, rejects forged signatures, then completes pending
registration and one-use VP evidence. This is real-browser validation of a
fixture host, not production authentication or finalized-network evidence.

The admin console has a separate host-selection boundary. Switching its API
base invalidates prior board reads and prepared signatures, clears pasted
envelopes and the selected record, and fences late governance responses by
the original host revision. A Chrome test holds a registry-A epoch publication
response while connecting to registry B, then confirms the A receipt cannot
replace B's board. The A transaction may still have executed; changing a
browser connection is not a cancellation or a finality observation.

Local follow-on stack after the workspace-backed #59 journey: the signed issuer
demo now submits four invalid VPs over one live challenge (forged credential
signature, another credential-family scope, revoked fixture status, and expired
fixture status). Each receives a redacted 403 without an acceptance receipt;
the original valid VP then succeeds using that same challenge. This is a
functional #58 intake/retry slice, not production status or network finality.
The simulator client now uses the caller's `sequenceToTimestamp` mapper for
both epoch windows and policy supersession. A real Compact-simulator test
covers default and shifted supersession cutoffs across issuer, verifier,
auditor, recognition, and auditor-mandate verification. The published OpenAPI
governed-action enum now includes suspension, revocation, and archival, with
source parity checked by the ordinary light docs gate. These are two of the
five #196 findings; the issue remains open. Focused tests, `./run.sh --light`,
integration-light, and the VitePress build passed locally. No push or PR was
created. Forge #195 remains untouched because artifact/key compatibility with
the pinned Trust Registry toolchain has not been established.

Local #202 slice: operator workspace format 2 replaces the unbounded signed
mutation nonce string array with a hash-keyed expiry map. The API checks a
registry/actor/nonce identity directly, prunes expired records only inside its
exclusive write, and returns a fail-closed 503 at 10,000 live entries instead
of evicting replay evidence. Version-1 pre-release workspaces are explicitly
rejected. This is reference gateway replay retention, not an on-chain nonce
store or public-network throughput guarantee. Fake-clock, restart, concurrent
HTTP, schema-capacity, and keyed-lookup tests belong to this slice; keep it
local until a coherent functional stack is ready for review.
The later local #202 hardening uses workspace format 3. It records actor-key
hashes with expiry, caps each actor at 512 live nonces while retaining the
10,000-entry global limit, and persists a nonce-clock high-water mark. A
backward host clock fails closed instead of reviving pruned intents. Formats 1
and 2 are explicitly rejected; operators must rebuild pre-release snapshots
from trusted source data rather than deleting nonce history or moving the
high-water mark backward. Cross-actor saturation and clock rollback have
pure-state and HTTP tests; this remains a local reference-gateway guarantee.
The same local integration-light run exposed a governed-demo temporal-dead-zone
error: an early threshold-removal adversarial case implicitly used the later
main `harness`. Passing `lastActiveHarness` explicitly restores the intended
threshold-policy assertion. This is a demo wiring repair, not a policy change.

Local #200 follow-on: `prepareFinalizedDeploymentActionDigest` in the client
accepts a trusted finalized-state reader and refuses to prepare a maintainer
signature digest when network, deployed address, registry commitment,
deployment-network commitment, active policy, or action sequence differs from
the operator's selected deployment. It excludes the `undeployed` profile and
keeps private keys outside the helper. Focused tests and `./run.sh --light`
pass. The reader port is a trust boundary, not an implementation of a public
network provider: a real adapter must authenticate network identity, finalized
ledger state, and deployment address before #200 or 0.1.0 public-network
qualification can close. PR #205 exact-head Quality completed green after the
proving-key jobs were sharded; #207's light/docs checks were also green at the
last local CI check. Neither PR was merged in this slice.

The next local #200 slice supplies `createRpcFinalizedCheckpointSource`:
`chain_getBlockHash(0)` must match an out-of-band approved genesis pin before
the source accepts `chain_getFinalizedHead`. The checkpoint then drives the
block-hash-scoped indexer ledger read. Focused tests cover wrong genesis,
malformed JSON-RPC, missing hashes, and unsafe URLs; `./run.sh --light` and
audit pass. This trusts the configured node for finality and does not prove a
deployment. Official Midnight environment documentation now places public
Preprod RPC/indexer behind Blockfrost project-token URLs; the older
Midnight-hosted Preprod endpoints shut down on 2026-10-09. Preview remains a
public RPC/indexer and faucet target. Do not derive the approved genesis pin
from the same live RPC response or disclose project tokens in reports.

At exact local parent head `51dff47`, full `./run.sh integration` passed:
65 proof circuits and all integration/actor-demo suites completed. This
does not validate the later RPC-source or provider-composition commits as a
full integration run. The follow-on local provider-composition slice uses
published Midnight indexer provider 4.1.1 with the pinned node checkpoint;
it still needs a funded deployment and finalized constructor readback before
#200 can close. PR #205's latest `085e3d8` Quality/proving-key shards were
green at the last check; it remains unmerged.

The local read-only `inspect-deployment` CLI reports the selected network,
finalized block hash, deployed address, and decoded Compact governance fields.
It reads endpoint URLs and the approved genesis pin from environment variables
and handles no wallet key. Successful inspection is not the #200 deployment
receipt or an independent node-finality proof.

The next local #200 adapter, `deployPublicTrustRegistry`, takes host-owned
Midnight.js providers and an explicit contract-maintenance signing key. Its
network, RPC/indexer endpoints, and approved genesis pin are configurable for
Preview, Preprod, and Mainnet; no live wallet or deployment is bundled. It
checks the configured SDK network and pinned node genesis before submission,
then keeps only the public deployment receipt. Finalized readback can be
verified, pending, unavailable, invalid, or mismatched; any non-verified result retains
the receipt for read-only investigation rather than inviting redeployment.
Initialization is governance action count one, not zero. Five focused adapter
tests and the local 20/20 light gate passed. The host providers and indexer
remain trust boundaries; #200 stays open until a funded, operator-approved
deployment and independent qualification are available. The follow-on
bootstrap-specific finalized read adds the registry DID, policy version,
all initial thresholds, active maintainer count, and the maintainer's
identity, key, active status, and joining sequence to that comparison;
the action-signing reader remains narrower by design. The preceding
`c0a483d` sidecar passed full `./run.sh integration` with 65 proof circuits.

The local #213 continuation requires a complete V2 release-manifest
verifier-key catalog before deployment, reads operation verifier-key hashes
and maintenance authority alongside the constructor ledger at one finalized
checkpoint, and withholds `verified` for missing, extra, or substituted keys
or a replaced initial authority. These checks are local adapter hardening,
not an approved public authority model or independent finality proof.
The full-integration reader test serializes and deserializes a real generated
verifier key through `ContractState` before comparing its SHA-256 with the
finalized-image readback. A malformed operation catalog reports
`invalid-image`, not transient `unavailable`; missing and extra valid
operations report `mismatch`.

## 2026-10-17: local decision-evidence continuation

PRs #205 and #207 are merged into `milestone-0.1.0`. The configurable
deployment/checkpoint stack was rebased onto that milestone without conflict;
its local signed/DCO head is `a294e6b`. No public deployment has been
performed. #200 remains open and promotion PR #198 must not be treated as
release-ready on the strength of simulator qualification.

Local #79 commits `bf66349` and `0969427` make the finalized Compact
decision reader reject a substituted deployment-network commitment or
publication network, and require the accepted epoch's off-ledger date window
to match a host-supplied sequence-to-time projection. The host must still
authenticate ledger finality/currentness, publication maintainer history,
DID state, and that time projection. Midnight has no contract wall clock.
Focused decision-evidence tests, audit, and `./run.sh --light` passed at
`0969427`; a full integration run started at that exact tree and must be
checked before claiming full qualification. The published evidence guide
now explains these boundaries on the local follow-on branch.

The next local #79 slice, `9d6ecc4`, exposes the same block-hash-pinned
Compact ledger used by deployment preflight to the VC decision reader.
`createCheckpointedCompactDecisionReaders` refuses a mismatched network,
deployed address, or malformed/zero finalized block hash before consulting
the separately authenticated historical-publication port. It still needs
host-authenticated publication signer history, DID state, evaluation time,
and network finality; the simulator test is not a live qualification. The
integration package passed 154/154 tests, `./run.sh --light` passed 20/20
tasks, and audit reported no known vulnerabilities at this slice.

The local #45 release-candidate manifest slice (`865b8b5`, `d185d70`)
records a signed/DCO source SHA, Compact pin, lockfile and contract hashes,
published DID/VC dependency versions, and hashes/sizes for each packed
artifact. Generation rejects dirty source, incomplete full Compact outputs,
and a contract tarball without all named proof artifacts. Manifest-backed
package smoke verifies the exact tarball set before installation; its local
light-artifact flow passed, but no full release candidate has been generated
or approved. A genuine candidate still needs full build/integration, exact
revision CI, owner/rollback approval, and public-network qualification.
Issue #90's VC status-registry package exists in the sibling VC checkout but
is marked private; npm returned 404 on 2026-10-17. Do not copy its source or
claim external status verification until an owner-published package or
approved adapter is consumable.

The follow-on #45 commit `49ca956` makes `packed-artifacts:smoke` run an
issuer/verifier consumer scenario from a temporary directory after installing
the tarballs. It uses only package exports, verifies active evidence with the
simulator client, and rejects a substituted issuer resource. The 20/20 light
gate, packed smoke, and low-level audit passed locally. This is not the full
HTTP applicant/admin/relying-party journey at that commit: the UI clients were
not yet among the packed local artifacts, and a simulator package consumer
does not prove live network finality. Keep the full actor demo and release
qualification as separate gates.

The current local #45 continuation adds the private admin-console and
applicant-portal API clients to the tarball set, makes the signed membership
demo import package exports, and runs all four roles from a temporary
tarball-only install with `--actor-journey`. This closes the clean-consumer
actor-flow gap locally without making the UI packages public or claiming
network qualification.

The first full `./run.sh integration` on the #79 parent tree spent about 80
minutes in Compact key generation and then failed in the governed VC issuer
demo: the decision-evidence API returned 503 because its fixture supplied no
`sequenceToTimestamp` function to `createCompactLedgerDecisionReaders`. The
API correctly redacted the internal error. The local follow-on restores the
simulator's documented sequence clock in `demo-vc-issuer-consumer.mjs`; the
focused governed demo passes. A new `demo:governed:check` preflight runs that
demo during `./run.sh --light` in roughly 16 seconds so this class of failure
is caught before full key generation. Do not report the full integration gate
green until it is rerun on the final tree.

The local #73 packed-consumer continuation (`0c4c8f5`, `f2c3e4b`,
`d6fee47`) exports the TR-owned Ledger 8 Compact fixture from the private
integration tarball. A temporary clean npm install compiles it against the
published VC Compact package and exercises pinned-domain construction,
authority-signed issuer/verifier installation, credential and request proofs,
and forged-signature, replay, and wrong-scope rejection. The light gate now
runs this packaged check automatically; 20/20 light tasks, the combined
four-role packed actor journey, package contents, and low-level audit passed
locally. The signed descriptors in this particular packed smoke are fixture
data; the source integration test is still responsible for binding them to
verified Trust Registry decisions. Neither proves a deployed synchronous
cross-contract call or authenticated public-network finality. Full
integration on the earlier release-candidate tree was still generating
Compact proving keys when this checkpoint was written, so it is not evidence
for the new stack head.

The next local stack adds a packaged recognition VC/VP accreditation and
governed-proposal journey (`bb8021b`) and then an independently finalized
proposal-evidence read projection (`2d63fa9`) and optional HTTP query
(`8312507`). The read projects the existing immutable proposal record and
registered evidence-verifier key for issuer, verifier, auditor, maintainer,
and recognition roles. The HTTP route is disabled without a finalized-ledger
reader and distinguishes a missing record from an unavailable reader. It does
not independently prove finality, inclusion, or proposal-time key status;
#67 must not be closed solely from this projection. A follow-on local slice
reconstructs the role-specific action payload from the authorization record
and verifies the retained JubJub signature against the registered key. The local light
lane, API integration suite, docs/OpenAPI build, packed recognition actor
smoke, and low-level audit passed for the corresponding local slices. A full
integration run at `bb8021b` later passed in the separate release-validation
worktree; that result must not be attributed to a later stack head.

The later local audit stack adds signature reconstruction for all five
proposal roles (`c3a3dde`), a tarball-only recognition report with signer,
policy, epoch, and rejection commitments (`c8d03ed`), and a simulator
regression proving that a proposal's retained signature still verifies after
its evidence-verifier key is retired (`18d4db5`). The new read surface is a
projection over a caller-supplied finalized ledger; it verifies the proposal
signature and record joins, but does not prove that the supplied ledger is
final or that its map entries have independent inclusion proofs. The four
packed membership journeys and recognition report passed from clean tarball
installation, API integration passed 67/67, and the light gate passed 20/20.
No live status authority or public-network deployment is implied. The VC
status-registry package in the sibling repository remains private and its
README explicitly rejects production use pending authority and non-membership
gates; do not satisfy #90 by consuming that prototype. A clean 4.5 GB
worktree at a commit already contained in this stack was removed while its
branch ref was preserved.

The full `./run.sh integration` at signed `bb8021b` passed after roughly 90
minutes, including 66 proof circuits, API/adapter integration, and the
governed and signed actor demos. A rerun at later `0a7ab85` encountered the
same 66 ZKIR hashes but `compact compile` deleted the existing key directory
and started regenerating all keys. It was stopped after about 12 minutes as
free space fell to 25 GiB; the generated contract outputs in that clean
validation worktree were removed, and a separate clean 14 GiB ancestor
worktree was retired without deleting its branch ref. Do not count that
interrupted rerun as a pass or rerun full compilation merely to check
TypeScript-only changes. The current local stack instead passed the light
gate, packaged five-actor smoke, docs build, API integration, and audit.
The packed recognition actor now checks the public evidence route's 200,
404, and 503 behavior; the proposal projection test verifies all five roles
after evidence-verifier key retirement and rejects a substituted historical
public key. Before release, qualify the final clean candidate with a full
integration run and address redundant key generation without weakening proof
or package-content checks.

The #60 slice adds historical native/TRQP HTTP checks across a
maintainer-threshold revision, including an archived active issuer grant
after revocation. It records the historical API decision in the
machine-readable governed-demo matrix. Compact cases require the revised
quorum for verifier, auditor, and maintainer approvals, and cross-role
proposal cases reject missing or duplicate signers. Issuer, verifier,
auditor, and maintainer proposal cases substitute evidence hashes while
retaining the old maintainer signatures; the replacement evidence-verifier
signatures are checked independently, and fresh maintainer signatures execute
the same altered proposal in a rolled-back simulator context. The direct
active-maintainer self-DID
Compact test already exists; an API candidate self-vote may fail earlier at
active-key lookup. Other adversarial-matrix role/boundary gaps remain in the
coverage map. Local light, focused integration, demo, and audit results are
recorded in the #60 delivery PR; they do not substitute for final-head full proving or
authenticated public-network finality.

Issue #216's local runner extraction is stacked above release qualification,
not merged into a release candidate. The governed-demo matrix now records
per-case `passed`/`failed` status, a redacted failure reason, and aggregate
counts; it fails the process if the checked demo count differs from 198 or if
any recorded case fails. All 198 named cases now have independent Node test
fixtures across Compact/integration/client, public HTTP, and TRQP boundaries.
The full 198-case demo remains; unrelated top-level setup assertions can still
abort it. The local strict parity checker executes both surfaces and reports
198 matching IDs with none missing. It rejects duplicate or unknown extracted
IDs and runs in the light gate. Matching IDs do not alone prove equivalent
boundary or invariant coverage.

The recognition-intake matrix now records six composed assertion/accreditation
rejections, including a signature invalidated by a changed resolved Midnight
DID assertion key. Each isolated case preserves a fresh challenge and then
accepts the original valid proofs. These are local fixture-backed checks, not
independent external accreditation or public-network finality evidence.

## Dedicated Local Ledger Smoke, 2026-10-19

The `tr-standalone-local-smoke` project pulled its three pinned Ledger 8
images and started a dedicated node, indexer, and proof server without
touching the sibling passport localnet. The indexer required a 64-character
hex secret. The proof server could not fetch its verified public parameters
on the internal bridge; it fetched them during a temporary online
installation phase, and its 18-file cache was copied to a preserved local
artifact directory. After removing the temporary external network, a
recreated proof container started with that cache mounted read-only and
parameter fetching disabled; a peer on the internal bridge returned proof
server version `8.1.0`. This is an offline cold-start observation, not a
successful proof or end-to-end actor journey.

The node image wrote its chain under `/node/chain`, not the original `/data`
volume mount. After stopping the dedicated node and indexer, the chain was
copied from the stopped container into the named node volume and Compose was
corrected to mount `/node/chain`. The recreated node reported the same genesis
hash `0xe624f91737add2cf1a6658b3cf3a5524d633faea8c943702b435820316d9e21e`
and still served the pre-stop finalized block
`0xd16811b96a9f9e567b92f46d84130b0ed29edf4075e1e7fec93fc5d484f33e17`
at height `0x76`; the indexer returned to healthy. These are local RPC and
container observations, not an independently approved genesis, authenticated
finality proof, contract deployment, backup restore, or release qualification.
On the tested Docker Desktop internal bridge, configured loopback port
bindings were not published to the host. Host-side deployment therefore
needs a separately controlled access path; offline E2E must run with that
egress-capable path removed and all required services inside the trust
boundary. #198 remains draft.

### Isolated node-volume restore smoke

The stopped-node snapshot preserved at the ignored
`artifacts/standalone-node-chain/` (302 MiB) was copied read-only into a new
Docker volume, `tr-standalone-node-restore-smoke`. A separate container of
the pinned node image `midnightntwrk/midnight-node@sha256:c3e46f8beff308b352813cd8904f6480c331504e09060abd671b8a32e1255220`
booted that volume at `/node/chain` with `--network none`, `CFG_PRESET=dev`,
and the same configured sidechain block beneficiary as the dedicated stack.
No sibling passport container or live Trust Registry volume was changed.

From inside the temporary container, `chain_getBlockHash(0)` returned the
recorded genesis
`0xe624f91737add2cf1a6658b3cf3a5524d633faea8c943702b435820316d9e21e`,
and `chain_getBlockHash(118)` returned the recorded pre-snapshot block
`0xd16811b96a9f9e567b92f46d84130b0ed29edf4075e1e7fec93fc5d484f33e17`.
The restored node also answered `chain_getFinalizedHead`. The temporary node
was then stopped; its container and volume remain for inspection. The active
three-service dedicated stack still passed `check-standalone-topology.mjs`
afterward. This is evidence of **same-host node-state restore and historical
block readback only**. The checkpoint was not independently authenticated;
there was no indexer/API/wallet restore, second-host test, contract receipt,
conflict injection, or ambiguous-transaction recovery. The full RC
backup/recovery gate remains open.

The following commands record this run. For a repeat, substitute a **new**
volume and container name throughout; `docker volume create` does not fail
if a volume already exists. Never target the live
`tr-standalone-local-smoke_node-data` volume or overwrite the preserved
snapshot:

```sh
docker volume create tr-standalone-node-restore-smoke
docker run --rm --network none --entrypoint /bin/sh \
  --mount type=bind,src="$PWD/artifacts/standalone-node-chain",dst=/source,readonly \
  --mount type=volume,src=tr-standalone-node-restore-smoke,dst=/target \
  midnightntwrk/midnight-node@sha256:c3e46f8beff308b352813cd8904f6480c331504e09060abd671b8a32e1255220 \
  -c 'cp -a /source/. /target/ && test -d /target/chains && test -d /target/ledger_storage'
docker run -d --name tr-standalone-node-restore-smoke --network none \
  --mount type=volume,src=tr-standalone-node-restore-smoke,dst=/node/chain \
  --env CFG_PRESET=dev \
  --env SIDECHAIN_BLOCK_BENEFICIARY=04bcf7ad3be7a5c790460be82a713af570f22e0f801f6659ab8e84a52be6969e \
  midnightntwrk/midnight-node@sha256:c3e46f8beff308b352813cd8904f6480c331504e09060abd671b8a32e1255220
docker exec tr-standalone-node-restore-smoke curl -sf -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"chain_getBlockHash","params":[118]}' \
  http://localhost:9944
docker stop tr-standalone-node-restore-smoke
```

### Isolated indexer-volume restore smoke

On the same dedicated local stack, the active indexer reported block height
`682` with hash
`8b71180425ff4e750f998929cfe359fc1bffbf64e6a7062d40f1921f56ac7f9b`.
Only `tr-standalone-local-smoke-indexer-1` was stopped while its `/data`
volume was copied read-only to a new
`tr-standalone-indexer-restore-smoke` volume (about 7.8 MiB). The original
indexer was restarted and returned healthy. A separate instance of the same
pinned indexer image booted from the copied volume, without published ports,
on the dedicated internal ledger network. Its GraphQL query
`block(offset: { height: 682 }) { height hash }` returned the exact recorded
hash. The restarted active indexer returned the same historical result. The
temporary restored indexer was stopped, and the active node/indexer/prover
stack still passed `check-standalone-topology.mjs`. Both copied volume and
stopped container remain for inspection.

This demonstrates **same-host indexer volume restore and historical block
readback**, not a clean-host backup/restore. The restored indexer connected to
the still-running local node and could have resynchronized missing data; the
test did not prove independent database completeness. No Trust Registry
contract, API workspace, wallet state, VC status authority, backup integrity
signature, cross-host restore, conflict injection, or ambiguous-transaction
recovery was exercised. The full RC recovery gate remains open.

### Pinned standalone install-bundle candidate

From signed/DCO source `0ae03ca857f9aedb101f47c29e5e98c93b1d082e`, the
local bundle builder packed ten packages with the preserved full 66-circuit
contract artifacts, exported three digest-pinned arm64 image archives, and
copied all 18 Ledger 8 proof-parameter files into a new ignored
`artifacts/standalone-install/<source SHA>/` directory. The byte-level
verifier passed. Subsequent archive inspection found that `docker save` of a
digest-only image produced `RepoTags: null`; a loader that assumed Docker's
image ID was the config digest failed on this Docker Desktop containerd
store, where `docker load` reported the OCI manifest digest instead. The
loader was corrected to accept only either verified digest and then create
an explicit source-SHA-scoped local tag. On the existing daemon, all three
archives loaded, their IDs matched verified archive metadata, and local tags
were created. The offline Compose overlay resolved those tags and disables
pulls. The bundle and local tags remain available for inspection.

This is **candidate-byte integrity and existing-daemon load evidence**, not
an approved software supply-chain provenance decision or a clean offline
installation. The daemon already held the upstream images, and neither a
fresh-host `docker load` nor a pull-disabled full-stack restart was run.
The bundle binds the earlier source SHA above; after subsequent source
changes, generate a new bundle from the final clean signed commit. A
release-qualified install additionally needs pinned local DID, VC/status,
API/browser and wallet components, an independently approved install
manifest, and an offline restart with egress denied.

### First-run setup wizard boundary

The initial local setup CLI verifies the staged bundle, records a progressing
local node observation against an operator-supplied genesis pin, and reserves
one deployment attempt before entering the existing deployment adapter. Its
private, resumable record refuses another attempt after reservation, including
an unknown SDK outcome. The status report deliberately leaves independent
genesis/committee approval, offline actor journeys, restore, and security
review pending. This is workflow scaffolding, not live deployment evidence;
the smoke wallet and 1-of-3 committee remain development-only. Next work is
to bind independently approved first-setup decisions and a real provider to
this workflow, then capture finalized deployment and offline evidence.

The next local development slice adds a repository-owned, loopback-only
provider for the documented public genesis wallet. It persists a random
bootstrap maintenance key in the setup directory before use, but relies on
in-memory contract private state. It is suitable only for a one-time real
local-ledger submission smoke, not release custody, maintenance transition,
or restart/restore evidence. The `ws` SDK dependency is pinned to a patched
8.21 version because the initially selected 8.20 release failed the low-level
audit gate; the workspace override also patches the indexer-provider path.

The first-run wizard now refuses deployment until it records a detached GPG
signature over the source SHA, install-inventory hash, observed genesis, and
loopback RPC endpoint. It checks the exact signing-key fingerprint from a
private operator-supplied public keyring and preserves signed bytes in the
setup record. This is a signature and binding check, not a claim that the
operator-entered fingerprint represents an independently authorized reviewer;
the release owner must approve that trust anchor out of band. Committee
approval, finalized maintenance readback, offline journeys, and independent
security review remain open.

The wizard also accepts a separately signed release committee roster after
genesis approval. It uses the integration package's policy validator (three
distinct keys minimum, threshold at least two), checks distinct custody-role
references and Ledger key validity per key, and binds the signed document to
the source, inventory,
genesis, and genesis approval. A 1-of-3 smoke roster is rejected by this path.
The recorded status is **roster signature verified, transition pending**; no local
maintenance transaction or finalized readback has occurred. Reviewer
authority, real key custody, transition submission, and release qualification
remain operator and independent-review gates.

### Staged local verifier-key installation boundary

The first development-only local deployment attempt reserved its private
one-attempt journal and exited after wallet synchronization without returning a
deployment receipt. A read-only scan of finalized blocks around the
reservation found no transactions, but that does not prove the attempt never
reached the network. The journal and diagnostics are preserved privately;
reconciliation and a human recovery decision are required before another
deployment attempt. No live Trust Registry deployment is yet qualified.

Unsubmitted SDK diagnostics against the dedicated local node, indexer, and
prover found that the full 66-circuit constructor proved but failed wallet
balancing with `exceeded block limit in transaction fee computation`. The same
path with one verifier-key circuit proved and balanced, without submission.
This motivates an explicit staged bootstrap, not a silent retry or evidence of
successful deployment. The initial transaction installs one pinned verifier
key; subsequent keys must be inserted one at a time in sorted catalog order
with a distinct durable journal, approved signing key, and finalized key-hash
readback. The maintenance authority counter starts at zero and advances once
per insertion. A staged committee transition expects the exact catalog-size
minus-one counter, while a full-constructor transition still expects zero.

The repository now has a local-only staged plan, per-key insertion and
read-only reconciliation CLI, and tests with injected providers. These tests
exercise journal and approval boundaries but are **not** live-ledger, offline
egress, restart, or recovery evidence. A failed or ambiguous insertion remains
reserved; no automatic retry or journal deletion is supported. The public
genesis wallet and 1-of-3 smoke committee remain development-only. Release
qualification still needs an approved operator, reviewed install bytes,
finalized deployment and every key readback, approved threshold committee,
offline actor journeys, restart/restore, and independent security review.

The first-run wizard now records the staged deployment plan's endpoint and
provider pins, requires its finalized staged-bootstrap receipt, and permits
one operator-invoked per-circuit insertion bound to that plan at a time. A separate
`reconcile-key` path is read-only and preserves ambiguous journals. This is
operator orchestration rather than local-ledger qualification evidence; the
pending development attempt still requires independent reconciliation and a
human recovery decision before any new submission.
The wizard also has read-only staged-deployment reconciliation for an initial
receipt whose finalized readback lagged. It requires the exact original plan
bytes, original journal intent, pinned manifest and provider, and the
genesis-pinned finalized one-key image. A journal without a receipt stays
unknown and reserved; neither this path nor the key-insertion path retries
or overrides an ambiguous submission. Receipt metadata is journal-attributed,
not independent transaction-inclusion evidence, and reconciliation stops once
the staged bootstrap or key installation has advanced. The earlier unresolved full-constructor
development attempt remains subject to independent reconciliation and a
human recovery decision.

The dedicated offline ledger topology check now rejects *any* extra network
attachment, including the temporary installation relay, rather than checking
only the three Compose service containers. A live controlled egress probe on
the dedicated stack used the same pinned node image and IP-pinned HTTPS canary
on Docker's normal and internal bridges: the normal bridge reached the canary,
the internal bridge returned a connection error, could not resolve that
canary's DNS name, and had no `/0` or `/1` route. The probe contacts the
external third-party host `example.com`; it does not prove that other
destinations or protocols are blocked. This is canary-specific ledger-bridge
evidence only, not proof that the wallet, API, browser, backup processes, or
actor journeys run without egress. The API executable
still uses a file-backed workspace; it is not yet a live Compact gateway.

The staged local maintenance reconciliation had a latent counter mismatch:
its signed-update hash was rebuilt at counter zero even when installed
verifier keys had advanced the authority counter. The corrected read-only
path derives both the old and next counter from the pinned manifest catalog;
the staged regression now uses the actual counter-bound bytes. The first-run
wizard can also prepare, but not submit, the local maintenance transition
after signed roster approval and verified readback for every staged key.
It returns the exact SDK data-to-sign and finalized image pin. These are
mocked-provider/unit checks until a real deployment, external bootstrap
signature, one-attempt submission, and finalized committee readback occur.
The local maintenance submission API now requires the independently retained
SHA-256 of those signable bytes and the finalized checkpoint hash. It re-reads
the current image and rejects a changed signable update before authorizing
the signature or reserving a one-attempt journal. The approved checkpoint is
retained separately from the fresh submission head. This guard does not itself
qualify the local deployment.

The first-run wizard now accepts a detached raw Ledger bootstrap signature
over the exact saved signing request, then reserves a private one-attempt
maintenance journal before using the approved provider module. Its separate
reconciliation step is read-only and retains ambiguous attempts instead of
retrying. A submitted transaction is not a finalized committee readback, and
an observed maintenance authority alone is not independent transaction
inclusion or a release qualification. The unresolved full-constructor local
attempt is untouched.

The maintenance provider factory is separate from deployment material and
does not load or create the bootstrap signing key; only the external signature
is passed into the handoff.

The approved finalized checkpoint is preserved separately from the current
submission checkpoint because the local chain continues finalizing blocks
during external signing and wallet synchronization. A fresh finalized full
image and unchanged maintenance update are required before reservation.
Caught preflight failures with no journal are recorded as aborted and may be
explicitly retried; an unreadable or present journal remains ambiguous. A
process crash before the journal write is different: an absent journal alone
does not prove non-submission, so the wizard reports
`recovery-required-no-journal` and requires independent human recovery. The
wizard retains bounded reconciliation history, protects observed and conflict
states from later weak reads, and surfaces a separate alert for a new conflict
after an observed transition.
The journal-presence flag distinguishes a lost journal after an unknown
submission from the pre-journal crash window. A returned transaction ID that
could not be durably written is retained as reported evidence, not accepted as
finalized inclusion.

The pre-journal crash window now has a narrow manual recovery path. Only an
independently signed governance decision can unlock a second attempt, after
the original intent's expiry plus a grace period, absent journal and
transaction attribution, and a fresh finalized readback of the unchanged
bootstrap authority. The reviewer attests to a later finalized checkpoint and
their independent journal/mempool/chain inspection; the wizard also observes
an advancing head but cannot prove the reviewer's checkpoint is its ancestor.
The next saved signing request must be distinct and cannot reuse the abandoned
checkpoint. Reconciliation that contradicts the absence finding changes the
state to conflict rather than silently undoing approval. The maintenance
signature authenticates `MaintenanceUpdate.dataToSign`, not transaction intent
expiry: a new intent window does not invalidate the old signature. Keep the
signature file under bootstrap custody until the authority counter advances.
This workflow does not qualify a real local deployment or replace the human
security and operator gates.

A separate read-only scanner now makes no-receipt deployment investigation
repeatable. It accepts only an approved local loopback plan and matching
private reservation, captures the node's finalized head, verifies the node
genesis and every parent-linked indexed block hash against the node, and
reports indexer-listed transactions and contract-deployment candidates, node
head gaps, and pending-extrinsic count. Node hashes anchor the indexed block
chain, but the node does not independently attest to the indexer's transaction
enumeration. It refuses a submitted receipt and never authorizes retry. An empty
finalized range is useful evidence but does not rule out provider ambiguity,
later inclusion, or a candidate contract outside the observed range; an
independent operator must still decide recovery.

The standalone Compose profile can now be run under an explicit second
`tr-standalone-local-*` project with distinct loopback ports. This creates
separate named node/indexer volumes and avoids resetting the preserved
ambiguous smoke ledger. The topology verifier checks the selected project,
internal-only bridge, expected services and persistence, pinned images, and
exact loopback-only port bindings; the egress probe targets that same project.
The new genesis and first-run approvals remain independent. A rendered Compose
plan or healthy containers do not count as deployment, offline actor-journey,
or restore evidence.

The first-run wizard now prepares a private Compose environment from a
re-verified install bundle. It binds the selected project and loopback ports,
checks the current Compose image pins and the absence of existing project
containers, network, and persistent volumes, and generates fresh indexer credentials
without printing them or storing them in the public setup record. This is
configuration preparation only: an operator still checks that the project and
ports are unused, starts the stack, approves the independently observed
genesis, and collects actual finalized deployment and offline-journey evidence.
The explicit observation step records live topology and canary egress checks
for that selected ledger bridge without implying that the full actor stack is
offline or that a contract has been deployed.
Repeated pre-genesis checks retain timestamped history instead of overwriting
earlier evidence; further stack observations are refused once ledger observation
or deployment begins. Deferring stack preparation in the interactive wizard
stops before a genesis pin can be recorded out of order.
After preparation, both interactive and explicit genesis observation require
the selected stack to have a recorded live topology and ledger-bridge egress
observation first. The wizard never starts that stack implicitly.
This ordering is mandatory for v3 install bundles; the explicit genesis command
continues to read historical v2 smoke records without upgrading them to RC
evidence. Stack observation rechecks the verified bundle's Compose bytes, not
the mutable checkout copies, and refuses a 21st pre-genesis observation.
The first-run CLI can draft unsigned genesis and release-committee approval
documents from observed setup pins plus public reviewer/custody metadata. It
rejects a smoke-only 1-of-3 roster and writes private, non-overwriting draft
files; independent review and detached human signatures still determine
authority, and drafting never advances the approval state.
The draft approval time is supplied as public reviewer metadata and is part
of the exact bytes later signed; the machine does not invent an approval time.
The wizard can collect a private, non-overwriting genesis **candidate** from
the verified live ledger bridge. It labels the hash as node-reported and
does not record a pin or approval; independent chain-spec review and detached
human signature remain required before deployment.
New wizard stacks require a v3 install bundle pinning both base and offline
Compose bytes as well as archived image references. V2 bundles remain readable
for historical smoke evidence only; the runtime operator must use the verified
bundle copies, not mutable checkout files.
Wizard-driven stack observation matches the running indexer credentials and
proof-cache bind source against the prepared private environment without
recording secret values. For v3, it additionally matches running image IDs
to the checked archives and Docker Compose's recorded config-file paths to
the verified bundle; source-scoped offline tags require all three services
and the two-file overlay. It also rejects extra mounts and privileged services.
These are ledger-bridge observations, not proof of a clean-host install,
packet-level egress denial, full actor journeys, or contract deployment.
The separate restart observer captures an immutable private baseline and
compares service start times, persistent volume creation times, the same
historical finalized block hash, and later finality after operator-controlled
restarts. It also binds the observer script hash. A pre-deployment smoke does
not establish contract, wallet, API, actor, or cross-host restore continuity;
those remain separate RC gates.
The host access relay is installation-only and must attach to the selected
project with distinct loopback host ports; the original smoke relay recipe
cannot be reused unchanged for a concurrent qualification project.

The first-run release committee roster is approved before deployment and
therefore cannot itself name the actual contract. A separate detached
governance approval after staged finalized readback now binds the roster hash,
reserved deployment-plan hash, exact receipt and contract address, genesis,
and verified release-manifest hash. The wizard requires this signed binding
before preparing or submitting the threshold-maintenance handoff and rechecks
it against the preserved setup state. The same pinned governance reviewer
signs both approvals. It is not a substitute for independent receipt review,
finalized maintenance readback, offline actor journeys, or human security
approval; an ambiguous no-receipt attempt cannot pass this gate.

The 0.1.0 Helm backlog (#218) depends on a runnable, ledger-backed API image,
not just Kubernetes templates. The current standalone Compose files start only
node, indexer, and proof server. A local, unpushed signed slice through
`bbee90e` builds two static portal OCI archives from a clean signed export,
records asset and archive hashes, and avoids remote Turbo cache reads/writes.
Both portal roles passed read-only, network-isolated startup at `b0f3844`;
admin rebuilt from `bbee90e`. A separate signed local API-image candidate at
`a5484f7` built an arm64 OCI archive and passed GPG and API-import checks in a
read-only, network-disabled container. Independent review found its legacy
deployment could re-resolve dependencies and published DID proving keys were
still included; that archive is not a release candidate. The corrected builder
at signed revision `a26ea84` uses the shared lockfile, excludes the known DID
proof assets and all native addons, and scans the full runtime payload. Two
builds had the same 12,166-entry payload digest after excluding pnpm's volatile
install metadata. Their OCI image/archive digests differed, so the exact
archive remains pinned separately. Packaging checks do not prove
cluster qualification or offline actor journeys. An unpushed v4 install
inventory slice binds a separately built API archive to the same signed
source revision as the release packages, verifies its OCI/config identity,
and imports a private hash-checked copy without a registry pull. It rejects
image-name annotations and unapproved platform variants. The signed local
API plan can reference a v4 inventory, but the installer does not start or
observe a running API. The CLI now has a separate
reviewer-signed read-only local-ledger mode, but its tests use simulator or
reader doubles. The indexer's Compact state lacks state-root authentication,
the signed governance timestamp map is not independently derived from the
chain, and no same-head API image has been installed and observed running from
a verified first-run inventory.
No live DID/VC/status authority or deployed actor path is established.
Complete #219 and the real isolated-cluster qualification before presenting a
chart as the offline RC deployment path. Chart lint and rendered manifests
cannot replace enforced egress denial, finalized readback, or restore evidence.
The running dedicated ledger bridge is healthy and its installation bytes
were verified, but its genesis remains a node-reported candidate without
independent signed approval; no deployment or committee transition is recorded
in that setup state.

On 2026-10-20 the pinned node digest was independently traced to Docker Hub's
`1.0.0-arm64` tag and the public `midnight-node` `node-1.0.0` release.
The tagged source, downloaded release tarball, and pinned image agree on the
SHA-256 of `res/cfg/dev.toml` and both `undeployed` genesis files. A disposable
network-disabled container running the separately downloaded release binary
reported the same genesis hash as the dedicated stack. This is a review packet,
not a governance signature or release qualification. The image's
`dev.earthly.git-sha` names an Earthly build-tool commit, not node source.
More importantly, the macOS Docker Desktop smoke stack requests loopback
bindings in `HostConfig.PortBindings` but has empty effective
`NetworkSettings.Ports` and no direct host RPC access. The wizard can now
record a prepared, isolated bridge as `unpublished-install-access-required`,
and a fresh live observation matched its private inputs and pinned images and
passed a scoped ledger-bridge egress probe. A temporary relay reached node RPC,
indexer GraphQL, and proof-server version, then was removed; it was not a
source-pinned installation path or offline-runtime evidence. Genesis observation
still requires verified effective host access, so do not deploy until a reviewed
access path passes that gate. Preserve the existing volumes and private
candidate evidence meanwhile.

The next complete v6 install-bundle format pins the temporary relay script
beside the six images and two Compose files. Its read-only verifier checks the
running relay image, exact Python entrypoint, read-only script mount, environment
identical to the pinned base image, mounted script bytes, selected internal
bridge plus default bridge, and three effective loopback ports. Wizard genesis
observation and deployment reservation recheck
the same relay identity and source-pinned bytes. This is an installation-only
access path: it must be removed before offline actor and egress qualification.
The deployment plan's node and indexer URLs must all match the relay, and a
post-submission drift check marks the attempt unknown rather than permitting a
blind retry. The proof-server URL lives in provider configuration outside this
plan and remains a separate qualification concern. Hashing current mounted
bytes does not prove which Python code was loaded at process start against a
malicious host administrator. The existing v3 smoke bundle lacks this pin and
remains unqualified. The final sentence of the earlier record preceded the
later v6 build and does not describe the current candidate.

As of signed source `33c9395bfb867d2038fc4e93f8712bbd296d5f0a`, the
verified v6 install inventory SHA-256 is
`4ff7a6cfe3767ba261cf3118a186d13ec9d4bf59568e8020b20507cb56f460ae`.
The dedicated b12 node/indexer/prover bridge matched its private inputs and
pinned image identities. A bridge-only canary denied HTTPS and DNS egress;
this does not cover actors or runtime services. An installation-only relay
matched pinned script SHA-256
`93b92ca48b9c73361bdf8f8f0384f99c42eadda888751f58bfcc75cd2ad6b9d8`
and returned the expected node genesis, GraphQL query type, and proof-server
version over loopback. The relay was removed and the three services stopped;
volumes and private b12 evidence were retained. The private review packet and
pin are unsigned proposals. No wizard genesis approval, contract deployment,
committee transition, deployed offline actor journey, or restore qualification
has occurred. The v2 signed API plan and Helm plan/Secret/image observer are
implemented and locally tested, but not deployed against this ledger. Keep
the local RC gates open until independent genesis and committee approvals,
finalized contract readback, offline actor journeys, recovery, and independent
security review are actually observed.

The next local wizard slice adds `draft-genesis-pin` to avoid hand-assembling
the node-reported proposal. It requires a previously collected canonical
candidate plus a fresh verified direct-loopback or source-pinned relay path,
then writes a private, non-overwriting `genesis-pin.proposed.json` with the
actual loopback RPC port. The generated pin remains explicitly untrusted;
the independent reviewer must still derive and approve genesis from the
chain specification before wizard observation and detached approval signing.
This source change is newer than the b12 install and does not requalify it.

As of 2026-10-24, b17 is the latest retained verified-staged v6 development
installation. Its inventory SHA-256
`51bdd796170f93953ff7a08d21c999227dddeec97b4d275f0cb32d06f3457e31`
is bound to signed source `3424799e3142520f9041f7ebbcd75a6327b67b77`.
The dedicated node/indexer/proof bridge is running. A pre-deployment restart
retained the finalized height-69 hash and advanced to height 77. The b17
genesis candidate and proposed pin remain unsigned; deployment, committee
transition, offline actor journeys, and restore remain pending. The earlier
b16 installation provided a positive-control HTTPS canary and internal-bridge
HTTPS/DNS denial observation, but that observation does not qualify b17 or a
deployed runtime. These are self-attested development observations, not
clean-host install, deployed contract, actor, or restore qualification. The
b15/b16 private volumes and evidence remain preserved. Later local source
changes require another exact-head bundle and review.

For #220, the read-only v2 recovery report now binds the exact approved API
plan digest and journal attempt digest, but never releases a reservation. The
installed indexer public-data provider's `queryContractState` returns a
deserialized contract state at a requested block hash without an accompanying
machine-verifiable state proof. The current reader pairs that response with a
pinned local node's finalized block hash; the pairing does not by itself
authenticate the absence of a proposal record against a hostile or faulty
indexer. Do not implement a journal unlock using a null read, elapsed time,
or this candidate report alone. A separately approved non-inclusion evidence
policy, signed operator decision, durable no-replay record, adversarial tests,
and independent security review remain required.

The local journal reader rejects unexpected hard links, non-private ownership
or permissions, and files whose inode or metadata changes during a bounded
read. A two-link deployment binding remains readable only when its companion
has the exact private temporary filename and inode left between atomic link
publication and temporary-name cleanup; other binding links still fail closed.
This protects the stored reservation input and avoids a permanent outage after
that crash window. It does not authenticate finalized non-inclusion or
authorize retry, deletion, or release of an ambiguous attempt.

The b17 observation above is historical. The later retained b19 install is
source-matched to signed `f48fbb9`; its inventory SHA-256 is
`d72798c39a414bd3caf2ab2c11cb3f2926909823f2f9054344f48e2bcbef8c14`.
Its stopped bridge, unsigned genesis packet, and pre-deployment canary egress
check are development evidence only. The subsequent binding crash-recovery
fix and RC evidence correction supersede b19 as an exact-source candidate.
Preserve its private evidence and volumes until an independently approved
replacement packet and explicit cleanup decision exist.

For #219 availability, a settled `null` from the finalized reader now denies
the current request and permits one new read after a one-second cooldown.
The new read must independently pass every pinned snapshot and ledger check;
no cached or fixture state is served. Reader exceptions, invalid state,
snapshot mismatches, and a timed-out read still latch until process restart.
A `null` is neither proof of proposal non-inclusion nor permission to clear
the #220 reservation gate. This is a local unit-tested behavior, not evidence
of live indexer recovery or deployed offline runtime.

The applicant portal now distinguishes current local-ledger lookups from
fixture-only historical evidence views. In confirmed local-ledger mode it
offers exact current authorization and recognition queries, labels their
responses as unverified API claims, and does not expose historical controls.
Unavailable complete-list projections render as unavailable rather than zero
trusted members. Malformed active-list responses fail closed instead of
populating public inspection cards. Portal unit tests, typecheck, lint, and
dependency audit passed locally on the signed current-portal branch; these
checks do not establish deployed local-ledger readback or offline actor
journeys for #219. Kubernetes/Helm remain optional deployment paths, not
0.1.0 qualification requirements.

For #220, the current real-journal issuer HTTP test rejects an insufficient
quorum before reservation, but uses a simulator-backed finalized reader.
The reserved-attempt candidate report remains read-only: its indexer state
has no authenticated absence proof. A future release of a reservation must
also survive node restore without letting the original signed sequence become
valid again, bind the signed decision to the exact journal attempt under lock,
and prevent direct writers from substituting an unverified sequence context.
The operator recovery-evidence policy and independent security review remain
open; no journal release is implemented or authorized by this note.

On 2026-10-24, #219 and #90 remained open. The sibling VC checkout's
`@midnight-ntwrk/midnight-did-credentials-status-registry` manifest still
declared `private: true`; a registry lookup for that exact package returned
404 to this client. This does not prove the package is unavailable to every
operator, but it does not provide a published VC-owned live status-authority
adapter for the Trust Registry RC. Do not copy the sibling's private source
into this repository or count existing simulator, portal, or API tests as
deployed offline DID/VC/status actor-journey evidence.

The standalone qualification observer must not combine a wizard setup with
an API runtime merely because both use the same source commit. The verified
install inventory, wizard project and observed Docker network, independently
approved genesis, and deployed contract address must match the running API's
signed plan and readback. An opt-in API restart must retain the same container,
network, plan, and selected state. These are cross-run identity checks, not
independent authentication of node/indexer finality or proof of a governed
actor write. The combined observer remains `releaseQualified: false` and
stops before API probes when wizard ledger prerequisites are missing.

The local acceptance inventory can now compare a private, read-only observer
report with its selected source, install inventory, signed API plan, approved
genesis, and deployed contract. This check never changes case verdicts or
authenticates the report; a pre-deployment result exits as missing evidence.
The operator quickstart invokes the Node observer directly when redirecting
JSON because `pnpm` emits a stdout banner. The standalone API now obtains its
local network ID from the versioned `standalone` profile in plan validation,
finalized source checks, proposal journaling, and recovery reports. The
profile still maps to Midnight's local `undeployed` identifier; this is not
public-network support or a portable genesis pin. Both changes are in local,
unpublished signed/DCO branches. Focused observer/acceptance tests, the API's
256-test suite, integration profile tests, typecheck, lint, docs build, and
dependency audit passed in the writable checkout. Neither change provides a
deployed actor journey or clears #219, #220, or the release security gates.

### Local issuer proposal assembly, 2026-10-27

The local-only issuer path now has a reviewer-visible terms binder, an unsigned
Compact signing context from the selected policy and current verifier key, a
side-effect-free SDK submission preflight, and an opt-in API issuer-port
assembly. The assembly requires a captured pending/accepted admission pair,
live DID/VP/VC-status and trusted-time verification, a finalized policy/ledger
reader, and immutable provider-code checks. The packaged signed-plan CLI does
not instantiate it and remains read-only. A failure after the API journal
reserves an attempt remains quarantined for explicit recovery; it must not
trigger an automatic retry.

The private admission store now reads the pending and accepted records from
one validated file state, and HTTP admission prefers that captured pair.
The local-ledger source now returns the policy snapshot, Compact ledger, and
finalized block hash from one bounded read; the approved-plan wrapper adds
its signed genesis pin. These changes prevent mixed record/checkpoint reads,
but do not independently authenticate local-node finality or provide a live
VC-owned status adapter. The injected-port tests, 261 API tests, 104 API
integration tests, build/typecheck/lint, docs checks, and low-level dependency
audit passed locally at this stage. They are not a deployed offline E2E run.

The dedicated b26 setup remained pre-deployment at inspection: no approved
genesis, contract address, reconciled verifier keys, or maintenance transition;
its install candidate also predates the new source. Do not reuse that setup as
qualification evidence for these commits. The next candidate needs a new
exact-source verified bundle and human-signed genesis/maintenance approvals,
then real deployed readback, live status authority, egress-denied actor cases,
restart/restore, and independent human security review. Keep #198 draft and
the local 0.1.0 RC unqualified until those gates are evidenced.

### Pre-actor API capability observation, 2026-10-27

Before collecting issuer signatures for a standalone run, the operator can
capture `/health` inside the dedicated API container and check it against the
reviewed signed-plan SHA-256. The new bounded-file checker rejects non-local
sources, malformed or zero finalized hashes, unknown or repeated roles, and
missing requested ports. The currently packaged read-only CLI reports no
issuer port, so this check exits 2 rather than inviting a doomed `A01` run.
Even exit 0 proves only configured port presence; it does not authenticate
the saved health response, finality, live VC status, or an actor transaction.
The operator guide now expands source-scoped image tags correctly instead of
using a literal `SOURCE_SHA` placeholder. Standalone topology tests and the
docs build passed; no release evidence or genesis approval was inferred.

The opt-in issuer port also requires an injected trusted-time reading on each
prepare, preflight, and execute. It rejects accepted evidence outside the
signed verified-at/expiry window before provider loading, and passes the
same reading to the live evidence verifier. This closes an adapter omission
path but does not establish trustworthy clock provenance; that remains a
deployment-owned, independently reviewed dependency.
The after-reservation SDK handoff now accepts an optional late readiness
check. The local issuer port uses it to resample trusted time after SDK
proving and pinned-node authentication, just before the transport send.
The guarded path requires a pinned provider that supports this check;
expiry before submission leaves the durable reservation
for explicit reconciliation. This narrows but does not close the gap between
local preflight time and a finalized ledger transition.

### Standalone adopter test boundary, 2026-10-27

At the local writer-plan-identity head, all four signed membership demo
journeys and the API/UI demo smoke passed, as did 75 standalone topology
tests. The membership journeys use the Compact simulator and fixture-backed
identity/status inputs; the topology suite tests checkers and simulated
boundaries. Neither is a deployed local-ledger actor E2E run.

The retained b26 private setup belongs to an older source revision. Its
wizard status has no approved genesis, deployment, reconciled verifier keys,
or maintenance transition. The candidate-scoped journey prerequisite check
therefore exits 2. Its `nextActions` field now gives the operator a specific
step for each missing gate without changing `releaseQualified: false` or
claiming that a recorded prerequisite proves independent finality. A future
exact-source setup, human-signed approvals, reviewed writer dependencies,
live VC status authority, and real offline actor receipts remain necessary.

The lower-level deployment and verifier-key modules previously also accepted
direct CLI invocation with an arbitrary JSON plan. Those paths checked plan
shape, provider bytes, and the immutable import boundary, but did not first
verify the wizard's signed genesis and committee approval chain. Direct
invocation now exits before reading a plan or submitting. The wizard remains
the supported operator entry point and imports the same lower-level functions
only after its retained approval checks. This closes an accidental adoption
bypass, not the separate authenticated-finality or provider-code review gates.

The local manifest-backed publish workflow now rechecks each tarball's
manifest-pinned size and SHA-256 immediately before handing that tarball to
`npm publish`. A streaming file checker rejects missing, linked,
duplicate-manifest, truncated, and same-size altered inputs. Artifact
workspace tests include the tampered-byte negative. This narrows the gap
between the full-set verification and individual publish calls, but does not
approve the release channel, complete human security review, or eliminate a
compromised-runner time-of-check/time-of-use window.

The publisher now also rejects a failed or empty workspace catalog rather
than treating process-substitution failure as a successful no-op. Its offline
shell tests cover missing and existing registry versions, matching and changed
registry integrity, and uncertain lookups; they stub npm I/O but run the real
published-byte integrity helper. Exact-head CI, manifest approval, and
independent release review remain separate gates.

The application-status HTTP transport caps its signed-attestation response at
64 KiB before JSON parsing, including when the authority omits or understates
Content-Length. Oversized and invalid UTF-8 responses fail closed. This
hardens the governed issuer evidence intake against untrusted status responses;
it is not a VC-owned live status-authority deployment, authenticated ledger
finality, or standalone actor-journey evidence.

The RPC checkpoint reader (local and public) now caps each
genesis/finalized-head JSON-RPC response at 8 KiB and rejects malformed UTF-8
or JSON before accepting a hash.
The limit applies even without an honest Content-Length header. This prevents
an unbounded node response from exhausting the actor host; a pinned local node
is still not an independently authenticated finality source.

Issue #229 now wires the pre-existing broad checked-JS configuration into CI
and adds a strict CI gate
for provider inode identity, immutable import confinement, and optional Helm
signature verification. The remaining non-strict approval, installer,
maintenance, and release scripts are listed with migration priority and owner in
`docs/plans/standalone-security-script-typecheck.md`. This does not type the
large wizard or replace its adversarial tests and independent human review.

Provider staging now delegates its expected-workspace, unique archive-name,
and SHA-256 catalog decision to a strictly checked pure policy. Malformed and
duplicate catalog entries are rejected before extraction. The staging I/O
shell and its installer dependencies remain outside the strict gate; this
does not qualify the install or prove any deployed actor journey.

The wizard's canonical reviewer metadata and release committee/custody
validation now live in a strictly checked, side-effect-free policy module.
Direct negatives cover noncanonical/missing fields, synthetic references,
one-of-three smoke thresholds, duplicate keys, and duplicate custody roles.
The wizard's existing approval and recovery suite still passes. This changes
neither the required detached human signatures nor the pending real local
deployment and offline actor acceptance gates.

The fixture browser suite had drifted from the API's required side-effect-free
proposal preflight and from the admin client's health-first loading. Its tests
now provide the required fixture port, a health response, and the current
governed-action error text. Applicant test teardown closes browser HTTP
connections before awaiting server shutdown; a full Chrome run passed all nine
specs. The browser-inclusive demo command is useful adoption coverage, not
live local-ledger or egress-denied actor evidence.

The opt-in local issuer port now repeats captured admission, authenticated
finalized signing context, live evidence verification, and immutable provider
code checks in the transport's pre-broadcast guard. It samples trusted time
again as the final guard step so slow verification cannot silently carry
expired evidence into the send. Injected-dependency tests block transport on
revoked status, advanced governance sequence, and expiry during guard work.
A caught guard failure still leaves the durable proposal reservation for
reconciliation; it is not proof of non-inclusion or permission to retry.
The API unit suite, issuer HTTP integration, typecheck, docs check, audit, and
the browser-inclusive fixture demo passed. Codex CLI review found and the
follow-up fixed the late-expiry gap, then found no actionable regression in
the correction. These tests and review do not implement a live VC-owned status
adapter, authenticate a deployed ledger, or close the human release review.

The wizard's restricted API approval-chain export decision now lives in a
strictly checked pure module. It preserves canonical signed-document byte
checks, approval hash links, source/install pins, deployment receipt matching,
and unambiguous maintenance readback before exporting only the public-key
approval evidence. Missing record fields, zero finalized hashes, and duplicate
signed JSON keys fail closed. The wizard still owns private-file I/O and
detached-signature verification; the extracted decision does not verify a
signature or authenticate finality independently. Both checked-JS gates and
the 102-case wizard suite passed. The remaining wizard sequencing and installer
adapters stay in the #229 migration inventory.

The genesis-review packet's candidate/pin comparison is also isolated in a
strictly checked pure module. It requires the selected standalone profile,
source and inventory pins, observed dedicated bridge, pinned node image,
canonical node-reported candidate, and loopback-only proposed pin. The image
reference syntax is shared with the installer rather than duplicated. New
negatives cover missing or primitive inputs, malformed observation and image,
wrong host lists, noncanonical time, and wrong numeric types. This comparison
still uses values reported by the same node: it is **not** an independent
chain-spec review, detached human approval, or deployed-ledger evidence.

The standalone acceptance inventory now requires each `pass` case to be
backed by its latest private operator decision record, with the record's
prior status and evidence list matching the case history. A raw attachment
after the decision makes that case incomplete until it is reviewed again.
This prevents an accidental manual `pass` label or stale decision from
producing `completeInventory: true`; it does not authenticate the operator,
receipt, finality, or security verdict. The #230 fresh-process journal and
provider-construction tests are now explicitly described in the actor-path
guide, separately from deployed restart/restore acceptance. The standalone
topology suite (76 tests), documentation build, and low-level audit passed.

The acceptance checker is now part of the broad security-script `checkJs`
gate in Quality CI. Its private-file and decision-chain tests continue to
cover runtime behavior. The script's parsed input objects are not yet in the
strict no-implicit-any boundary, and typechecking does not authenticate an
operator decision or live ledger receipt.

The decision-chain evaluator has since been extracted into a side-effect-free
module in the strict no-implicit-any gate. It rejects malformed or reordered
records, mismatched source and prior status, and a `pass` made stale by later
evidence. The original CLI continues to own private-file reads and digests.
This improves reviewability of the acceptance inventory but does not change
the self-attested nature of decisions or make a fixture browser run a local
ledger qualification.

The protected npm publish job now verifies the registry's SHA-512 integrity
against each exact manifest-checked tarball before skipping an already
published immutable version. A lookup error other than an explicit npm 404,
or missing/weak/mismatched integrity metadata, stops publication. Tampered
tarball and malformed metadata negatives cover this idempotent resume path.
This closes an artifact-byte gap in #236 locally; exact-head protected CI,
release-owner approval, and independent review remain required before the
release gate can be considered satisfied.

The local standalone node pin was advanced from 1.0.0 to the arm64 manifest of
the official 1.0.400 security release. The latter includes the ledger-8.1.3
canonical contract-call fix; retaining 1.0.0 as the next RC install would miss
that patch. A disposable three-service bridge showed node, existing indexer,
and proof server healthy, with indexer GraphQL reachable. A node-only restart
preserved its self-reported genesis and an earlier block. Despite matching
hashes for the `dev` configuration and packaged `undeployed` genesis inputs,
the fresh node reported a **different genesis hash** from the old b28 node.
The prior proposed pin cannot be reused; the complete new chain specification
needs independent review and a new human signature. The test project and its
fresh volumes were removed; b28 private evidence and volumes were retained.
Node 1.0.400 lacks Python, so new v6 bundles host the pinned installation
relay in the separately verified API image with its normal API healthcheck
disabled for that one temporary container. The relay verifier still accepts
historical node-hosted bundles for audit and checks the new API image identity,
entrypoint, mount, effective loopback ports, and network attachments. These
are implementation and pre-deployment compatibility findings, not a deployed
contract, independent finality, offline actor, or release approval.

The opt-in local issuer writer now requires its authenticated snapshot reader
to return the same deployment image checked by the read-only signed API plan:
network, contract, full verifier-key hashes, maintenance authority and
governance action count. It checks these on preparation and every SDK reread,
so a governance mutation cannot be submitted under a stale manually signed
plan merely because contract and genesis still match. The reader callback
must still independently authenticate finality; the packaged CLI does not
instantiate the writer, and these injected-dependency tests are not a live
standalone actor journey.

The local API v3 approval-chain verifier initially required one reviewer key
for genesis, committee, deployment, and API plan signatures. The later
`bbe527cf` change permits an independent genesis reviewer while retaining a
single pinned governance reviewer for committee, deployment, and API plan.
Governance must sign the exact genesis-approval digest; a second valid public
key in the keyring cannot substitute a genesis approval without a matching
governance approval. The focused test exercises both a rejected substitution
and a correctly linked approval signed by a different genesis reviewer.
This is one #234 identity link, not proof that the maintenance readback is
independently finalized, that deployment is qualified, or that human security
review is complete. A future governance-reviewer rotation still needs an
explicit signed protocol rather than a silent keyring change.

The local deployment and staged-reconciliation shell is now in the strict
security-script type gate. Its plan type distinguishes full from staged
deployment, so only the staged call carries an initial verifier-key name.
Parsed release manifests and provider factory results enter as `unknown` at
the dynamic-code boundary; a malformed or empty verifier-key hash catalog
stops before endpoint observation or provider import. The test fixture now
uses a realistic nonempty catalog and adds an early-denial case. Strict
typechecking does not prove that a dynamically loaded provider is benign or
that its output is a finalized ledger result; immutable installation, signed
approval, and live reconciliation remain separate gates.

The staged verifier-key insertion shell is also in the strict type gate. Its
plan type no longer intersects incompatible deployment and insertion format
literals; the checked code narrows an approved staged receipt before
comparing it to the setup record and routes submit versus read-only
reconciliation through distinct typed functions. It treats parsed manifests
and provider material as untrusted boundary values and rejects a malformed
verifier-key catalog before endpoint or provider use. This does not prove a
key was inserted on a deployed local ledger or that finality is independently
authenticated.

The local issuer SDK and the generic governed-proposal HTTP preflight now
apply Compact's distinct-maintainer-public-key quorum rule before an HTTP
journal reservation. Two registered key IDs backed by one Jubjub public key
are rejected even when their signatures verify. A synthetic-ledger HTTP test
uses a real file journal and checks that no reservation or submission occurs;
it is not a deployed-ledger actor test. This closes a deterministic
pre-broadcast wedge identified under #220, not the broader audited recovery
policy for a reservation whose network outcome is unknown.

## Local proposal recovery proof boundary

Issue #220 remains a local RC safety/liveness gate. The candidate and
detached-signed decision verifier are read-only, but the opt-in file journal
now has an internal abandonment transition. It rechecks the exact reserved
attempt under the existing lock, requires a deployment-owned finality callback
and a distinct reviewer's signed decision, and durably records a terminal
tombstone that blocks replay of the original ID. Focused tests cover
simulator-injected invalidation, competing journal instances, late receipts,
rotation, restart, and a later different proposal. The callback used by those
tests is not a production finality authenticator. The packaged API/CLI exposes
no approved operator recovery command, and there is no reviewed complete
action-history proof or deployed Compact stale-action check. The
[recovery specification](../spec/local-proposal-recovery.md) requires those
independent proofs and human review before a real reservation can be released.
A null indexer read, timeout, or new journal path cannot substitute for them.

## Static runtime archive type boundary

The standalone installer now strictly type-checks the static API/portal
healthcheck shape and Docker/OCI archive verifier. Parsed image metadata and
asset manifests enter as unknown values and are narrowed before role,
revision, layer, and asset decisions. The installer rejects malformed OCI
layers and inherited runtime role names; the existing source-matched image
and digest rules remain in force. This extends issue #229's strict security
boundary without claiming that the broader bundle I/O shell or first-run
wizard is fully typed. Focused archive, install-inventory, and mapping tests,
the strict and broad security-script type gates, docs build, source lint, and
dependency audit passed in the writable checkout. The read-only exact-head
Codex review found no actionable regression; its temp-file tests could not
run under its sandbox. None of these results is a deployed local-ledger actor
journey or independent finality evidence for #219.

## Latest local standalone evidence boundary

At signed/DCO source `7efcf607`, a verified source-matched v6 install and
dedicated `wizard-7efc-1` setup passed pinned-bundle checks, internal ledger
topology and local canary denial, and pre-deployment restart continuity.
The node-reported genesis candidate and proposed pin remain untrusted; the
journey prerequisite check stopped at the unsigned genesis approval. No
registry contract was deployed, no independent finality was authenticated,
and no offline actor or distinct-project restore test ran. The containers
were stopped without removing their volumes or private evidence. Later
source changes make the install historical rather than a current-head RC
candidate. The [acceptance map](../plans/milestone-0.1.0-acceptance-map.md)
records its inventory and untrusted-candidate digests without publishing the
private review packet. A new exact-source install and independently signed
approval are required before live qualification can resume.

## Demo E2E build safety

The demo E2E command previously ran its four signed simulator journeys before
building the packages they imported. Individual demo and browser aliases also
used `build:light`, which removes full generated Compact output. The shared
prebuilt-runtime build now checks the copied Compact source and generated
contract-module presence, restores missing generated source declarations from
the preserved `dist` copy (rejecting mismatches), and recompiles contract
TypeScript helpers and downstream TypeScript/UI workspaces. It is used by the
documented commands and prebuilt integration lane. A missing or
stale prebuilt contract stops before a journey rather than silently selecting
a destructive light build. This prevents stale package results and protects
artifact-bearing checkouts; the check does not independently authenticate
generated-code provenance or turn fixture E2E into deployed-ledger evidence.

## Journal authority after provider restart

Issue #230 isolates a restart safety invariant from the larger deployed
recovery gate. The pinned provider's in-memory deployment sets are only
same-process guards; the private, deployment-bound proposal journal is the
cross-restart authority. The issuer SDK integration test now loses a mocked
node submission response, resets the provider module, opens the same journal,
and verifies that a newly constructed provider cannot cause a second
broadcast. Existing API HTTP tests separately recreate the listener and
proposal port; journal tests cover write failure and finalized reconciliation.
Both restart scenarios now run in the API light test lane with injected
node/ledger state, alongside the journal write-failure and reconciliation
suite. They do not use a public or deployed local network.
No test in this group establishes a deployed ledger, authentic finality, or
permission to clear an unobserved reservation. The #220 recovery proof and
#219 offline actor qualification remain open.

## Local RC independent review handoff

The published local qualification stack is now draft PRs #238, #239, and
#240, not the older seven-branch publication plan. The
[review-stack plan](../plans/local-0.1.0-review-stack.md) records their order
without freezing their heads. The
[security-review handoff](../plans/local-0.1.0-security-review-handoff.md)
gives the independent reviewer an exact-source inventory and the trust
boundaries to inspect for #232. It is a checklist, not an attributable human
verdict. The unpublished local descendants and passing fixture tests do not
change the published PR checks or the missing signed genesis, authenticated
deployed readback, offline actor, restore, and VC-owned status evidence.

The journey prerequisite CLI is exercised against a temporary wizard setup
record, not only a synthetic status object. It exits blocked before genesis
approval, remains blocked after a node-only observation, and reports a stale
candidate source revision as the first safe action. This is a fail-closed
operator preflight test, not a real deployment or actor E2E result.

## Fractional application-evidence time boundary

The application-evidence envelope, challenge-backed intake, and local issuer
writer now compare RFC3339 instants without truncating fractional digits to
milliseconds. The exact 24-hour evidence lifetime is accepted; an additional
fractional digit is rejected. Intake rejects a VP verification instant just
after the trusted evaluation time before consuming the one-use challenge,
and the local issuer port rejects trusted time just before `verifiedAt`.
This fixes one #179 trust-decision boundary. Other `Date.parse` uses in
recognition, policy, and adapter decisions still require the independent
audit; this slice does not close #179 or prove a deployed actor journey.

## Fractional recognition-assertion boundary

Recognition authority assertions now enforce their 24-hour lifetime at full
RFC3339 fractional precision. The signed DID assertion verifier likewise
compares exact expiry with the millisecond trusted evaluation instant, so a
statement expiring just after that instant remains current, while one expiring
exactly at it does not. A signed-assertion integration test covers that
boundary and an overlong lifetime. This narrows #179 but does not address the
remaining recognition/accreditation, policy, and adapter timestamp decisions.
The test uses a fixture DID resolver; it is not a standalone deployed-ledger
actor journey or independent VC status-authority evidence.

## Domain record chronology precision

The shared lifecycle and effective-window validators now use the exact
RFC3339 instant comparator instead of `Date.parse` millisecond truncation.
Policy, participant, authorization, and recognition schemas reject reversed
sub-millisecond chronology while accepting equivalent offset spellings.
Regression tests exercise a 10-digit fraction and malformed timestamps.
Other trust-decision and adapter sites remain in the #179 audit; this domain
validator fix is not a deployed standalone E2E result.

## Recognition challenge fractional-time consumption

The one-use recognition authority challenge now checks the signed assertion's
issue time against its stored millisecond window and its expiry against the
trusted consume clock without dropping signed fractional digits. An assertion
signed a fraction after the trusted clock is rejected without spending the
challenge; an assertion expiring a fraction after that clock remains current.
Out-of-range stored window timestamps fail before conversion. Persisted
admission expiry remains conservatively rounded down to milliseconds. These
tests use a fixture DID resolver and in-memory challenge store, so they do not
establish a deployed standalone actor journey or close #179's wider audit.

## TRQP evidence epoch order beyond milliseconds

The API source now sorts matching authorization and recognition bundles by
their full RFC3339 epoch start before using epoch ID as a tie-breaker. Two
source-level regressions place the newer bundle only one 10-digit fractional
step after the older within the same millisecond, with IDs arranged to favor
the older one under the former `Date.parse` sort. These tests narrow #179's
historical evidence-selection risk but use synthetic operator snapshots, not
an authenticated local-ledger history or deployed actor E2E evidence.

## Application status-attestation time precision

The DID-signed application status-attestation verifier compares the complete
RFC3339 instant for the one-minute future limit, five-minute observation age,
expiry, and five-minute signed lifetime. A signature just beyond a boundary
cannot enter by losing fractional digits in `Date.parse`; an exactly
five-minute fractional window remains valid. The integer-millisecond
`validUntilMs` returned to the VP verifier is conservatively rounded down.
The focused tests re-sign fixture statements with the local test key. They
also send the fixture over a real loopback HTTP listener and exercise the
published VC/VP intake through the transport, accepting a current signed
answer and rejecting a newly signed fractionally overlong one. The DID, VC,
status authority, and ledger state are still fixture-owned: this does not
supply a VC-owned live status adapter, independent finality, or a deployed
offline actor journey. Those release gates remain open.

## Policy replay isolation and current E2E boundary

The unpublished local policy-replay slices extracted old-policy signer checks
and historical HTTP checks from the governed demo into focused helpers. A
separate regression runs snapshot publication and policy replay in different
simulator harnesses, so the snapshot's governance actions cannot accidentally
advance the replay sequence. It verifies that old-policy signatures fail for
the prepared issuer decision without creating an authorization, while fresh
signatures for the same payload and sequence succeed. The isolated adversarial
runner also rejects a TAP subtest attributed to a different case ID or more
than one top-level outcome. Local validation recorded 198 individually
attributed adversarial cases, 235 demo-smoke tests, the four signed simulator
role journeys, ten fixture-browser tests, and the prebuilt integration lane
with all 66 full proof circuits. These are regression and fixture results,
not a deployed standalone E2E run or release qualification.

The private b23 setup remains pre-deployment and is tied to older source
`6a5b2529`; its node-reported genesis candidate is unapproved. No current
source-matched, human-signed genesis approval or authenticated finalized
contract readback exists. The packaged local API is read-only and has no
qualified governed-write actor host or VC-owned live status adapter. The next
real E2E attempt must start from a new exact-source install, independent
genesis and committee approvals, and a live finalized deployment; it must
then record actor writes and reads with runtime egress denied, followed by
deployed restart/restore and independent human security review. None of the
local regression results above can be attached as a passing `A01`-`S01`
acceptance case.

## Acceptance decision-history metadata

The local acceptance inventory now rejects malformed reviewer identifiers,
reason codes, noncanonical decision timestamps, and a decision timestamp that
precedes an earlier decision in the same case. A legacy case labeled before
the decision-chain feature may still record its prior label in its first
decision; the new decision is required before that case counts as
decision-backed. These checks preserve a coherent local audit trail but do
not authenticate the operator, receipts, finality, or human security verdict.

## Standalone qualification observer type boundary

The broad checked-JS CI gate now names the ledger topology, rendered Compose,
aggregate qualification, and API restart observers directly. Its three egress
probe modules were already included transitively; direct roots make the other
entry points explicit rather than depending on incidental imports. The
aggregate starts with unknown child results and narrows them only after the
runtime scope validators reject malformed or inflated evidence. This reduces
type drift, but it does not prove Docker's effective isolation, independently
authenticate finality, run a governed actor, or satisfy the human security
review. Those release gates remain open.

## Issuer writer-annex time source

The opt-in issuer proposal port now checks the signed writer annex's validity
window against the same deployment-owned trusted-time result used for the
accepted evidence at prepare, preflight, execute, and pre-broadcast recheck.
The host clock remains an additional startup/fast-fail check, not a way to
extend the annex if it rolls backward. Focused tests cover a trusted time
before `notBefore` and after `notAfter` while the host clock and accepted
evidence would otherwise allow preparation. This still uses injected time,
ledger, and status dependencies; it does not supply the production adapter
or a deployed local actor journey required by #219.

## Reviewed npm artifact handoff

The local #236 publish workflow separates release-byte preparation from the
protected npm publication job. Preparation builds the exact signed source,
generates and verifies the release manifest against the complete packed
tarball set, runs a clean-consumer smoke, and uploads the tarballs and manifest.
Its job output and summary identify the source revision, version, and manifest
SHA-256 before `npm-publish` approval is requested. The protected job downloads
that artifact, checks the recorded manifest digest, rebuilds full Compact
outputs from the same source, verifies the manifest and tarballs again, and
reruns the consumer smoke before publishing. The publisher separately checks
each tarball immediately before its registry operation.

This is a byte-integrity and review-order gate, not proof of an independently
approved release. GitHub must have required reviewers configured on the
`npm-publish` environment; workflow YAML cannot impose them. The release
owner must inspect the prepared artifact and its digest before approval, and
the publish runner remains inside the trusted computing base after the final
check. No npm publish or exact-head hosted CI has run for this unpublished
slice. It does not satisfy the signed local genesis, finalized deployment,
offline actor E2E, recovery, VC status-authority, or human security gates.
