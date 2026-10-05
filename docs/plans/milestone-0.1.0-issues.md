# 0.1.0 Executable Issue Plan

Status: active milestone backlog
Updated: 2026-10-05
GitHub milestone: [Midnight Trust Registry 0.1.0](https://github.com/midnightntwrk/midnight-trust-registry/milestone/1)
Normative scope: [0.1.0 reference profile](../spec/milestone-0.1.0.md)

Issue numbers are the tracker identifiers. The order below is the dependency
order, not a promise that every issue requires a separate PR. A PR may close
several issues only when each definition of done has evidence. Existing closed
issues #54-#57 and ADRs are inputs, not work to recreate.

## Milestone Map

| Order | Issue | Slice / actor coverage | Depends on |
| --- | --- | --- | --- |
| 1 | [#49](https://github.com/midnightntwrk/midnight-trust-registry/issues/49) | Reconcile spec, backlog, and knowledge base | Existing baseline |
| 2 | [#75](https://github.com/midnightntwrk/midnight-trust-registry/issues/75) | Canonical scope and policy snapshots: issuer, verifier, auditor, maintainer, relying party | #49, ADR-0001, ADR-0002 |
| 3 | [#76](https://github.com/midnightntwrk/midnight-trust-registry/issues/76) | Real VC/VP evidence attestation: applicant and evidence verifier | #75 |
| 4 | [#67](https://github.com/midnightntwrk/midnight-trust-registry/issues/67) | DID-bound on-chain evidence signature | #75, #76 |
| 5 | [#77](https://github.com/midnightntwrk/midnight-trust-registry/issues/77) | Authenticated mutation gateway: applicant, maintainer, operator | #67, #75 |
| 6 | [#39](https://github.com/midnightntwrk/midnight-trust-registry/issues/39) | Historical API and TRQP evidence | Scope profile and #67 |
| 7 | [#79](https://github.com/midnightntwrk/midnight-trust-registry/issues/79) | Produce authenticated issuer/verifier decision evidence | #75, #39 |
| 8 | [#73](https://github.com/midnightntwrk/midnight-trust-registry/issues/73) | Publish VC-compatible signer descriptors and authority proofs for Ledger 8 consumers | #67, #79 |
| 9 | [#58](https://github.com/midnightntwrk/midnight-trust-registry/issues/58) | Issuer VC/VP governed journey | #67, #77, #39, #73 |
| 10 | [#78](https://github.com/midnightntwrk/midnight-trust-registry/issues/78) | Other governed role journeys: verifier, auditor, recognition, maintainer | #58, #67, #77 |
| 11 | [#59](https://github.com/midnightntwrk/midnight-trust-registry/issues/59) | Applicant, operator, relying-party HTTP/UI journey | #77, #58, #73 |
| 12 | [#60](https://github.com/midnightntwrk/midnight-trust-registry/issues/60) | Adversarial and historical security matrix | #58, #78, #73 |
| 13 | [#45](https://github.com/midnightntwrk/midnight-trust-registry/issues/45) | Release candidate and attestable package gate | All prior milestone issues |

## Use-Case Ownership

The lead issue owns a positive and rule-specific negative case. The security
suite #60 adds adversarial mutations, not a substitute for the lead tests.

| Use cases | Lead issue | Required evidence |
| --- | --- | --- |
| UC-01 bootstrap, UC-02 policy revision | #75 | Genesis/threshold fixture and immutable policy history |
| UC-03 maintainer lifecycle, UC-04 evidence verifier key | #78, #67 respectively | No self-enrollment; active DID-bound assertion key and retirement |
| UC-05 issuer, UC-06 verifier, UC-07 auditor applications | #58, #78, #78 respectively | Real VC/VP eligibility, exact scope, quorum, negative status |
| UC-08 quorum decision, UC-09 lifecycle action | #58, #78 respectively | Bound commitment and threshold-specific transition |
| UC-10 external recognition | #78 | No transitive local authorization |
| UC-11 epoch, UC-12 historical query | #39 | Accepted root, signer/policy history, tampered-proof rejection |
| UC-13 holder presentation | #58 | VC proof, status, and issuer trust evaluated separately |
| UC-14 auditor request | #78 | Exact mandate, no automatic data access |
| UC-15 VC consumer anchor | #73 | Authority proof, pinned Ledger 8 anchor, monotonic updates |

## Existing Issue Amendments

### #49: reconcile the public planning surface

- [ ] Land the 0.1.0 profile, actor/use-case matrix, issue plan, backlog, and
      updated knowledge-base snapshot together.
- [ ] Link each milestone issue to an acceptance criterion and make deferred
      work visible without claiming it is implemented.
- [ ] Ensure the milestone description and GitHub assignment match the docs.

Done when docs checking passes and no current section calls an already merged
PR or closed issue "open". Validation: `./scripts/check-docs.sh` and
`git diff --check`.

### #67: verify evidence against an authorized DID assertion key

The existing issue body is substantially executable. Strengthen its completion
review with these checks:

- [ ] Four non-bootstrap applicant roles submit a real signed commitment to
      Compact; contract verifies the active registered verifier DID/key.
- [ ] Rotated and retired keys have deterministic historical semantics.
- [ ] Missing, mismatched, expired, replayed, and policy-ineligible evidence
      fails inside the contract; no callback result can substitute for a proof.
- [ ] The simulator's deterministic `SHA-256(commitment:keyId)` signature is
      absent from the conformance path.

Validation: `./run.sh --light`, focused Compact tests, `./run.sh integration`.

### #39, #58, #59, #60, and #45: acceptance alignment

- #39 MUST return a historical epoch, policy version, exact scope, and
  independently verifiable proof for native API requests; TRQP historical
  responses remain a named extension. Its UC-11 fixture MUST publish a valid
  epoch and reject an invalid root or signer before that view can be queried.
- #58 MUST consume the real evidence-verifier adapter and DID-bound contract
  path and the #73 signer descriptor, then test accepted, wrong-scope, suspended,
  revoked, expired, and wrong-registry issuer outcomes. Its credential decision
  MUST use the VC composed `VC<>::assertAuthorizedIssuerProof` path, not the
  metadata-only descriptor helper.
- #59 MUST exercise authenticated applicant and maintainer intents through the
  public API/UI, assert fail-closed stale/replayed writes, and compare the
  public query with client evidence verification.
- #60 MUST include self-approval, duplicate/removed signer, insufficient
  quorum, key substitution, policy/time replay, tampered Merkle proof, and
  recognition-as-authorization attempts. Each case names its invariant.
- #45 becomes the final 0.1.0 gate: pin source/compiler/package versions,
  produce digest-verified npm and contract artifacts, and record clean-checkout
  validation plus explicitly deferred capabilities. It must not publish a
  release until all milestone blockers pass.

## Issue #75: Canonical scope and policy snapshot conformance

Tracker title: `feat(domain): enforce canonical scopes and policy snapshots across registry surfaces`

Why: ADR-0001 and ADR-0002 describe exact scope IDs and immutable policy
versions, while the current contract exposes opaque byte fields and the
application evidence domain uses a separate JSON commitment. Independent
writers need one set of vectors before the contract and API accept VC-backed
applications.

Subtasks:

- [ ] Implement one versioned encoder for issuer, verifier, auditor, and
      maintainer scope objects; normalize sorted arrays and reject unknown
      fields, duplicate fields, wildcards, and ambiguous versions.
- [ ] Define policy ID/version/effective-window commitment and action-family
      threshold snapshot; bind it to application and governance events.
- [ ] Publish the three-maintainer, 2-of-3 reference fixture for ordinary,
      membership, emergency, and archival families; reject self-vote and a
      transition that would leave fewer active maintainers than the threshold.
      Reject a threshold above the current Compact five-signer ceiling.
- [ ] Exercise one-time bootstrap versus duplicate initialization and a
      versioned policy revision versus reinterpretation of an old decision.
- [ ] Publish JSON and byte-level vectors consumed by domain, Compact wrapper,
      client, API, TRQP adapter, and OpenID Federation projection where used.
- [ ] Resolve whether a rejected proposal is terminal and how a superseding
      application references its predecessor; update lifecycle fixtures.
- [ ] Include an explicit migration note for old ordinal-status or root-only
      policy records.

Definition of done: the same input yields the same 32-byte scope and policy
commitments across implementations; mismatched version/scope fails closed;
existing live records retain their historical policy interpretation. Tests
cover each role plus field order, array order, version change, wildcard, and
duplicate-ID negatives. Validation: `./run.sh --light` and
`./run.sh integration` for contract-facing changes.

Depends on: ADR-0001, ADR-0002, #49. Labels: `trust-registry`, `governance`,
`architecture`, `contract`.

## Issue #76: Verify VC/VP eligibility and sign the result

Tracker title: `feat(evidence): verify Midnight VC/VP eligibility and sign application attestations`

Why: a real 0.1.0 journey needs DID-bound assertion-key authorization and
actual VC/VP, status, and policy verification before on-chain governance.
The simulator now uses a real test-key JubJub signature over the evidence
commitment, but its verifier key is not yet resolved from a DID.

Subtasks:

- [ ] Build a fixture-backed evidence-verifier adapter using public DID/VC
      package interfaces; verify applicant DID control, challenge binding,
      credential issuer, status, expiry, and role-specific claims.
- [ ] Restore end-to-end accepted, mismatched-registry, and revoked-status
      scenarios through a published status-authority package or adapter. The
      published VC core 0.2.0 validates status-reference shape and commitment,
      but does not replace the retired status-registry verification helper.
- [ ] Anchor the accepted status-registry identifier and authority key to the
      issuer authorization statement or a signed policy commitment. The
      bundle's current `referencedStatusRegistryId` metadata is outside the
      signed authorization leaf and must not authorize a VC status binding.
- [ ] Sign the canonical envelope commitment with the evidence verifier's
      Midnight DID assertion key; expose the key reference and verification
      result without returning the raw VC/VP from a public API.
- [ ] Define challenge issuance, expiry, one-use nonce storage, redacted error
      categories, and retention boundary for off-ledger transcripts.
- [ ] Provide positive fixtures for issuer, verifier, auditor, and maintainer,
      plus stale status, wrong subject, challenge replay, wrong claim, wrong
      scope, and expired credential negatives.
- [ ] Document the package boundary and a focused command to rerun the tests
      from a clean checkout.

Definition of done: a valid VC/VP yields a real signed commitment that the
#67 contract path can verify; invalid evidence never reaches proposal; no raw
credential, presentation, or holder identifier appears in a journal, ledger,
bundle, or report. Validation: `./run.sh --light` and
`./run.sh integration`.

Depends on: #75. Labels: `trust-registry`, `backend`,
`security`, `e2e`.

## Issue #79: Produce authenticated issuer/verifier decision evidence

Tracker title: `feat(client): verify issuer/verifier decision evidence for VC anchors`

Why: a VC `AuthorizedSignerDescriptor` must be derived from a real governed
grant and active DID key, not from a caller-provided boolean or root. Current
TR bundles prove authorization history but do not bind an exact DID method,
observed DID version, and the authority context needed for descriptor signing.

Subtasks:

- [ ] Define a versioned TR decision-evidence bundle with registry DID/network,
      independently accepted epoch root, exact issuer or verifier grant,
      policy version, DID method/key and relationship, DID state version,
      lifecycle state, quorum evidence, and Merkle inclusion proof.
- [ ] Export a package-level builder and independent verifier that checks the
      configured registry root, epoch quorum, policy/scope/time bounds, DID
      state and key, and inclusion proof before producing a descriptor candidate.
- [ ] Define the mapping of `active`, `suspended`, `revoked`, `superseded`, and
      `archived` TR states to a current issuer/verifier decision; no stale or
      superseded record may become a new active descriptor.
- [ ] Keep artifact/deployment references as digest-verified governed metadata,
      not mutable binary storage; distinguish applicant eligibility evidence
      from post-approval signer authorization evidence.
- [ ] Add issuer and verifier positive fixtures, plus wrong-network, unpinned
      root, stale epoch, withdrawn schema, suspended party, wrong request
      profile, substituted DID key, invalid signer, and tampered proof negatives.

Definition of done: the exported verifier returns a typed, authenticated
decision candidate with exact method/key, scope, policy, and DID version; each
listed mutation fails before #73 may sign it. The package and JSON schema are
documented and independently testable from a clean checkout. Validation:
`./run.sh --light`, `./run.sh integration`, and focused evidence-vector tests.

Depends on: #75 and #39. Labels: `trust-registry`, `backend`, `security`, `e2e`.

## Issue #73: Publish VC signer descriptors and authority proofs

The existing issue becomes a 0.1.0 blocker. Its acceptance is the current
[VC signer-authorization specification](https://github.com/midnightntwrk/midnight-verifiable-credentials/blob/develop/spec/signer-authorization.md),
not the older transcript-digest draft.

- [ ] Map #79's verified decision to VC `AuthorizedSignerDescriptor` v1 with
      exact native field order, role, method/key, relationship, DID state
      version, policy commitment, and monotonic decision sequence.
- [x] Align the published Midnight DID dependency to 0.7.0 and verify the
      adapter's canonical fragment and DID-state mapping without importing
      sibling repository source.
- [x] Replace the legacy VC 0.1.0 credential tarballs with published VC core
      and DID-binding 0.2.0 packages, pinned in the lockfile and installed in
      a clean consumer. This dependency migration does not complete the
      verified TR decision-to-VC descriptor bridge above.
      #48's automated refresh policy remains a separate, deferred task.
- [ ] Use VC `persistentHash<SchemaRef>` for issuer scope; define the exact
      signed request-profile commitment for verifier scope. Publish vectors
      against VC's checked-in signer-authorization conformance suite.
- [ ] Specify `domainCommitment` preimage (network, consumer contract,
      registry, authority), governed authority key lifecycle, and the signer
      service's refusal to sign a decision without a committed quorum.
- [ ] Produce the VC authority `Proof` with `createdAt == decisionSequence`;
      sign the domain-bound decision root with a native Jubjub key.
- [ ] Compile/run a Ledger 8 consumer fixture with a locally pinned authority;
      reject witness-supplied anchors, wrong domain/method/key/scope, stale
      sequence, DID-version rollback, and revoked-to-active replay.
- [ ] In the consumer fixture, use the VC composed
      `VC<>::assertAuthorizedIssuerProof` for credential decisions and prove
      that a forged credential signature fails despite matching descriptor
      metadata. Use `assertAuthorizedVerifierProof` for signed verifier requests.
- [ ] Document asynchronous revocation delivery and the distinction between
      current VC descriptor semantics and separate TR historical epoch queries.

Definition of done: a clean-checkout TR package and fixture export issuer and
verifier descriptors and proofs accepted by the current VC core consumer
checks; every listed substitution fails. No source import crosses repositories.
Validation: `./run.sh --light`, `./run.sh integration`, VC conformance vectors,
and a focused Ledger 8 fixture smoke test. Depends on #67 and #79.

## Issue #77: Authenticate mutation actors and make writes replay safe

Tracker title: `feat(api): require DID-signed applicant and maintainer mutation intents`

Why: the local workspace-backed API currently accepts `target` and `label`
for submission and invokes maintainer actions without a caller signature.
That is suitable for a loopback demo, not the governed actor journey required
for 0.1.0.

Subtasks:

- [ ] Define a domain-separated signed intent with registry ID, actor DID,
      role, action, target ID, exact scope/payload commitment, nonce, expiry,
      and expected workspace/epoch version.
- [ ] Verify the DID key and role at the applicable time, then pass explicit
      maintainer signatures to the Compact-backed operation; never sign for
      a caller inside the server.
- [ ] Reject replay, cross-role action, self-approval, stale version, invalid
      signature, expired intent, and payload substitution before journal write.
- [ ] Add atomic/idempotent mutation semantics and structured 401/403/409
      problem responses; define a fail-closed multi-process writer rule.
- [ ] Wire applicant portal and admin console to the exported API contract and
      provide test-only local key fixtures for the demo.

Definition of done: the unauthenticated `POST /v1/applications`, lifecycle,
and epoch write paths cannot mutate state; two distinct maintainer identities
can approve under a nontrivial quorum; no failed request changes the journal.
Validation: `./run.sh --light`, API integration, `./run.sh integration`, and
`pnpm run demo:smoke`.

Depends on: #67 and #75. Labels: `trust-registry`,
`backend`, `application`, `security`.

## Issue #78: Prove verifier, auditor, recognition, and maintainer journeys

Tracker title: `test(e2e): cover governed verifier, auditor, recognition, and maintainer roles`

Why: #58 intentionally focuses on the issuer path. 0.1.0 also promises
separate scoped rights for verifier, auditor, external authority, and
non-bootstrap maintainer.

Subtasks:

- [ ] Prove verifier application through active exact request-profile grant;
      reject excess attributes, predicates, purpose, and disclosure.
- [ ] Prove auditor mandate application and exact audit-profile lookup; test
      that authorization alone yields no holder or verifier data.
- [ ] Prove external recognition and show it cannot be used as a local issuer
      or maintainer grant.
- [ ] Prove maintainer onboarding with no self-approval, quorum change,
      suspension, and last-active-maintainer protection.
- [ ] Export a scrubbed evidence report with policy version, epoch, signer
      set, and expected result for every actor.

Definition of done: each UC-03/06/07/09/10/14 path has a positive and
rule-specific negative automated case using the real evidence path. The suite
is deterministic and runs through `./run.sh integration` with expensive
proving variants documented separately.

Depends on: #58, #67, #77. Labels: `trust-registry`,
`governance`, `e2e`, `security`.

## Deferred Beyond 0.1.0

- Ledger 8 synchronous cross-contract calls and production relayer monitoring
  are not part of this reference profile. The #73 consumer fixture verifies
  portable signed decisions with an authority pinned in its own state.
- [#61](https://github.com/midnightntwrk/midnight-trust-registry/issues/61),
  [#62](https://github.com/midnightntwrk/midnight-trust-registry/issues/62),
  [#63](https://github.com/midnightntwrk/midnight-trust-registry/issues/63),
  and [#64](https://github.com/midnightntwrk/midnight-trust-registry/issues/64):
  curated dependency policy, docs site, change-aware CI, and extra repository
  boundary automation. Keep them open, outside the product milestone.
- [#40](https://github.com/midnightntwrk/midnight-trust-registry/issues/40)
  through [#44](https://github.com/midnightntwrk/midnight-trust-registry/issues/44),
  [#47](https://github.com/midnightntwrk/midnight-trust-registry/issues/47),
  and [#48](https://github.com/midnightntwrk/midnight-trust-registry/issues/48)
  need implementation-reference reconciliation against merged PR #71 before
  closure. Do not recreate their work or count them as 0.1 blockers without
  identifying an actual missing acceptance criterion.
