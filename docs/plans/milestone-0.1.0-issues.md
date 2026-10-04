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
| 5 | [#77](https://github.com/midnightntwrk/midnight-trust-registry/issues/77) | Authenticated mutation gateway: applicant, maintainer, operator | #67 |
| 6 | [#39](https://github.com/midnightntwrk/midnight-trust-registry/issues/39) | Historical API and TRQP evidence | Scope profile and #67 |
| 7 | [#79](https://github.com/midnightntwrk/midnight-trust-registry/issues/79) | Produce issuer/verifier trusted-anchor evidence for VC consumers | #75, #39 |
| 8 | [#58](https://github.com/midnightntwrk/midnight-trust-registry/issues/58) | Issuer VC/VP governed journey | #67, #77, #39, #79 |
| 9 | [#78](https://github.com/midnightntwrk/midnight-trust-registry/issues/78) | Other governed role journeys: verifier, auditor, recognition, maintainer | #58 |
| 10 | [#59](https://github.com/midnightntwrk/midnight-trust-registry/issues/59) | Applicant, operator, relying-party HTTP/UI journey | #77, #58, #79 |
| 11 | [#60](https://github.com/midnightntwrk/midnight-trust-registry/issues/60) | Adversarial and historical security matrix | #58, #78, #79 |
| 12 | [#45](https://github.com/midnightntwrk/midnight-trust-registry/issues/45) | Release candidate and attestable package gate | All prior milestone issues |

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
  responses remain a named extension.
- #58 MUST consume the real evidence-verifier adapter and DID-bound contract
  path and the #79 trust anchor, then test accepted, wrong-scope, suspended,
  revoked, expired, and wrong-registry issuer outcomes.
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

Suggested title: `feat(domain): enforce canonical scopes and policy snapshots across registry surfaces`

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

Suggested title: `feat(evidence): verify Midnight VC/VP eligibility and sign application attestations`

Why: the current simulator fabricates `SHA-256(commitment:keyId)` as a
signature. A real 0.1.0 journey needs actual DID, VC/VP, status, and policy
verification before on-chain governance.

Subtasks:

- [ ] Build a fixture-backed evidence-verifier adapter using public DID/VC
      package interfaces; verify applicant DID control, challenge binding,
      credential issuer, status, expiry, and role-specific claims.
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

## Issue #79: Produce VC-compatible issuer/verifier trusted anchors

Suggested title: `feat(client): export verified issuer/verifier trust anchors for VC consumers`

Why: the VC verification v1 contract reserves `trustScopeDigest`,
`trustEvidenceDigest`, and trust `EvidenceBindingV1` for an accepted
issuer/verifier/schema decision. VC explicitly delegates production of this
proof to the trust registry. Existing TR evidence bundles are not yet a
VC-compatible issuer-plus-verifier anchor, and a digest alone proves nothing.

Subtasks:

- [ ] Define a versioned `TrustAnchorEvidenceV1` with registry DID/network,
      independently pinned registry root, issuer DID/family/schema grant,
      verifier DID/request-profile grant, effective times, policy version,
      accepted epoch(s), and both inclusion proofs; specify field order,
      presence rules, digest framing, and public JSON schema.
- [ ] Export a package-level builder and independent verifier that checks the
      configured registry authority, epoch signer quorum, policy/time bounds,
      DID/key state where required, active issuer/verifier statuses, exact
      schema/profile scope, and proof inclusion before returning a trusted
      result.
- [ ] Map the verified bundle to the VC v1 `trustScopeDigest` and trust
      `EvidenceBindingV1`/`trustEvidenceDigest` inputs with TS/Compact-compatible
      vectors; document which canonical bytes are owned by TR versus VC.
- [ ] Keep artifact/deployment references as digest-verified governed metadata,
      not mutable binary storage; distinguish application evidence attestation
      from a post-approval trusted anchor.
- [ ] Add issuer-only and issuer-plus-verifier positive fixtures, plus
      wrong-network, unpinned root, stale epoch, withdrawn schema, suspended
      issuer/verifier, wrong request profile, invalid signer, and tampered
      inclusion negatives.

Definition of done: a VC integration can consume a TR-produced trust anchor
without reconstructing authority from an API boolean or caller-supplied hash;
the exported verifier rejects every listed mutation and the digest vectors
match the declared VC contract. The package and evidence schema are documented
and independently testable from a clean checkout. Direct VC Compact contract
consumption is explicitly deferred to #73, not silently claimed here.
Validation: `./run.sh --light`, `./run.sh integration`, and a focused
TR-to-VC fixture compatibility test.

Depends on: #75 and #39. Labels: `trust-registry`, `backend`,
`security`, `e2e`.

## Issue #77: Authenticate mutation actors and make writes replay safe

Suggested title: `feat(api): require DID-signed applicant and maintainer mutation intents`

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

Suggested title: `test(e2e): cover governed verifier, auditor, recognition, and maintainer roles`

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

Definition of done: each UC-03/06/07/10/14 path has a positive and
rule-specific negative automated case using the real evidence path. The suite
is deterministic and runs through `./run.sh integration` with expensive
proving variants documented separately.

Depends on: #58, #67, #77. Labels: `trust-registry`,
`governance`, `e2e`, `security`.

## Deferred Beyond 0.1.0

- [#73](https://github.com/midnightntwrk/midnight-trust-registry/issues/73):
  portable Ledger 8 authorized signer descriptors and VC contract consumption.
  The 0.1.0 relying party uses the TR client and independent VC verification;
  it does not claim cross-contract calls.
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
