# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- moved pre-release contract fixture and client simulator exports to explicit
  `/testing` and `/simulator` subpaths instead of shipping them from production
  package roots; packaged smoke checks enforce those boundaries
- require canonical role-specific scope preimages and matching commitments at
  application-challenge issue and consume boundaries
- restricted generic maintainer audit events to a fixed action kind so raw
  authorization cannot emit a lifecycle or epoch event without its transition
- reject incompatible contract formats before simulator evidence, status, and
  raw client record reads
- bound the issuer status-registry, authority-method, and status-policy choice
  to a governed ledger commitment and epoch-authenticated issuer evidence;
  reject missing or substituted preimages without claiming live VC status
- require exactly one epoch maintainer signature in the pre-release evidence
  bundle schema, matching the signature persisted by the format-one contract;
  multi-signature prototype bundles are not accepted. Malformed encoding now
  produces an epoch-specific error on client and simulator verification
  surfaces; cardinality remains a schema error for clients and a domain error
  for direct simulator calls
- bound the process-local application challenge store to a finite live-entry
  capacity with idle expiry and same-binding supersession; challenge consumption
  now returns canonical lowercase hashes and reports invalid clocks or capacity
  exhaustion as operational errors
- bound recognition authorization and activation to the proposed evidence
  commitment, rejecting silent evidence replacement between governance steps
- selected contract format 1 for the first 0.1.0 deployment rather than
  migrating unreleased prototype formats; old policy roots, signatures, and
  event evidence require a fresh deployment and are not reinterpreted
- tightened policy-record versions to monotonic `vN` notation and required an
  explicit `effectiveUntil` for superseded records (pre-release API change)
- pinned Compact runtime exactly across contract, client, and VC probe packages;
  light validation now rejects published DID/VC runtime-version drift
- replaced the simulator's application-evidence hash stand-in with a
  domain-separated, key-bound JubJub signature; application evidence validation
  now requires the expected `applicationId` and rejects invalid or future
  evaluation times
- bound governed action signatures and governance event hashes to the active
  policy snapshot in the pre-release contract format, with separate epoch
  publication-policy commitments; earlier prototype state is not compatible
- selected the checked-in Compact compiler version for contract builds and
  validated the active compiler default during the light gate
- bound governance policy snapshot digests and versions to signed threshold
  revisions, historical epoch roots, and client evidence verification in the
  initial contract-format-1 reference profile
- upgraded published Midnight DID packages to `0.7.0` and replaced retired
  vendored VC tarballs with published VC core and DID-binding packages at `0.2.0`
- moved clean-consumer artifact smoke tests to npm-resolved identity dependencies
- removed Turbo cache restore from the fork-capable CI lane and limited cache
  publication to trusted pushes
- prevented OpenID Federation statements from re-signing unanchored issuer
  status-registry hints and added DID/VC integration scenarios to CI
- upgraded the published `midnight-did` package chain and contract Schnorr
  helper from `0.5.0-rc1` to `0.5.0-rc2`
- added protected, develop-only npm publishing with local artifact and
  published-package smoke validation
- upgraded published `midnight-did` dependencies consumed by trust-registry from
  `0.4.0` to the `0.5.0-rc2` package baseline
- aligned the repo with the pnpm `10.34.1` baseline used by the current DID
  repository
- pinned repository workflows, added Scorecard coverage, and aligned Dependabot
  grouping and cooldown policy with the public `midnight-did` repository
- added pi.dev project settings and public contribution, security, and release
  policy checks

### Removed

- removed the pre-release `authorizeMaintainerAction` circuit and simulator
  wrapper with caller-supplied action kinds; use `authorizeMaintainerAuditEvent`
  for a fixed-kind generic audit event
- removed pre-release direct-create verifier, auditor, and recognition
  circuits and simulator wrappers; all four roles use the governed
  proposal, authorization, and activation state machine
- removed pre-release unbound maintainer action signing/digest exports; callers
  must sign and verify against the active policy commitment

### Added

- defined a canonical V1 issuer status-policy binding preimage and fixed digest
  vector; ledger anchoring and supported status verification remain pending
- added a five-minute, one-use off-ledger application challenge service with
  context binding, exact evidence-envelope matching, and an in-memory
  reference store for local testing
- defined the 0.1.0 actor/use-case profile, executable milestone issue plan,
  and current VC signer-authorization anchor delivery boundary
- public-repo hardening with PR-title/body validation and a quality workflow
- root demo commands for preparing a seeded operator workspace and booting the
  API, admin console, and applicant portal from the repo root
- issue-backed backlog tracking for the next 20 trust-registry implementation
  slices
