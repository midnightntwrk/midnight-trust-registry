# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- require exactly one epoch maintainer signature in the pre-release evidence
  bundle schema, matching the signature persisted by the format-one contract;
  multi-signature prototype bundles are not accepted
- bound the process-local application challenge store to a finite live-entry
  capacity with idle expiry and same-binding supersession; challenge consumption
  now returns canonical lowercase hashes and reports invalid clocks or capacity
  exhaustion as operational errors
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

### Added

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
