# Trust Registry Knowledge Base

Status: working knowledge snapshot
Updated: 2026-10-05

## Purpose

This document is the repo-local execution snapshot for
`midnight-trust-registry`.

It records the current code surface, validation baseline, dependency posture,
backlog posture, and the next implementation direction. It is intentionally
shorter-lived and more action-oriented than the normative specification.

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
- `referencedStatusRegistryId` in the evidence bundle is metadata outside the
  signed authorization leaf; never treat it as authenticated status policy
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

- Compact compile remains the dominant cost center for both light and
  integration lanes
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
`docs/plans/milestone-0.1.0-delivery-harness.md`: exact-head review receipts,
issue-backed PRs, light, Quality, and scan gates, bounded review rounds, and
guarded merging. PR #82 exposed receipt parsing and PR-controlled-policy
problems (#88 and #85) and must remain unmerged. The replacement bootstrap
uses read-only policy execution from the protected milestone base after its
first externally reviewed merge. `.github/CODEOWNERS` plus required code-owner
review protects the workflow and validator against later PR self-modification.
The bootstrap itself is not yet protected by those controls; a hostile canary
must be blocked before autonomous milestone merges start. Only the milestone
branch permits zero-general-human-review product merges. Gate changes still
require code-owner review; `develop` and `main` remain human-controlled.
