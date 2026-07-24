# Trust Registry Knowledge Base

Status: working knowledge snapshot
Updated: 2026-07-23

## Purpose

This document is the repo-local execution snapshot for
`midnight-trust-registry`.

It records the current code surface, validation baseline, dependency posture,
backlog posture, and the next implementation direction. It is intentionally
shorter-lived and more action-oriented than the normative specification.

## Current Branch State

- upstream baseline branch:
  - `develop`
- current local implementation branch:
  - `codex/trust-registry-public-readiness`
- branch purpose:
  - uplift published identity dependencies
  - harden the repository for public consumption
  - expose root demo and operator entrypoints
  - switch the backlog from stack-only tracking to issue-backed tracking

## Current Implementation Baseline

Merged on `develop` before the current local slice:

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

## Identity Dependency Posture

Trust Registry consumes official Midnight identity packages from local vendored
tarballs under `libs/`.

Current DID package baseline:

- `@midnight-ntwrk/midnight-did@0.5.0-rc1`
- `@midnight-ntwrk/midnight-did-contract@0.5.0-rc1`
- `@midnight-ntwrk/midnight-did-domain@0.5.0-rc1`
- `@midnight-ntwrk/midnight-did-jubjub-schnorr@0.5.0-rc1`

Current VC dependency posture:

- keep consuming official vendored VC packages from repo-local `libs/`
- Trust Registry remains the owner of governance and authorization logic
- `midnight-did` remains the owner of DID lifecycle and resolver behavior
- `midnight-verifiable-credentials` remains the owner of VC/VP and status
  semantics

Dependency decision:

- do not import source files from sibling repositories at runtime
- do not keep copied Schnorr helper code inside the TR contract package
- consume published or vendored package artifacts through local manifests

## Public-Readiness Hardening

The current local slice adds the following repository hardening:

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

Validation status for the current local slice on 2026-07-23:

- `pnpm install --frozen-lockfile=false`
  - passed while updating the lockfile for DID `0.5.0-rc1`
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

The first 20 issue-backed work items now exist in the repository:

- `#29` through `#49`

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

## Next Recommended Execution Order

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
