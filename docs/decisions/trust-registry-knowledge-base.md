# Trust Registry Knowledge Base

Status: working knowledge snapshot
Updated: 2026-05-21

## Purpose

This document is the repo-local knowledge base for
`midnight-trust-registry`.

It records the current implementation state, branch and PR shape, validation
entrypoints, and the next expected slices. It is intentionally shorter-lived and
more execution-oriented than the normative spec or long-form research memo.

## Current Implementation State

Completed in the current implementation wave:

- repo-local `npm` workspace scaffold
- repo runner entrypoint:
  - `./run.sh`
- light validation entrypoint:
  - `./run.sh --light`
- `turbo` root task wiring for lint, typecheck, build, and test
- first code package:
  - `packages/trust-registry-domain`
- initial typed schemas for:
  - registry records
  - governance policy records
  - participant records
  - authorization records
  - recognition records
  - epoch commitments
  - evidence bundles
- lifecycle transition helpers and chronology guards
- first unit tests for domain and evidence paths
- first Compact package:
  - `contracts/trust-registry`
- DID-backed JubJub Schnorr dependency from:
  - `midnight-did`
  - synced into `libs/midnight-did/jubjub-schnorr/`
- local identity dependency refresh helper:
  - `./upgrade-libs.sh --destination .`
- manifest-driven identity dependency sync:
  - reads TR workspace package manifests
  - syncs only mapped local packages required from `midnight-did` or
    `midnight-verifiable-credentials`
  - current required package:
    - `@midnight-ntwrk/midnight-did-jubjub-schnorr`
  - VC package mappings are prepared but not yet required by the current TR
    code surface
- registry initialization circuit with:
  - registry id commitment
  - registry DID commitment
  - governance policy commitment
  - bootstrap maintainer registration
- generic maintainer-signed action authorization circuit
- generic threshold validation plus explicit single-signer guard for v1
- append-only governance event hashing and event-count progression
- first Compact contract tests and package-surface tests
- issuer authorization record and current-scope index in the Compact contract
- issuer authorization create, suspend, revoke, archive, and query circuits
- issuer authorization payload-hash helpers for maintainer signatures
- focused positive and negative issuer authorization contract tests
- CI workflow repair for stacked PRs and manual dispatch:
  - `pull_request` workflows no longer require `develop` as the base branch
  - `CI` path filters now cover `contracts/**`, `adapters/**`, `libs/**`, and
    all `scripts/**`
  - GitHub runners now install the Compact compiler before `./run.sh --light`
  - `Docs` whitespace checks now handle `workflow_dispatch` safely
  - `Scan` concurrency keys now stay branch-specific for manual dispatch runs
- `turbo typecheck` now builds workspace dependencies first so fresh-checkout
  CI runs do not depend on stale local artifacts
- verifier authorization record and current-scope index in the Compact contract
- verifier authorization create, suspend, revoke, archive, and query circuits
- verifier authorization payload-hash helpers for maintainer signatures
- focused positive and negative verifier authorization contract tests
- recognition record and current-scope index in the Compact contract
- recognition create, suspend, revoke, archive, and query circuits
- recognition payload-hash helpers for maintainer signatures
- focused positive and negative recognition contract tests
- simulator-first integration workspace:
  - `packages/trust-registry-integration`
- dedicated integration entrypoint:
  - `./run.sh integration`
- local end-to-end scenarios that combine:
  - contract simulator state transitions
  - domain authorization records
  - domain recognition records
  - evidence bundle generation
  - wrong-registry and inactive-authorization rejections

## Current Branch And PR State

Active implementation branch:

- `codex/trust-registry-verifier-authorization`

Stacked base branch:

- `codex/trust-registry-issuer-authorization`
- `#6`
- title:
  - `feat: add issuer authorization circuits`

Merged baseline now on `origin/develop`:

- domain foundation
- compact skeleton

Branch handling note:

- the earlier stacked branches were merged and collapsed into `develop`
- the current branch now carries verifier authorization, the simulator-first
  integration harness, and recognition on top of the issuer branch while that
  draft PR is still open

## Validation Baseline

Current required local gate for code-bearing TR changes:

```bash
npm install
./upgrade-libs.sh --destination .
./run.sh --light
./run.sh integration
git diff --check
```

What `./run.sh --light` currently covers:

- docs check
- lint
- typecheck
- build
- test

What still runs separately:

- `./run.sh integration`
  - simulator-first end-to-end trust-registry scenarios

It does not yet cover:

- DID integration
- VC integration
- external adapters
- stale upstream package drift outside the synced `libs/` copy

## Current Architectural Position

- `midnight-trust-registry` owns trust governance, authorization, recognition,
  historical evidence, and query evidence surfaces
- `midnight-did` remains the owner of DID lifecycle and resolver behavior
- `midnight-verifiable-credentials` remains the owner of VC/VP, holder-binding,
  and status/revocation semantics
- trust authorization and authority recognition remain separate record types
- status and revocation are intentionally not duplicated in this repo

## Known Short-Term Gaps

Still missing for the first usable prototype:

- epoch anchor contract surface
- TypeScript client package
- DID- and VC-backed integration tests beyond the local simulator lane

Still intentionally deferred inside the current Compact slice:

- stateful multi-maintainer threshold execution above `1-of-N`
- maintainer onboarding and removal flows
- issuer, verifier, and recognition application state machines
- separate `proposed` and `authorized` on-chain authorization phases
- epoch-root publication and historical inclusion proofs

## Next Recommended Slices

1. `TR-010`
   - finish the issuer authorization branch and merge it to `develop`
2. `TR-011`
   - retarget and finish the stacked verifier, simulator-integration, and
     recognition branch after `TR-010`
3. `TR-013` and `TR-014`
   - epoch-anchor and client surfaces
4. `TR-015` and `TR-016`
   - DID- and VC-backed scenarios on top of the new local integration harness

## Knowledge Synchronization Rule

When a meaningful TR slice lands or materially changes direction, update:

1. this repo-local knowledge base
2. the workspace-root knowledge base under
   `midnight-identity-workspace/research/`
3. the global `trusted-registry` Obsidian vault

Do not put private notes, local machine-only state, or unpublished secrets into
this file.
