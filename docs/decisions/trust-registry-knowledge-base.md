# Trust Registry Knowledge Base

Status: working knowledge snapshot
Updated: 2026-05-20

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

## Current Branch And PR State

Active implementation branch:

- `codex/trust-registry-compact-skeleton`

Baseline branch for the current stacked slice:

- `codex/trust-registry-domain-foundation`
- draft PR:
  - `#4`
  - title:
    - `feat: add trust registry domain foundation`

Current stacked draft PR:

- `#5`
- title:
  - `feat: add trust registry compact skeleton`

Branch handling note:

- the current Compact slice is intentionally stacked on the validated domain
  foundation branch
- once the lower branch merges, this branch should be rebased onto live
  `origin/develop`

## Validation Baseline

Current required local gate for code-bearing TR changes:

```bash
npm install
./upgrade-libs.sh --destination .
./run.sh --light
git diff --check
```

What `./run.sh --light` currently covers:

- docs check
- lint
- typecheck
- build
- test

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

- issuer authorization circuits
- verifier authorization circuits
- recognition circuits
- epoch anchor contract surface
- TypeScript client package
- DID and VC integration tests

Still intentionally deferred inside the current Compact slice:

- stateful multi-maintainer threshold execution above `1-of-N`
- maintainer onboarding and removal flows
- issuer, verifier, and recognition state machines
- epoch-root publication and historical inclusion proofs

## Next Recommended Slices

1. `TR-009`
   - review and merge the Compact skeleton stack
2. `TR-010`
   - issuer authorization circuits
3. `TR-011`
   - verifier authorization circuits
4. `TR-012` and `TR-013`
   - recognition and epoch-anchor surfaces

## Knowledge Synchronization Rule

When a meaningful TR slice lands or materially changes direction, update:

1. this repo-local knowledge base
2. the workspace-root knowledge base under
   `midnight-identity-workspace/research/`
3. the global `trusted-registry` Obsidian vault

Do not put private notes, local machine-only state, or unpublished secrets into
this file.
