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

## Current Branch And PR State

Active implementation branch:

- `codex/trust-registry-domain-foundation`

Current draft PR:

- `#4`
- title:
  - `feat: add trust registry domain foundation`

Branch handling note:

- the original workflow branch was already effectively integrated into
  `origin/develop`
- the current implementation branch was rebased onto live `origin/develop`
  before opening the PR

## Validation Baseline

Current required local gate for code-bearing TR changes:

```bash
npm ci
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

- Compact compilation
- DID integration
- VC integration
- external adapters

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

- Compact contract skeleton
- maintainer quorum and threshold enforcement
- issuer authorization circuits
- verifier authorization circuits
- recognition circuits
- epoch anchor contract surface
- TypeScript client package
- DID and VC integration tests

## Next Recommended Slices

1. `TR-009`
   - first Compact contract skeleton
2. `TR-010`
   - issuer authorization circuits
3. `TR-012` and `TR-013`
   - recognition and epoch-anchor surfaces

## Knowledge Synchronization Rule

When a meaningful TR slice lands or materially changes direction, update:

1. this repo-local knowledge base
2. the workspace-root knowledge base under
   `midnight-identity-workspace/research/`
3. the global `trusted-registry` Obsidian vault

Do not put private notes, local machine-only state, or unpublished secrets into
this file.

