# Trust Registry Knowledge Base

Status: working knowledge snapshot
Updated: 2026-05-22

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
  - current required packages:
    - `@midnight-ntwrk/midnight-did`
    - `@midnight-ntwrk/midnight-did-contract`
    - `@midnight-ntwrk/midnight-did-domain`
    - `@midnight-ntwrk/midnight-did-jubjub-schnorr`
    - `@midnight-ntwrk/midnight-did-credentials`
    - `@midnight-ntwrk/midnight-did-credentials-status-registry`
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
- epoch commitment records keyed by `epochId`
- latest-epoch pointer in the Compact contract
- epoch publication payload-hash helper for maintainer signatures
- epoch publication circuit plus current/by-id epoch query circuits
- focused positive and negative epoch contract tests
- simulator-first integration workspace:
  - `packages/trust-registry-integration`
- dedicated integration entrypoint:
  - `./run.sh integration`
- local end-to-end scenarios that combine:
  - contract simulator state transitions
  - domain authorization records
  - domain recognition records
  - published epoch commitments
  - evidence bundle generation
  - anchored epoch validation against stored roots and signatures
  - wrong-registry and inactive-authorization rejections
- first client workspace:
  - `packages/trust-registry-client`
- simulator-backed query helpers for:
  - issuer authorization by id and current scope
  - verifier authorization by id and current scope
  - recognition by id and current scope
  - epoch commitments by id and latest pointer
- evidence verification helpers for:
  - issuer authorization bundles
  - verifier authorization bundles
  - recognition bundles
- client-side validation of:
  - published epoch roots
  - maintainer signatures over epoch publication payloads
  - statement scope expectations
  - stale and not-yet-valid epoch windows
  - wrong-registry and tampered-evidence failures
- focused client tests that exercise current and historical queries plus
  anchored bundle verification against the local simulator
- acyclic workspace graph for CI:
  - `@midnight-ntwrk/trust-registry-client` does not declare a manifest
    dependency on `@midnight-ntwrk/trust-registry-integration`
  - client tests consume shared integration fixtures by direct source import so
    `turbo` root lanes do not reintroduce a client/integration build cycle
- DID-backed integration helpers that:
  - construct `did:midnight` identifiers with official `midnight-did` helpers
  - resolve trusted issuer and verifier subject DIDs through
    `MidnightDIDResolver`
  - use fixture ledger state instead of copied DID parsing or resolver logic
- DID-backed integration tests that verify:
  - active issuer and verifier bundle subjects resolve to DID documents
  - missing DID fixture state resolves to `null`
- VC-backed integration tests that verify:
  - active issuer and verifier TR bundles are accepted before VC status
    verification proceeds
  - issuer bundle status-registry references are consumed by the official VC
    status-registry helpers
  - mismatched status registries fail with deterministic `unknownRegistry`
    errors
  - revoked credentials fail with deterministic `revoked` errors
- first adapter workspace:
  - `adapters/trqp`
- TRQP adapter package with:
  - strict TRQP authorization request/response schemas
  - strict TRQP recognition request/response schemas
  - RFC 7807-style problem-details mapping
  - explicit Midnight profile extensions for registry metadata and
    evidence-bundle export
- TRQP adapter design constraints:
  - `registryDid` is the canonical `authority_id`
  - the adapter is read-only and source-driven, not simulator-bound
  - metadata and evidence remain extensions because TRQP v2 standardizes
    authorization and recognition, not description/metadata queries
- focused TRQP adapter tests that verify:
  - active issuer and verifier authorization responses
  - revoked authorization mapping to `authorized: false` while preserving
    evidence access
  - active recognition mapping plus registry metadata export
  - problem-details responses for unknown authorities and unmatched tuples
- second adapter workspace:
  - `adapters/openid-federation`
- OpenID Federation adapter package with:
  - signed registry entity configuration payloads
  - signed subordinate statements from a fixture trust anchor to the registry
  - simple trust-chain verification over static JWT arrays
  - embedded canonical TR evidence bundles inside custom registry publication
    metadata
- OpenID Federation adapter boundaries:
  - federation authenticates the registry publisher, not each authorized DID
  - `serviceEndpoint` is the federation entity identifier in the current
    experiment
  - `registryDid` and `registryId` remain custom trust-registry metadata
  - live fetch, resolve, list, and `.well-known` publication stay out of scope
- focused OpenID Federation adapter tests that verify:
  - signed registry entity configuration projection
  - trust-anchor-to-registry chains with embedded authorization bundles
  - trust-anchor-to-registry chains with embedded recognition bundles
  - malformed authority-hint linkage rejection
- adapter-package typecheck now consumes the built integration workspace
  package in tests instead of direct source imports so fresh-runner CI cannot
  race generated contract surfaces
- operator CLI workspace:
  - `packages/trust-registry-cli`
- operator CLI surface for:
  - deterministic demo snapshot initialization from the local simulator harness
  - local registry, policy, authorization, recognition, and epoch inspection
  - anchored evidence-bundle export for issuer, verifier, and recognition
    records
- focused operator CLI tests that verify:
  - demo snapshot creation and typed reload from disk
  - summary, list, and inspect flows over the saved snapshot
  - evidence export for operator-facing JSON handoff

## Current Branch And PR State

Active implementation branch:

- `codex/trust-registry-operator-cli`

Stacked base branch:

- `codex/trust-registry-verifier-authorization`
- pending PR for the operator CLI slice
- `codex/trust-registry-issuer-authorization`
- `#6`
- title:
  - `feat: add issuer authorization circuits`

Merged baseline now on `origin/develop`:

- domain foundation
- compact skeleton

Branch handling note:

- the docs/workflow baseline plus domain foundation and compact skeleton are on
  `develop`
- the current branch stacks the operator CLI on top of the verifier,
  recognition, epoch, client, DID/VC integration, TRQP, and OpenID
  Federation slices while the lower draft PRs are still open

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
  - simulator-first, DID-backed, and VC-backed trust-registry scenarios

It does not yet cover:

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

- audit-oriented operator reporting beyond the current CLI snapshot,
  inspection, and evidence-export baseline

Still intentionally deferred inside the current Compact slice:

- stateful multi-maintainer threshold execution above `1-of-N`
- maintainer onboarding and removal flows
- issuer, verifier, and recognition application state machines
- separate `proposed` and `authorized` on-chain authorization phases
- historical epoch selection by timestamp
- Merkle-style inclusion proofs beyond the current signed-statement anchor

## Next Recommended Slices

1. `TR-010`
   - finish the issuer authorization branch and merge it to `develop`
2. `TR-011` to `TR-014`
   - retarget and finish the stacked verifier, simulator-integration,
     recognition, epoch, and client branch after `TR-010`
3. `TR-019`
   - add the first operator CLI on top of the stabilized read adapters and
     client surface
4. `TR-020`
   - add the audit report generator after the operator CLI establishes the
     inspection path

## Knowledge Synchronization Rule

When a meaningful TR slice lands or materially changes direction, update:

1. this repo-local knowledge base
2. the workspace-root knowledge base under
   `midnight-identity-workspace/research/`
3. the global `trusted-registry` Obsidian vault

Do not put private notes, local machine-only state, or unpublished secrets into
this file.
