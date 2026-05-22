# Trust Registry Knowledge Base

Status: working knowledge snapshot
Updated: 2026-05-23

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
  - resolves current sibling source workspaces from `packages/...` paths
  - falls back to existing compiled sibling `dist/` artifacts when a rebuild
    fails but reusable outputs already exist
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
- issuer application-state foundation with:
  - explicit `proposed`, `authorized`, and `active` issuer lifecycle states
  - issuer proposal, approval, and activation circuits
  - archive-from-proposed and revoke-from-authorized coverage
- governed verifier, recognition, and auditor workflows with:
  - explicit verifier `proposed`, `authorized`, and `active` lifecycle support
  - explicit recognition `proposed`, `authorized`, and `active` lifecycle support
  - a dedicated auditor authorization family that mirrors verifier composite scope
  - positive integration coverage for verifier and recognition application history
  - active and historical integration coverage for auditor authorization
- governed maintainer membership workflow with:
  - dedicated maintainer membership records separate from the active signer key table
  - bootstrap maintainer mirrored into append-only membership history at initialization
  - proposal, approval, activation, suspension, revocation, and archival circuits
  - duplicate live maintainer identity rejection
  - last-active-maintainer threshold protection on deactivation paths
  - local contract and simulator integration coverage
- governed quorum execution foundation with:
  - fixed-capacity maintainer authorization bundles for up to `5` approving signers
  - signer-set commitments recorded in governance event state
  - scoped maintainer thresholds for default, emergency, and archival actions
  - governed threshold-policy updates so registries can move from bootstrap `1-of-1` to real `N-of-M` operation after new maintainers activate
  - contract and local simulator coverage for `2-of-N` onboarding flows plus duplicate-signer rejection
  - internal epoch publication in the simulator now auto-selects active co-maintainers when the default threshold is above `1`, so evidence export remains valid after quorum policy changes
- typed governance-policy binding foundation with:
  - typed policy templates for maintainer, member, emergency, archival, and auditor decision families
  - typed decision bindings that resolve each decision family to a concrete policy template
  - schema validation that rejects duplicate policy families or bindings that reference missing templates
  - simulator policy fixtures that keep template thresholds aligned with the current default, emergency, and archival maintainer thresholds
  - operator audit reports that render policy templates and decision bindings instead of only free-form rule text
- fresh cache-miss validation observation for the quorum slice:
  - `./run.sh --light` now compiles `54` circuits through the contract build path
  - `typecheck:light` spent about `18m56s` on `2026-05-22` when the contract build cache missed
  - further quorum-surface growth should be treated as a CI/runtime review event, not just a feature addition
- CI workflow repair for stacked PRs and manual dispatch:
  - `pull_request` workflows no longer require `develop` as the base branch
  - `CI` path filters now cover `contracts/**`, `adapters/**`, `libs/**`, and
    all `scripts/**`
  - GitHub runners now install the Compact compiler before `./run.sh --light`
  - `Docs` whitespace checks now handle `workflow_dispatch` safely
  - `Scan` concurrency keys now stay branch-specific for manual dispatch runs
- `turbo typecheck` now builds workspace dependencies first so fresh-checkout
  CI runs do not depend on stale local artifacts
- `turbo typecheck` now depends on each package's own `build` task as well as
  `^build`, so fresh-runner typecheck does not race missing local generated
  artifacts
- contract build cache now restores:
  - `src/managed/**`
  - `dist/**`
  - `tsconfig.build.tsbuildinfo`
  so cached builds remain usable for contract typecheck and test lanes after
  clean checkout paths
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
- simulator-first issuer application coverage with:
  - proposed issuer evidence before activation
  - authorized issuer evidence before activation
  - active issuer evidence after explicit activation
  - quorum-gated issuer onboarding once maintainer thresholds are raised above `1`
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
- client verification coverage for:
  - non-active issuer proposal and approval bundles with `requireActive: false`
  - default rejection of proposed or authorized issuer bundles when active trust
    is required
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
  - mutable operator workspace initialization backed by an append-only CLI
    action journal
  - local registry, policy, authorization, recognition, and epoch inspection
  - governed issuer, verifier, and recognition submit, approve, activate,
    suspend, revoke, and archive flows without direct simulator access
  - registry epoch publication from the mutable workspace model
  - anchored evidence-bundle export for issuer, verifier, and recognition
    records
- focused operator CLI tests that verify:
  - demo snapshot creation and typed reload from disk
  - summary, list, and inspect flows over the saved snapshot
  - mutable issuer workflow from submission through activation
  - mutable verifier and recognition workflows from submission through later
    lifecycle transitions
  - evidence export for operator-facing JSON handoff
- snapshot-backed audit reporting for:
  - full registry audit output
  - focused issuer, verifier, recognition, and epoch history output
  - deterministic file or stdout rendering from saved snapshots
- read-only HTTP query workspace:
  - `packages/trust-registry-api`
- native API routes for:
  - registry metadata and summary
  - current and historical epoch export
  - issuer and verifier listing, by-id lookup, scoped resolution, and evidence export
  - recognition listing, by-id lookup, scoped resolution, and evidence export
- TRQP-over-HTTP routes for:
  - registry metadata
  - authorization query and evidence
  - recognition query and evidence
- file-backed API source modes for:
  - saved snapshots
  - mutable operator workspaces reloaded on each request
- focused API tests that verify:
  - native query and evidence routes from a workspace file
  - TRQP routes from a snapshot file
  - workspace reload between requests
  - structured problem-details errors for invalid or missing input
- governed application API routes for:
  - applicant submission of issuer, verifier, and recognition requests
  - maintainer approval, activation, suspension, revocation, and archival actions
  - registry epoch publication from the workspace-backed API surface
- mutation-source rule for the API:
  - writes require a mutable operator workspace source
  - snapshot and in-memory API modes stay read-only and reject mutation routes
- mutation hardening for the API:
  - path-parameter validation now returns structured 400 problem-details errors
  - duplicate submissions now return structured 409 problem-details errors
  - unknown governed ids now return structured 404 problem-details errors
  - writes are serialized per process and per workspace source
- focused mutation API tests that verify:
  - submit -> approve -> activate issuer flow through HTTP
  - verifier lifecycle transitions through archive over HTTP
  - governed recognition approval through HTTP
  - epoch publication with and without a request body
  - invalid target and unknown-id problem responses
  - mutation rejection for snapshot-backed API servers
- first admin console package:
  - `packages/trust-registry-admin-console`
  - static local UI over the existing API
  - review boards grouped by lifecycle state for issuer, verifier, and recognition records
  - maintainer actions for approve, activate, suspend, revoke, archive, and epoch publication
- API/browser interoperability support for the admin console:
  - permissive local CORS headers on the API
  - preflight handling for `OPTIONS` requests
  - preview-server smoke coverage against a seeded operator workspace
- focused operator CLI report tests that verify:
  - full human-readable report generation
  - focused report export with stable timeline output

## Current Branch And PR State

Active implementation branch:

- `codex/trust-registry-api-application-surface`
- stacked on:
  - `codex/trust-registry-api-query-surface`
- current slice:
  - `TR-027`
  - governed application API surface

Current stacked base branch:

- `develop`
- open stack currently spans:
  - `#12` through `#17`
  - `TR-023` through `TR-027`

Merged baseline now on `origin/develop`:

- domain foundation
- compact skeleton
- merged through `TR-022`

Branch handling note:

- the docs/workflow baseline plus all slices through `TR-022` are on `develop`
- the current stack adds maintainer membership, quorum execution, governance
  policy bindings, mutable operator workflows, and API surfaces on top of that

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

- maintainer-facing web UX above the existing client and CLI/API packages

Still intentionally deferred inside the current Compact slice:

- stateful multi-maintainer threshold execution above `1-of-N`
- historical epoch selection by timestamp
- Merkle-style inclusion proofs beyond the current signed-statement anchor

## Next Recommended Slices

1. second `TR-027` slice
   - add applicant submission and governed approval API routes
2. `TR-028` to `TR-030`
   - execute the remaining stack from UI through historical proof hardening
     and release/demo flow

## Knowledge Synchronization Rule

When a meaningful TR slice lands or materially changes direction, update:

1. this repo-local knowledge base
2. the workspace-root knowledge base under
   `midnight-identity-workspace/research/`
3. the global `trusted-registry` Obsidian vault

Do not put private notes, local machine-only state, or unpublished secrets into
this file.
