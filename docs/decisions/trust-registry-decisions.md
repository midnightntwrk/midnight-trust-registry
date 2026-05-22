# Trust Registry Decisions

Date: 2026-05-23

## Current Decisions

- Use Midnight DID by default for party and registry identifiers.
- Use Midnight VC and VP packages as the default application evidence surface.
- Keep Schnorr signatures over JubJub-compatible registry control keys as the default contract-facing authorization primitive for v1.
- Admit non-Midnight DID methods only through explicit governance policy.
- Treat secp256k1, secp256r1, and Ed25519 as planned extension paths, not mandatory v1 contract features.
- Treat authorization and recognition as separate statement types.
- Preserve historical state instead of overwriting it.
- Keep this repository as the owner of trust-registry governance and implementation.
- Target long-term package placement under contract, package, adapter, and example directories once source work begins.
- Treat `midnight-did` as a downstream consumer and integration point, not the owner of the registry contract.
- Reuse the VC status registry for status and revocation instead of cloning those concerns.
- For the first issuer-authorization slice, maintainer-approved create lands directly in `active` state; the separate application/proposal workflow remains a later slice.
- Keep the issuer authorization lookup split between a primary `authorizationId` record and a current-scope index keyed by `(subject DID commitment, resource type, resource id)`.
- For the first verifier-authorization slice, keep the authorization lookup split between a primary `authorizationId` record and a current-scope index keyed by `(subject DID commitment, request profile id, allowed attribute set commitment, allowed predicate set commitment, disclosure level commitment)`.
- For the first recognition slice, maintainer-approved create lands directly in `active` state, but recognition remains a separate record family from local authorization.
- Keep the recognition lookup split between a primary `recognitionId` record and a current-scope index keyed by `(recognized authority DID commitment, recognized registry id, scope resource type, scope resource id)`.
- Store recognition scope resource type as an opaque `Bytes<32>` label in the contract so external trust domains are not forced into the issuer/verifier resource enums.
- For the first epoch-anchor slice, publish epochs as append-only records keyed by `epochId`, plus a latest-epoch pointer for the current verifier view.
- Store the maintainer key id and raw JubJub signature components in the epoch record so evidence bundles can export a real registry signature instead of a synthetic placeholder.
- Keep epoch selection by explicit `epochId` or latest pointer in the contract; richer historical selection by timestamp remains a later client concern.
- Start integration coverage with a simulator-first workspace package and a dedicated `./run.sh integration` lane; keep it separate from `./run.sh --light` until DID- and VC-backed scenarios justify the extra CI cost.
- For the first client slice, add a dedicated `packages/trust-registry-client` workspace instead of embedding client helpers into the integration harness.
- Keep the first client slice evidence-first: verify published epoch roots, maintainer signatures, and bundle scope expectations directly from canonical contract records before adding higher-level transport adapters.
- Keep the first client implementation simulator-backed so current and historical query semantics stabilize before DID- and VC-runtime dependencies are added.
- For the first DID-backed integration slice, sync the official `@midnight-ntwrk/midnight-did`, `@midnight-ntwrk/midnight-did-domain`, and `@midnight-ntwrk/midnight-did-contract` packages into `libs/` instead of depending on sibling-repo paths at runtime.
- Use official `midnight-did` helpers to construct fixture `did:midnight` identifiers and `MidnightDIDResolver` to resolve bundle subject DIDs from fixture ledger state; do not duplicate DID parsing or resolution logic inside TR tests.
- For the first VC-backed integration slice, sync the official `@midnight-ntwrk/midnight-did-credentials` and `@midnight-ntwrk/midnight-did-credentials-status-registry` packages into `libs/` instead of modeling VC status evidence locally inside TR.
- Keep VC-backed integration evidence-first: verify TR authorization bundles through `@midnight-ntwrk/trust-registry-client`, then verify VC status through the official status-registry helpers using the status-registry reference exported by the issuer bundle.
- Keep the Turbo workspace graph acyclic: `@midnight-ntwrk/trust-registry-client` test coverage may consume integration fixtures by source import, but the client package manifest must not depend on `@midnight-ntwrk/trust-registry-integration`.
- Implement the first TRQP slice as a dedicated read-only adapter workspace under `adapters/trqp`, backed by an abstract source interface instead of direct contract or simulator coupling.
- Use `registryDid` as the canonical TRQP `authority_id`; keep the local `registryId` as a Midnight profile field in metadata responses.
- Keep the standard TRQP v2 surface limited to authorization and recognition queries. Registry metadata and evidence-bundle export are explicit Midnight profile extensions because TRQP v2 defers metadata/description query types.
- For the first TRQP recognition mapping, interpret the local recognition `scope.resourceType` as the TRQP `action` field and use `context.recognized_registry_id` as the disambiguating extension for external registry matches.
- Implement the first OpenID Federation slice as an offline, fixture-only adapter workspace under `adapters/openid-federation`; do not claim live fetch, resolve, or `.well-known` publication support yet.
- Use the registry `serviceEndpoint` URL as the federation entity identifier and keep `registryDid` and `registryId` inside custom trust-registry metadata, because the federation experiment authenticates the registry publisher rather than replacing DID-native identifiers.
- Keep OpenID Federation as a publisher-authentication layer only: the signed federation chain proves who published the registry metadata, while embedded TR evidence bundles remain the source-of-truth for authorization and recognition semantics.
- Implement the first operator slice as a dedicated `packages/trust-registry-cli` workspace instead of embedding ad hoc scripts into `scripts/` or the client package.
- Keep the first operator CLI simulator-first and file-backed: initialize a deterministic local snapshot, inspect typed records from that snapshot, and export anchored evidence bundles without requiring direct simulator spelunking.
- Keep the first operator CLI read-heavy: local initialization, inspection, and evidence export land before mutable maintainer workflows or audit/report generation.
- Implement the first audit-report slice on top of the existing CLI snapshot surface instead of creating a separate reporting workspace.
- Keep the first audit-report slice deterministic and read-only: render human-readable registry, policy, authorization, recognition, and epoch history from saved snapshots without introducing mutable operator flows.
- For `TR-026`, implement mutable CLI state as an append-only operator workspace journal plus a derived snapshot. Do not persist or mutate raw simulator state directly on disk.
- For `TR-026`, scope the first mutable CLI workflows to issuer, verifier, and recognition actions plus registry epoch publication. Defer mutable auditor, maintainer, and threshold-governance commands to later slices.
- Accept replay-first workspace performance for `TR-026`: every mutable CLI command may rebuild the simulator and derived snapshot from the full journal. Favor auditability and deterministic reconstruction now; optimize compaction or incremental replay only if real operator usage makes the local workflow too slow.
- Implement the first REST query slice as a dedicated `packages/trust-registry-api` workspace instead of extending the CLI package into an ad hoc HTTP entrypoint.
- Keep the first REST query slice read-only and file-backed: serve native registry/epoch/authorization/recognition/evidence routes plus TRQP-compatible routes from saved snapshots or mutable operator workspaces; defer applicant submission and maintainer approval endpoints to the second `TR-027` slice.
- Implement the first on-chain application-state slice for issuer authorization before widening mutable operator surfaces: add explicit `proposed`, `authorized`, and `active` issuer states, and keep verifier, recognition, auditor, and maintainer application flows as follow-on slices.
- Keep the existing direct maintainer `createIssuerAuthorization` path as a compatibility shortcut for bootstrap or migration flows while the governed application workflows are being rolled out; new integration coverage should prefer the proposal, approval, and activation path.
- Treat the issuer application-state enum expansion as a wire-format break for persisted ordinal interpretations of `AuthorizationStatus`; pre-existing deployed state would need migration or redeployment before adopting this slice.
- Apply the same governed application-state pattern to verifier and recognition records before adding mutable operator/API submission surfaces: `proposed` claims scope, `authorized` records approval, and `active` is the only state accepted by authorization assertions.
- Model auditor onboarding as a dedicated authorization family that mirrors the verifier composite scope shape instead of overloading verifier records or recognition. This keeps auditor evidence role-specific while reusing the same request-profile, attribute, predicate, and disclosure commitments.
- Sequence the next stack after operator reporting around the missing governance seams: issuer application workflow, then verifier/recognition/auditor application flows, then maintainer membership and multi-maintainer quorum execution before operator/API mutation surfaces.
- Implement the first maintainer-governance slice as a dedicated `MaintainerMembershipRecord` family, separate from the active signer key table. This keeps append-only maintainer onboarding history explicit while preserving a narrow active-key surface for contract authorization checks.
- Keep bootstrap maintainer initialization as a special-case active membership created by `initializeRegistry`, but require every non-bootstrap maintainer to pass through `proposed -> authorized -> active`.
- Refuse duplicate live maintainer identity enrollment and refuse maintainer deactivation when it would drop the registry below the configured maintainer threshold.
- Implement quorum execution with a fixed-capacity signer bundle instead of a dynamic signer list. The v1 contract supports up to `5` approving maintainers per governed action so the core registry can cover `3-of-5` and `5-of-7` governance patterns without introducing dynamic Compact arrays into the authorization surface.
- Keep maintainer quorum policy explicit and stateful: bootstrap starts at `1-of-1`, then the registry lifts thresholds through a governed `tr:policy:thresholds:update` action after additional maintainers are activated.
- Scope maintainer quorum rules by action family before the richer policy-template slice lands: use the default threshold for onboarding and ordinary governance actions, a dedicated emergency threshold for suspend/revoke actions, and a dedicated archival threshold for archive actions.
- Keep `lastAuthorizedMaintainerKeyId` and epoch publication signatures submitter-oriented in v1: they record `signer1`, while the full approving quorum is bound into the governance-event chain via `signerSetHash`.
- Keep simulator-generated epoch publication quorum-aware once thresholds rise above `1`: internal evidence publication may auto-select active co-maintainers to satisfy the live default threshold, but operator-facing harness calls must still pass explicit co-authorizers when the action itself is governed.
- Treat quorum execution as the current Compact cost boundary: as of `2026-05-22`, a fresh cache-miss `./run.sh --light` path compiles `54` circuits and spent about `19` minutes inside the contract build during `typecheck:light`, so any further signer-bundle expansion or duplicate build wiring needs explicit review.
- Implement the first governance-policy template slice in the domain, evidence, simulator, and operator-report surfaces before widening the Compact contract. The v1 contract continues to anchor one policy commitment plus threshold state, while typed policy templates and decision-family bindings explain how maintainer, member, emergency, archival, and auditor decisions should be interpreted off-chain.
- Keep `upgrade-libs` source-layout-aware: resolve sibling DID and VC workspaces from their current `packages/...` paths instead of assuming flat workspace names.
- Let `upgrade-libs` fall back to existing compiled artifacts when a sibling package rebuild fails but usable `dist/` output already exists; refresh should still fail when no compiled artifacts are available to sync.
- Make `turbo typecheck` depend on the package's own `build` task as well as `^build` so fresh-runner typecheck cannot race missing generated artifacts.
- Treat `src/managed/**` as a real build output for the contract package so Turbo cache replay restores generated Compact surfaces needed by typecheck and tests.
- For adapter package tests, prefer the built integration workspace package over direct source imports when the tests rely on generated contract surfaces; this preserves fresh-checkout task ordering without introducing a contract rebuild inside the adapter lanes.

## Pending Decisions

- Resource granularity for issuer authorization: credential family, schema version, credential definition, or a combination.
- Whether verifier authorization should later grow beyond the current v1 scope of request profile plus disclosure and predicate commitments.
- Whether signer-set commitments should become canonicalized independent of submitter order, or remain order-sensitive because the first disclosed signer acts as the submitter of record in epoch evidence.
- Whether `tr:policy:thresholds:update` should keep using the default maintainer threshold or move to a dedicated governance-policy quorum in the `TR-025` slice.
- Whether typed governance-policy bindings should stay domain-first or later receive explicit per-family commitments in Compact state.
- Minimum archival retention window for long-term credential verification.
- First operator-facing app surface: admin CLI, admin console, applicant portal, or public query API.
- First external adapter: TRQP, OpenID Federation, or both.
