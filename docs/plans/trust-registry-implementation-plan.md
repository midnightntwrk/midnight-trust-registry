# Trust Registry Implementation Plan

Status: draft
Base branch: `develop`

## Execution Strategy

Build the project in large but reviewable PRs. Each PR should leave the repository in a useful state and should either improve documentation, validation, contract behavior, TypeScript package behavior, or DID/VC integration.

## Phase 0: Repository Foundation

Goal: make the project concrete enough for engineers to work in it safely.

Deliverables:

- Replace template README with project-specific scope and boundaries.
- Move the trust registry spec, plan, research memo, and backlog into `docs/`.
- Add `AGENT.md` and local skill guidance for TR work.
- Add lightweight docs validation before code packages exist.
- Make CI run against `develop` pull requests.

Acceptance:

- Engineers can identify where scope belongs.
- Documentation links are locally checkable.
- The backlog is explicit and ordered.

## Phase 1: Domain Model

Goal: define typed registry data before writing Compact contracts.

Deliverables:

- `packages/trust-registry-domain` with TypeScript types and codecs.
- State-machine validators for registry, participant, authorization, recognition, policy, and epoch records.
- Canonical ID and hash helpers.
- Fixture set for valid and invalid issuer/verifier authorization paths.

Acceptance:

- Unit tests cover all lifecycle transitions.
- Invalid cross-scope trust decisions fail fast.
- Public package exports are documented.

## Phase 2: Compact Contract Prototype

Goal: create a minimal on-chain governance and authorization surface.

Deliverables:

- `contracts/trust-registry` Compact package.
- Registry initialization circuit.
- Maintainer authorization and threshold checks.
- Issuer/verifier authorization create, suspend, revoke, and archive circuits.
- Recognition create, revoke, and archive circuits.
- Epoch anchor publication circuit.

Acceptance:

- Contract tests cover positive and negative authorization paths.
- Contract state is append-only for historical evidence.
- High-churn status data remains outside TR.

## Phase 3: Client and Evidence API

Goal: expose contract state to apps and verifiers without leaking holder activity.

Deliverables:

- `packages/trust-registry-client` with query helpers.
- Evidence bundle builder.
- Historical lookup helpers by epoch and timestamp.
- Maintainer signature verification helpers.
- JSON schemas for query responses and evidence bundles.

Acceptance:

- A verifier can evaluate issuer and verifier authorization from an evidence bundle.
- The client does not require issuer callback during presentation verification.
- Wrong-registry and revoked-authorization evidence fails deterministically.

## Phase 4: DID and VC Integration

Goal: prove the registry works with the existing identity stack.

Deliverables:

- DID resolver integration test using `did:midnight` references.
- VC verifier integration test that consumes TR evidence plus credential status evidence.
- University issuer/verifier scenario extension for authorized and unauthorized issuer paths.
- Wrong-registry, suspended issuer, revoked verifier, and expired policy negative cases.

Acceptance:

- DID and VC packages remain owners of their surfaces.
- TR integration is additive and optional until consumers enable it.
- Integration reports show the DID, VC, status, and TR evidence used in each scenario.

## Phase 5: External Query and Federation Adapters

Goal: make the registry interoperable with external trust ecosystems.

Deliverables:

- TRQP-compatible read adapter for registry metadata, authorization, recognition, and historical evidence.
- OpenID Federation metadata adapter for signed metadata and trust-chain experiments.
- Adapter conformance fixtures.
- Clear warning boundaries for draft or partial standards support.

Acceptance:

- Internal evidence model maps cleanly to external query responses.
- Adapters do not become source-of-truth for registry state.
- External trust chains remain separate from local authorization.

## Phase 6: Operator Tooling

Goal: make real registry operation testable.

Deliverables:

- Admin CLI for initializing registry state and submitting changes.
- Fixture-backed demo registry.
- Governance policy templates.
- Audit report generator.
- Release/package flow once code packages stabilize.

Acceptance:

- A new engineer can run a local registry flow from README instructions.
- Maintainers can inspect state and evidence without reading raw contract state.
- CI validates the demo flow.

## Phase 7: Governed Application Workflows

Goal: stop treating trust decisions as direct-to-active writes and model governed proposal, approval, activation, and membership flows explicitly.

Deliverables:

- Issuer authorization proposal, approval, and activation workflow.
- Matching verifier, recognition, and auditor application workflows.
- Maintainer onboarding, suspension, revocation, and archival lifecycle.
- Quorum-aware maintainer execution above the current `1-of-N` shortcut.

Acceptance:

- Applications and approvals preserve historical evidence before activation.
- New maintainers cannot self-authorize into the registry.
- Policy rules can distinguish onboarding, emergency action, and archival thresholds.

## Phase 8: Mutable Operator And Service Surfaces

Goal: expose real operational flows to maintainers, applicants, and relying parties without forcing raw simulator or contract access.

Deliverables:

- CLI commands for submit, approve, activate, suspend, revoke, and epoch publication.
- REST API for applicant submission and public trust/evidence queries.
- Local admin/applicant UI scaffold on top of the client and API packages.

Acceptance:

- An applicant can submit a scoped request without editing fixtures manually.
- A maintainer can review and approve a request through stable operator surfaces.
- Query consumers can fetch current and historical trust evidence over HTTP.

## Phase 9: Historical Proof Hardening And Release

Goal: strengthen long-term verification and make the repo shippable as a reusable reference implementation.

Deliverables:

- Historical query helpers by timestamp in addition to explicit epoch id.
- Richer inclusion-proof export beyond the current single-statement merkle anchor.
- Reproducible demo registry flow and packaged artifacts.
- CI validation for the documented demo and release path.

Acceptance:

- Verifiers can answer "what was trusted at time T" deterministically.
- Demo and package instructions work from a clean checkout.
- Release artifacts match the documented package boundaries.
