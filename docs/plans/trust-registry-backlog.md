# Trust Registry Execution Backlog

Status: active
Updated: 2026-05-22

## Priority Model

- P0: needed before meaningful implementation can start.
- P1: needed for the first usable prototype.
- P2: needed for interoperability, operations, or polish.

## Current Backlog

| ID | Priority | Status | Item | Acceptance |
| --- | --- | --- | --- | --- |
| TR-001 | P0 | Done in docs foundation | Move trust registry spec, plan, research memo, and decisions into this repository. | `docs/spec`, `docs/plans`, `docs/research`, and `docs/decisions` contain public TR source material. |
| TR-002 | P0 | Done in docs foundation | Replace template README with project-specific scope. | README explains scope, non-scope, repo boundaries, and documentation map. |
| TR-003 | P0 | Stacked workflow PR | Add repository-local agent guidance. | `AGENT.md`, `.codex`, and `.claude` point engineers to the same TR rules. |
| TR-004 | P0 | Stacked workflow PR | Add lightweight docs validation. | `./scripts/check-docs.sh` checks markdown links and required docs without requiring a package manager. |
| TR-005 | P0 | Stacked workflow PR | Make CI target `develop`. | Docs and scan workflows run for pull requests into `develop`. |
| TR-006 | P1 | Done on develop | Create TypeScript domain package. | Registry, participant, policy, authorization, recognition, and epoch types compile and are unit-tested. |
| TR-007 | P1 | Done on develop | Add lifecycle validators. | Invalid transitions for authorization, recognition, and policy records fail tests. |
| TR-008 | P1 | Done on develop | Add canonical evidence bundle model. | Evidence bundle JSON schema covers issuer, verifier, recognition, policy, epoch, and inclusion proof fields. |
| TR-009 | P1 | Done on develop | Build first Compact contract skeleton. | Registry initialization and maintainer authorization compile. |
| TR-010 | P1 | Done on develop | Add issuer authorization circuits. | Create, suspend, revoke, archive, and query paths have positive and negative tests. |
| TR-011 | P1 | Done on develop | Add verifier authorization circuits. | Request-profile authorization supports disclosure and predicate scopes. |
| TR-012 | P1 | Done on develop | Add recognition circuits. | Recognized external authority state is separate from local authorization state. |
| TR-013 | P1 | Done on develop | Add epoch anchor. | Maintainer-signed state roots can be published and verified. |
| TR-014 | P1 | Done on develop | Add TypeScript client. | Apps can query current and historical authorization and recognition state and verify anchored evidence. |
| TR-015 | P1 | Done on develop | Add DID integration test. | `did:midnight` references resolve through `midnight-did` helpers and `MidnightDIDResolver` fixtures without copying DID logic. |
| TR-016 | P1 | Done on develop | Add VC integration test. | VC verifier consumes TR evidence plus status evidence. |
| TR-017 | P2 | Done on develop | Add TRQP read adapter. | Registry metadata, authorization, recognition, and historical evidence map to TRQP-style responses. |
| TR-018 | P2 | Done on develop | Add OpenID Federation adapter experiment. | Signed metadata and trust-chain mapping are documented and fixture-tested. |
| TR-019 | P2 | Done on develop | Add operator CLI. | Maintainers can initialize, inspect, and export registry state locally. |
| TR-020 | P2 | Done on develop | Add audit report generator. | A command emits human-readable authorization and policy history. |
| TR-021 | P1 | Done on develop | Add issuer application-state workflow. | Issuer authorization supports explicit `proposed`, `authorized`, and `active` states with positive and negative tests plus historical evidence. |
| TR-022 | P1 | Done on develop | Add verifier, recognition, and auditor application workflows. | Verifier, recognition, and auditor flows support governed proposal and approval state instead of direct-only activation. |
| TR-023 | P1 | Draft PR `#12` on `codex/trust-registry-maintainer-membership-lifecycle` | Add maintainer membership lifecycle. | Admin onboarding/removal is modeled explicitly, and no new maintainer can self-approve into the registry. |
| TR-024 | P1 | Draft PR `#13` on `codex/trust-registry-quorum-execution` | Add multi-maintainer quorum execution. | Thresholds above `1-of-N` work on-chain with signer-set evidence and policy-scoped quorum rules. |
| TR-025 | P1 | Draft PR `#14` on `codex/trust-registry-governance-policy-bindings` | Add governance policy templates and bindings. | Maintainer, member, emergency, and auditor decisions can bind to typed policy templates and fixtures. |
| TR-026 | P2 | Draft PR `#15` on `codex/trust-registry-mutable-operator-cli` | Add mutable operator CLI workflows. | Operators can submit, approve, activate, suspend, revoke, and epoch-publish from the CLI without raw simulator access. |
| TR-027 | P2 | Draft PRs `#16` and `#17` on `codex/trust-registry-api-query-surface` and `codex/trust-registry-api-application-surface` | Add applicant and query REST API. | Applicants can submit applications and consumers can query trust/evidence through stable HTTP endpoints. |
| TR-028 | P2 | Draft PRs `#18` and `#19` on `codex/trust-registry-admin-console` and `codex/trust-registry-applicant-portal` | Add admin console and applicant portal scaffold. | A local UI supports proposal review, approval, and public registry inspection flows on top of the API/client. |
| TR-029 | P2 | Draft PR `#20` on `codex/trust-registry-historical-timestamp-queries` with follow-up slices planned | Add historical timestamp queries and proof hardening. | Client and adapters can answer trust decisions by timestamp and export stronger inclusion-proof material than the current signed-statement anchor. |
| TR-030 | P2 | Planned stack from `codex/trust-registry-demo-fixtures` | Add release, demo, and package flow. | The repo ships a reproducible demo registry, packaged artifacts, and CI validation for the documented operator flow. |

## First PR Stack

1. `codex/trust-registry-docs-foundation`: documentation migration, spec, plan, backlog, and project README.
2. `codex/trust-registry-dev-workflow`: local agent guidance, docs validation, and CI alignment for `develop`.

## Implementation Notes

- Keep status and revocation in VC status registry packages.
- Keep DID CRUD and resolver behavior in DID packages.
- Start integration coverage with an in-process simulator lane before binding TR
  to DID and VC runtime dependencies.
- Use append-only state for decisions that affect long-term verification.
- Keep holder data out of TR state and query logs.
- Keep recognition separate from authorization.
- Keep the first client package evidence-first: query raw contract state, then
  validate anchored bundles against published epoch records before adding richer
  adapters.
- Keep DID-backed scenarios on the shared integration lane by consuming the
  official `midnight-did` package surface and fixture ledger state rather than
  re-implementing DID parsing or resolution logic inside TR.

## Next 10 PR Stack

1. `codex/trust-registry-applicant-portal`
   - second `TR-028` slice
   - add applicant submission and public active-registry inspection UI flows
2. `codex/trust-registry-historical-timestamp-queries`
   - first `TR-029` slice
   - add timestamp-based trust queries across snapshot, client, CLI, and HTTP surfaces
3. `codex/trust-registry-proof-bundle-hardening`
   - second `TR-029` slice
   - replace the placeholder signed-statement proof with stronger inclusion-proof material and verification
4. `codex/trust-registry-historical-evidence-adapters`
   - third `TR-029` slice
   - expose timestamped historical trust evidence through TRQP and HTTP adapter surfaces
5. `codex/trust-registry-demo-fixtures`
   - first `TR-030` slice
   - add reproducible demo registry fixtures and deterministic mutable workspace seeds
6. `codex/trust-registry-demo-orchestration`
   - second `TR-030` slice
   - add local scripts to boot the demo API, admin console, and applicant portal together
7. `codex/trust-registry-package-artifacts`
   - third `TR-030` slice
   - package demo and release artifacts for CLI, API, and UI consumers
8. `codex/trust-registry-demo-ci`
   - fourth `TR-030` slice
   - validate the documented demo flow from a clean checkout in CI
9. `codex/trust-registry-release-docs`
   - fifth `TR-030` slice
   - publish release/demo operator documentation and final package boundaries
10. `codex/trust-registry-release-hardening`
    - sixth `TR-030` slice
    - close reproducibility gaps, runtime regressions, and final acceptance issues before release
