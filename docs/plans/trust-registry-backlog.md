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
| TR-027 | P2 | Draft PR `#16` on `codex/trust-registry-api-query-surface` | Add applicant and query REST API. | Applicants can submit applications and consumers can query trust/evidence through stable HTTP endpoints. |
| TR-028 | P2 | Planned stack `codex/trust-registry-admin-console` | Add admin console and applicant portal scaffold. | A local UI supports proposal review, approval, and public registry inspection flows on top of the API/client. |
| TR-029 | P2 | Planned stack `codex/trust-registry-historical-proof-hardening` | Add historical timestamp queries and proof hardening. | Client and adapters can answer trust decisions by timestamp and export stronger inclusion-proof material than the current signed-statement anchor. |
| TR-030 | P2 | Planned stack `codex/trust-registry-release-demo-flow` | Add release, demo, and package flow. | The repo ships a reproducible demo registry, packaged artifacts, and CI validation for the documented operator flow. |

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

1. `codex/trust-registry-maintainer-membership-lifecycle`
   - `TR-023`
   - add governed maintainer onboarding, activation, suspension, revocation, and archival
2. `codex/trust-registry-quorum-execution`
   - `TR-024`
   - replace the current single-signature maintainer shortcut with policy-aware quorum execution
3. `codex/trust-registry-governance-policy-bindings`
   - `TR-025`
   - bind maintainer, member, emergency, and auditor actions to typed governance policy templates
4. `codex/trust-registry-mutable-operator-cli`
   - `TR-026`
   - add operator commands for submit, approve, activate, suspend, revoke, archive, and epoch publication
5. `codex/trust-registry-api-query-surface`
   - first `TR-027` slice
   - expose stable read/query HTTP endpoints over the client and adapter surfaces
6. `codex/trust-registry-api-application-surface`
   - second `TR-027` slice
   - expose applicant submission and maintainer approval endpoints with governed workflow semantics
7. `codex/trust-registry-admin-console`
   - first `TR-028` slice
   - add admin review and approval UI flows on top of the API
8. `codex/trust-registry-applicant-portal`
   - second `TR-028` slice
   - add applicant submission and public registry inspection UI flows
9. `codex/trust-registry-historical-proof-hardening`
   - `TR-029`
   - add timestamp-based trust queries and stronger inclusion-proof export
10. `codex/trust-registry-release-demo-flow`
    - `TR-030`
    - package the demo flow, release artifacts, and CI-backed reproducibility checks
