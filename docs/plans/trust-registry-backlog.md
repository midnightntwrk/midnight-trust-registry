# Trust Registry Execution Backlog

Status: active
Updated: 2026-05-20

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
| TR-010 | P1 | Active branch `codex/trust-registry-issuer-authorization` | Add issuer authorization circuits. | Create, suspend, revoke, archive, and query paths have positive and negative tests. |
| TR-011 | P1 | Open | Add verifier authorization circuits. | Request-profile authorization supports disclosure and predicate scopes. |
| TR-012 | P1 | Open | Add recognition circuits. | Recognized external authority state is separate from local authorization state. |
| TR-013 | P1 | Open | Add epoch anchor. | Maintainer-signed state roots can be published and verified. |
| TR-014 | P1 | Open | Add TypeScript client. | Apps can query current and historical authorization state. |
| TR-015 | P1 | Open | Add DID integration test. | `did:midnight` references resolve through DID repo APIs or fixtures without copying DID logic. |
| TR-016 | P1 | Open | Add VC integration test. | VC verifier consumes TR evidence plus status evidence. |
| TR-017 | P2 | Open | Add TRQP read adapter. | Registry metadata, authorization, recognition, and historical evidence map to TRQP-style responses. |
| TR-018 | P2 | Open | Add OpenID Federation adapter experiment. | Signed metadata and trust-chain mapping are documented and fixture-tested. |
| TR-019 | P2 | Open | Add operator CLI. | Maintainers can initialize, inspect, and export registry state locally. |
| TR-020 | P2 | Open | Add audit report generator. | A command emits human-readable authorization and policy history. |

## First PR Stack

1. `codex/trust-registry-docs-foundation`: documentation migration, spec, plan, backlog, and project README.
2. `codex/trust-registry-dev-workflow`: local agent guidance, docs validation, and CI alignment for `develop`.

## Implementation Notes

- Keep status and revocation in VC status registry packages.
- Keep DID CRUD and resolver behavior in DID packages.
- Use append-only state for decisions that affect long-term verification.
- Keep holder data out of TR state and query logs.
- Keep recognition separate from authorization.
