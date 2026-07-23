# Trust Registry Execution Backlog

Status: active
Updated: 2026-07-23

## Priority Model

- P0: needed before meaningful implementation can start.
- P1: needed for the first usable prototype.
- P2: needed for interoperability, operations, or polish.

## Current Backlog

| ID | Priority | Status | Item | Acceptance |
| --- | --- | --- | --- | --- |
| TR-001 | P0 | Done in docs foundation | Move trust registry spec, plan, research memo, and decisions into this repository. | `docs/spec`, `docs/plans`, `docs/research`, and `docs/decisions` contain public TR source material. |
| TR-002 | P0 | Done in docs foundation | Replace template README with project-specific scope. | README explains scope, non-scope, repo boundaries, and documentation map. |
| TR-003 | P0 | Done on develop | Add repository-local agent guidance. | `AGENT.md`, `.codex`, and `.claude` point engineers to the same TR rules. |
| TR-004 | P0 | Done on develop | Add lightweight docs validation. | `./scripts/check-docs.sh` checks markdown links and required docs without requiring a package manager. |
| TR-005 | P0 | Done on develop | Make CI target `develop`. | Docs and scan workflows run for pull requests into `develop`. |
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
| TR-023 | P1 | Open issue [#29](https://github.com/midnightntwrk/midnight-trust-registry/issues/29) | Add maintainer membership lifecycle. | Admin onboarding/removal is modeled explicitly, and no new maintainer can self-approve into the registry. |
| TR-024 | P1 | Open issue [#30](https://github.com/midnightntwrk/midnight-trust-registry/issues/30) | Add multi-maintainer quorum execution. | Thresholds above `1-of-N` work on-chain with signer-set evidence and policy-scoped quorum rules. |
| TR-025 | P1 | Open issue [#31](https://github.com/midnightntwrk/midnight-trust-registry/issues/31) | Add governance policy templates and bindings. | Maintainer, member, emergency, and auditor decisions can bind to typed policy templates and fixtures. |
| TR-026 | P2 | Open issue [#32](https://github.com/midnightntwrk/midnight-trust-registry/issues/32) | Add mutable operator CLI workflows. | Operators can submit, approve, activate, suspend, revoke, and epoch-publish from the CLI without raw simulator access. |
| TR-027 | P2 | Open issues [#33](https://github.com/midnightntwrk/midnight-trust-registry/issues/33) and [#34](https://github.com/midnightntwrk/midnight-trust-registry/issues/34) | Add applicant and query REST API. | Applicants can submit applications and consumers can query trust/evidence through stable HTTP endpoints. |
| TR-028 | P2 | Open issues [#35](https://github.com/midnightntwrk/midnight-trust-registry/issues/35) and [#36](https://github.com/midnightntwrk/midnight-trust-registry/issues/36) | Add admin console and applicant portal scaffold. | A local UI supports proposal review, approval, and public registry inspection flows on top of the API/client. |
| TR-029 | P2 | Open issues [#37](https://github.com/midnightntwrk/midnight-trust-registry/issues/37), [#38](https://github.com/midnightntwrk/midnight-trust-registry/issues/38), and [#39](https://github.com/midnightntwrk/midnight-trust-registry/issues/39) | Add historical timestamp queries and proof hardening. | Client and adapters can answer trust decisions by timestamp and export canonical `merkle-inclusion` evidence bundles instead of the earlier signed-statement placeholder. |
| TR-030 | P2 | Open issues [#40](https://github.com/midnightntwrk/midnight-trust-registry/issues/40) through [#45](https://github.com/midnightntwrk/midnight-trust-registry/issues/45) | Add release, demo, and package flow. | The repo ships a reproducible demo registry, packaged artifacts, and CI validation for the documented operator flow. |
| TR-031 | P1 | Open issue [#46](https://github.com/midnightntwrk/midnight-trust-registry/issues/46) | Harden public-repo governance, pnpm baseline, and quality workflows. | The public repo has pnpm-native docs, PR governance, dependency automation, and a DID-style quality lane. |
| TR-032 | P2 | Open issue [#47](https://github.com/midnightntwrk/midnight-trust-registry/issues/47) | Add trust-registry publish and release-smoke workflows. | The repo can publish intended artifacts and run a smoke test over the published outputs. |
| TR-033 | P2 | Open issue [#48](https://github.com/midnightntwrk/midnight-trust-registry/issues/48) | Automate published DID and VC dependency refresh with compatibility checks. | Published tarball refresh is scriptable and validated against the TR light/integration lanes. |
| TR-034 | P1 | Open issue [#49](https://github.com/midnightntwrk/midnight-trust-registry/issues/49) | Align backlog and knowledge base with live GitHub issue tracking. | Checked-in planning docs point to live issues instead of stale stacked-PR state. |

## Historical Foundation

The first docs-foundation and repo-workflow slices are already merged on
`develop`. Current execution is tracked through the GitHub issues listed above
instead of the earlier stacked-PR queue.

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

## First 20 GitHub Issues

1. [#29](https://github.com/midnightntwrk/midnight-trust-registry/issues/29) `TR-023`: maintainer membership lifecycle
2. [#30](https://github.com/midnightntwrk/midnight-trust-registry/issues/30) `TR-024`: multi-maintainer quorum execution
3. [#31](https://github.com/midnightntwrk/midnight-trust-registry/issues/31) `TR-025`: governance policy templates and bindings
4. [#32](https://github.com/midnightntwrk/midnight-trust-registry/issues/32) `TR-026`: mutable operator CLI workflows
5. [#33](https://github.com/midnightntwrk/midnight-trust-registry/issues/33) `TR-027A`: read-only query API
6. [#34](https://github.com/midnightntwrk/midnight-trust-registry/issues/34) `TR-027B`: governed application API
7. [#35](https://github.com/midnightntwrk/midnight-trust-registry/issues/35) `TR-028A`: admin console scaffold
8. [#36](https://github.com/midnightntwrk/midnight-trust-registry/issues/36) `TR-028B`: applicant portal scaffold
9. [#37](https://github.com/midnightntwrk/midnight-trust-registry/issues/37) `TR-029A`: timestamp-based trust evaluation
10. [#38](https://github.com/midnightntwrk/midnight-trust-registry/issues/38) `TR-029B`: canonical merkle-inclusion proof bundles
11. [#39](https://github.com/midnightntwrk/midnight-trust-registry/issues/39) `TR-029C`: historical evidence adapters
12. [#40](https://github.com/midnightntwrk/midnight-trust-registry/issues/40) `TR-030A`: demo fixtures
13. [#41](https://github.com/midnightntwrk/midnight-trust-registry/issues/41) `TR-030B`: local demo orchestration
14. [#42](https://github.com/midnightntwrk/midnight-trust-registry/issues/42) `TR-030C`: package and release artifacts
15. [#43](https://github.com/midnightntwrk/midnight-trust-registry/issues/43) `TR-030D`: demo CI
16. [#44](https://github.com/midnightntwrk/midnight-trust-registry/issues/44) `TR-030E`: release/demo docs
17. [#45](https://github.com/midnightntwrk/midnight-trust-registry/issues/45) `TR-030F`: release hardening
18. [#46](https://github.com/midnightntwrk/midnight-trust-registry/issues/46) `TR-031`: public-repo hardening parity
19. [#47](https://github.com/midnightntwrk/midnight-trust-registry/issues/47) `TR-032`: publish and release-smoke workflows
20. [#48](https://github.com/midnightntwrk/midnight-trust-registry/issues/48) `TR-033`: published DID/VC dependency refresh automation
