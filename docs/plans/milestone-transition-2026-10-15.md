# 0.1.0 to 0.2.0 transition review

Status: release-scope decision recorded; not a release declaration
Reviewed: 2026-10-15

## Decision boundary

The owner chose to retain the published
[0.1.0 reference profile](../spec/milestone-0.1.0.md) as the release
contract. Its open acceptance issues remain in the 0.1.0 milestone until they
are implemented with evidence. A simulator demonstration is not evidence of a
production ledger adapter, published package, or live credential-status check.

The `milestone-0.1.0` branch is the integration source for a future PR into
`develop`; `develop` then needs a separate, reviewed promotion into `main`.
Neither promotion is an automatic release. Before opening the first PR,
reconcile the three commits present only on `develop`, finish or explicitly
defer the unmerged local #196 fixes, and run the exact-head validation and
review required by the destination branch. Do not direct-push or bypass gates.

## Current evidence and gaps

- No open PR was found at the review point. The milestone branch was 583
  commits ahead of and three behind `develop`; `develop` was 102 ahead of and
  eight behind `main`. The branches require integration, not a blind fast-forward.
- Fourteen 0.1.0 issues remained open. The critical path in
  [the executable issue plan](milestone-0.1.0-issues.md) still includes VC/VP
  eligibility and contract verification (#76, #67), signed public mutations
  (#77), independently verifiable decisions (#39, #79, #73), complete actor
  journeys and negatives (#58, #78, #59, #60), and release artifacts (#45).
- A full local simulator integration passed on the signed local #196 stack,
  including 66 Compact circuits and its actor demos. This validates the local
  reference journey; it does not close the open acceptance criteria above.
- The full contract distribution is approximately 2 GiB. The package-content
  gate fails during npm pack dry-run with `ERR_OUT_OF_RANGE: data is too long`.
  #45 remains a release blocker until artifacts are split, packaged, and
  digest-verified from a clean checkout.
- #178 documents the owner's decision that milestone PRs require green
  exact-head CI and current-head LLM review, without GitHub branch protection.
  The repository's agent/harness text must be reconciled with that decision.

## Retrospective

| Observation | Adjustment |
| --- | --- |
| Many small PRs and serial CI rounds slowed functional delivery. | Develop coherent actor journeys locally, reuse a worktree for small changes, and publish reviewable feature batches. |
| Expensive Compact artifact generation dominated integration and CI. | Keep light tests fast; measure cold and warm full-test time separately from cache-hit counts. Cache only compiler-compatible deterministic artifacts, never proofs or assertions. |
| The local simulator exposed useful regressions, but could be mistaken for a production-ready service. | Label simulator, finalized-ledger, status-authority, and network boundaries in tests, docs, and release notes. |
| Issue closure lagged implementation and some policy documentation drifted. | Attach PR, merge SHA, validation, and deliberate deferrals when closing issues; reconcile #178 and the release profile before promotion. |
| Package size was discovered at the final packaging gate. | Make artifact topology and clean-checkout package checks an early release workstream. |

## 0.2.0 candidate order

The [0.2.0 milestone](https://github.com/midnightntwrk/midnight-trust-registry/milestone/2)
tracks work beyond the agreed 0.1.0 acceptance boundary. Prioritize features
and externally visible safety before CI or repository polish:

1. #152: complete the auditor applicant portal journey and role-disjoint
   positive/negative API tests.
2. #159 and #179: define current TRQP decision time, proof freshness, and
   operative-window behavior before promising current trust answers.
3. #193 and #124: capacity, rotation, recovery, and challenge-store retry
   semantics for a durable public intake host.
4. #167, #130, #101, and #176: signed-intent mapping, governed-resource and
   challenge invariants, canonical JubJub ingress, and signer-rotation tests.
5. #47 and #62: publication flow and public documentation, after the #45
   contract-package topology is resolved.
6. #84, #157, #158, #168, #95, #64, #63, and #61: CI/dependency/source-boundary
   housekeeping, sequenced behind functional delivery unless they block it.

#195 is blocked on Forge/backend compatibility, not a reason to upgrade
dependencies or alter a real circuit. #194 is Renovate's Dependency Dashboard,
not a product deliverable. Neither was moved to the 0.2.0 milestone. #196
belongs with the 0.1.0 defect-fix stack until its signed local commits are
merged and the issue has acceptance evidence. The 19 numbered 0.2.0 candidate
issues listed above were assigned to the new GitHub milestone.

## Promotion checklist

- Retain the published 0.1.0 reference-profile contract; do not relabel the
  existing branch as a complete internal snapshot or shift its blockers to 0.2.
- Reconcile open 0.1.0 issues against actual merged evidence; do not close a
  partially implemented issue solely because a demonstration passes.
- Merge local #196 fixes through a reviewed milestone PR, then re-run light,
  integration, package-content, and audit checks from the exact integration
  head. Record timings and artifact digests.
- Open a milestone-to-`develop` PR, resolve the divergent commits, and require
  current-head CI, LLM review, and human merge authority.
- Open a separate `develop`-to-`main` PR only once the chosen release profile
  and packaging gate are met; tag or publish only after that PR passes its
  release checklist.
