# Milestone 0.1.0 delivery harness

`milestone-0.1.0` is a product integration train based on `develop`. It is not
a release branch. The branch accepts issue-backed PRs after exact-head review
and CI; promotion back to `develop` requires the normal human review policy.

## Authority and scope

| Target | Merge authority | Minimum evidence |
| --- | --- | --- |
| `milestone-0.1.0` | Agent/operator after guard checks | Issue, documented current-head review, green required CI, signed commits, resolved conversations |
| `develop` | Human review | Existing protected-branch policy and integration evidence |
| `main` | Human release review | Release policy and complete release validation |

No agent may use `--admin`, direct push, force push, or a branch-protection
bypass to land a milestone increment. A CI pass is not a substitute for review.
Self-review is allowed for low-risk changes; contract, cryptography, governance,
security, credential trust decisions, and CI/merge-policy changes need a
second-opinion external review (Claude CLI or another independent reviewer).
Blocking findings must be fixed before merge. Record advisory findings and
their disposition in the PR, with a linked follow-up issue when deferred.

## One-PR loop

1. Select a ready issue with acceptance criteria and base `milestone-0.1.0`.
2. Use an isolated `codex/` branch; run focused tests, then `./run.sh --light`.
   Run `./run.sh integration` for contract, client, API, or UI behavior changes.
3. Push DCO-signed and GPG-signed commits. Open a PR to the milestone branch
   with a GitHub closing keyword or `Refs #N` in its body. Keep the PR below
   GitHub's 250-commit PR-listing limit; larger trains require manual audit.
4. Review the final diff. Fill `## Review findings` with the reviewed head SHA,
   reviewer or tool, review round, blocking/advisory dispositions, and, if
   external, a review link. A new push invalidates prior exact-head review
   evidence; repeat the review on the new head. This is an operator process,
   not a CI-attested approval.
5. Confirm `Milestone Light`, `scan`, and `Quality` are green
   for the current head. Resolve review conversations and confirm mergeability.
   If the base moved, rebase or merge locally with a verified signature and DCO
   trailer, then repeat the exact-head review. GitHub's Update branch button
   can create an unsigned-off merge commit and does not satisfy the DCO policy.
6. Re-read the PR head immediately before merging. Merge only with the
   compare-and-swap guard; never use `--admin`:

   ```bash
   gh pr merge <number> -R midnightntwrk/midnight-trust-registry \
     --merge --match-head-commit <reviewed-head-sha>
   ```

   The branch protection settings, not a local script, enforce the PR,
   signature, status, and conversation gates. The SHA flag prevents a race
   with a subsequent push. Merge one PR at a time, bottom-up for stacks.

## Bounded review loop

One round is one completed correctness/security review of a candidate head,
followed by finding disposition and, if needed, a fix push. Record each round
and its head in `## Review findings`.
Allow at most three completed rounds per PR. Before round three, batch related
fixes rather than pushing after each comment. After round three, do not start
another automatic review/fix loop. Open a linked follow-up issue for any
remaining advisory finding with owner, risk, and acceptance criteria. If a
blocking finding remains, create a follow-up issue but leave the PR unmerged
and explicitly blocked; never convert a security, correctness, data-integrity,
or CI failure into an advisory solely to meet the round limit. A changed head
without a valid final-head review cannot merge.

## Hosted gates

- `Milestone Light`: unconditional Compact version check, `./run.sh --light`,
  DID/VC integration scenarios, and `pnpm run demo:smoke` on milestone PRs,
  even docs-only PRs. The existing path-filtered `CI` PR lane excludes
  milestone to avoid a duplicate Compact build.
- `Quality`: build, typecheck, and dependency audit on milestone PRs and train
  PRs. Require its `Typecheck, Audit, and Packaging Baseline` job before
  autonomous merges. Issue #84 tracks reducing its critical path; a slow check
  is not an authorization to merge red CI.
- `Scan`: security scan on every PR and milestone push.
- Existing docs and PR-title checks remain applicable where triggered.

The milestone branch must require PRs, zero general approving GitHub reviews,
strict up-to-date checks (`Milestone Light`, `scan`, and
`Typecheck, Audit, and Packaging Baseline`), signed commits, and resolved
conversations. Enable code-owner review for the gate source and all workflow
files using the milestone branch's root `CODEOWNERS`; ordinary product PRs remain zero-human-review
unless they touch those paths. Issue #84 tracks a faster fail-closed Quality
lane, not removal of the gate.
Force pushes and deletions must be disabled. Verify these settings through the
GitHub API after configuration. Do not weaken `develop` or `main` protection.

## Boundaries

This is deliberately smaller than the `factory` harness: no custom Pi runtime,
claim leases, metrics database, change-classification engine, or automated
merger. Add those only when a measured delivery bottleneck justifies them.
Review findings in the PR body are process evidence, not an enforced or
cryptographic attestation. The operator must verify review of the final head
before merging. Self-review is documented in the PR because GitHub does not
permit authors to approve their own PRs. DCO signoffs are checked locally by
the operator; branch protection enforces signed commits but not DCO trailers.

The initial bootstrap PR #91 requires external exact-head review and all
hosted gates before merge. The bootstrap must not be represented as already
protected by code-owner review. After it lands, enable code-owner review, then
test a canary PR that modifies a workflow or policy file. The canary must be
blocked without code-owner approval. Do not run an autonomous milestone merge
before this is confirmed.

Code-owner review protects workflow, build entrypoints, package scripts, and
policy changes. The agent guide and this delivery policy are code-owned too,
so a docs-only PR cannot silently weaken merge authority. Milestone pushes do
not publish the shared Turbo cache used by PRs; only trusted `develop` and
`main` pushes may publish it. [CI optimization issue #84](https://github.com/midnightntwrk/midnight-trust-registry/issues/84)
tracks a measured path to faster, fail-closed routing.

The milestone branch intentionally scopes root `CODEOWNERS` to policy and
build-control files so ordinary product PRs can merge without a GitHub human
approval. `develop` and `main` retain their existing root catch-all owner
rule. A promotion PR into `develop` must restore that catch-all before merge;
never promote the milestone-specific ownership file unchanged.

After the pending milestone specification PR lands in `develop`, sync it into
the train through a separate PR and rerun the complete train gates. Do not
silently rebase or force-push the protected milestone branch.
