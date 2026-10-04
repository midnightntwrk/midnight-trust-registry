# Milestone 0.1.0 delivery harness

`milestone-0.1.0` is a product integration train based on `develop`. It is not
a release branch. The branch accepts issue-backed PRs after exact-head review
and CI; promotion back to `develop` requires the normal human review policy.

## Authority and scope

| Target | Merge authority | Minimum evidence |
| --- | --- | --- |
| `milestone-0.1.0` | Agent/operator after guard checks | Issue, current-head review receipt, green required CI, signed commits, resolved conversations |
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
   with `Closes #N`, `Fixes #N`, or `Refs #N` in its body.
4. Review the final diff. Fill `## Review findings` with blocking/advisory
   dispositions, the review round, and, if external, a review link. Add exactly
   one receipt on its own line, replacing `<head>`, `<mode>`, and `<round>`:

   ```text
   <!-- tr-review:v1 head=<head> mode=<mode> round=<round> verdict=pass -->
   ```

   `<head>` is the 40-character GitHub PR head SHA; `<mode>` is `self` or
   `external`; `<round>` is `1`, `2`, or `3`. Editing the PR body reruns only
   `Milestone Review`. A new push
   invalidates the old receipt and all prior exact-head review evidence.
5. Confirm `Milestone Review`, `Milestone Light`, and `scan` are green for the
   current head. Inspect `Quality` and all other non-required checks. During
   the 0.1.0 delivery week, a pending or red `Quality` result may be deferred
   only with a linked issue, root cause, and risk disposition in the PR; a new
   unexplained failure or a runtime security blocker still stops merge. Resolve
   review conversations, confirm mergeability, and refresh the base if stale.
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
and its head in `## Review findings`; the final receipt names the last round.
Allow at most three completed rounds per PR. Before round three, batch related
fixes rather than pushing after each comment. After round three, do not start
another automatic review/fix loop. Open a linked follow-up issue for any
remaining advisory finding with owner, risk, and acceptance criteria. If a
blocking finding remains, create a follow-up issue but leave the PR unmerged
and explicitly blocked; never convert a security, correctness, data-integrity,
or CI failure into an advisory solely to meet the round limit. A changed head
without a valid final-head review cannot merge.

## Hosted gates

- `Milestone Review`: exact-head review receipt, issue link, findings text,
  author-matching DCO signoffs for new commits, and harness unit tests.
  Develop commits already accepted on the human-reviewed branch are
  grandfathered for explicit develop-to-milestone sync PRs. The job uses
  read-only permissions and no secrets.
- `Milestone Light`: unconditional `./run.sh --light` and `pnpm run demo:smoke`
  on milestone PRs, even
  docs-only PRs. The existing path-filtered `CI` PR lane excludes milestone
  to avoid a duplicate Compact build.
- `Quality`: build, typecheck, and dependency audit on milestone PRs and train
  pushes. It is temporarily non-blocking because a docs-only run took over
  43 minutes and the current audit baseline is red. See #84 and #86. Revisit
  this exception by 2026-10-12; do not remove the workflow.
- `Scan`: security scan on every PR and milestone push.
- Existing docs and PR-title checks remain applicable where triggered.

The milestone branch must require PRs, zero approving GitHub reviews, strict
up-to-date checks (`Milestone Review`, `Milestone Light`, `scan`), signed
commits, and resolved conversations. This is a temporary delivery-week profile,
not a claim that full Quality passed. Restore a fast fail-closed Quality
aggregator after #84 and #86 are resolved.
Force pushes and deletions must be disabled. Verify these settings through the
GitHub API after configuration. Do not weaken `develop` or `main` protection.

## Boundaries

This is deliberately smaller than the `factory` harness: no custom Pi runtime,
claim leases, metrics database, change-classification engine, or automated
merger. Add those only when a measured delivery bottleneck justifies them.
The body receipt is an attestation, not cryptographic proof of review. CI
verifies freshness and form; the operator remains responsible for the actual
review and disposition. For now, a self-review is a documented process rather
than a GitHub approval because GitHub does not permit authors to approve their
own PRs.

The review validator currently runs from the PR checkout, so a PR changing
the validator or its workflow can affect its own check. Treat such changes as
security-sensitive and require independent review of the exact diff before
merging; a trusted-base gate is a later hardening step. The full Quality lane
is currently too slow for docs-only PRs; [CI optimization issue #84](https://github.com/midnightntwrk/midnight-trust-registry/issues/84)
tracks a measured path to faster, fail-closed routing.

After the pending milestone specification PR lands in `develop`, sync it into
the train through a separate PR and rerun the complete train gates. Do not
silently rebase or force-push the protected milestone branch.
