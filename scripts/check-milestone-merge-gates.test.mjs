import assert from "node:assert/strict";
import { test } from "node:test";

import { evaluateMilestoneMergeGate } from "./check-milestone-merge-gates.mjs";

const head = "a".repeat(40);
const signature = "-----BEGIN PGP SIGNATURE-----\nfixture\n-----END PGP SIGNATURE-----";
const check = (name, id, conclusion = "success") => ({
  name, id, head_sha: head, status: "completed", conclusion,
});
const fixture = () => ({
  pull: { number: 42, state: "open", draft: false, mergeable: true,
    base: { ref: "milestone-0.1.0", sha: "c".repeat(40) }, head: { sha: head } },
  commits: [{ sha: head, commit: { author: { name: "Reviewer", email: "reviewer@example.test" },
    message: "fix: checked change\n\nSigned-off-by: Reviewer <reviewer@example.test>",
    verification: { verified: true, reason: "valid", signature } } }],
  checks: [check("Milestone Build, Package, and Test", 1), check("scan", 2),
    check("Typecheck, Audit, and Packaging Baseline", 3), check("docs", 4, "skipped")],
  statuses: [],
  review: { format: "tr-milestone-current-head-review-v1",
    repository: "midnightntwrk/midnight-trust-registry", pullRequest: 42,
    headSha: head, verdict: "no-blockers", reviewer: "Claude CLI",
    evidenceReference: "review/local-42.md", reviewedAt: new Date().toISOString() },
  finalPull: { number: 42, state: "open", draft: false, mergeable: true,
    base: { ref: "milestone-0.1.0", sha: "c".repeat(40) }, head: { sha: head } },
});

test("passes only an exact-head reviewed PR with green applicable jobs and signed DCO commits", () => {
  const result = evaluateMilestoneMergeGate(fixture());
  assert.equal(result.result, "preflight-passed-operator-must-confirm-review-and-merge");
  assert.equal(result.checkedRuns, 4);
  assert.equal(result.checkedCommits, 1);
});

test("rejects a draft, off-train, or changed-head PR", () => {
  for (const change of [
    { pull: { ...fixture().pull, draft: true } },
    { pull: { ...fixture().pull, base: { ref: "develop" } } },
    { finalPull: { ...fixture().finalPull, head: { sha: "b".repeat(40) } } },
    { finalPull: { ...fixture().finalPull, base: { sha: "b".repeat(40) } } },
    { finalPull: { ...fixture().finalPull, state: "closed" } },
    { pull: { ...fixture().pull, mergeable: false } },
  ]) {
    assert.throws(() => evaluateMilestoneMergeGate({ ...fixture(), ...change }), /changed head|off-train/u);
  }
});

test("rejects missing, pending, failed, or wrong-head required checks", () => {
  const renamed = "Milestone Build, Package, and Test";
  const oldNameOnly = fixture();
  oldNameOnly.checks[0] = check("Milestone Light", 1);
  assert.throws(() => evaluateMilestoneMergeGate(oldNameOnly), /Milestone Build, Package, and Test/u);
  const failed = fixture();
  failed.checks[0] = check(renamed, 1, "failure");
  assert.throws(() => evaluateMilestoneMergeGate(failed), /Milestone Build, Package, and Test/u);
  const missing = fixture();
  missing.checks = missing.checks.filter((entry) => entry.name !== "scan");
  assert.throws(() => evaluateMilestoneMergeGate(missing), /scan/u);
  for (const bad of [
    { ...check("scan", 2), status: "in_progress", conclusion: null },
    check("scan", 2, "failure"),
    { ...check("scan", 2), head_sha: "b".repeat(40) },
  ]) {
    const input = fixture();
    input.checks[1] = bad;
    assert.throws(() => evaluateMilestoneMergeGate(input), /check/u);
  }
});

test("rejects an applicable failed check or status, but accepts a successful rerun", () => {
  const input = fixture();
  input.checks.push(check("docs", 5, "failure"));
  assert.throws(() => evaluateMilestoneMergeGate(input), /docs/u);
  input.checks.push(check("docs", 6, "success"));
  input.statuses = [{ id: 1, sha: head, context: "legacy-ci", state: "failure",
    created_at: "2026-10-01T00:00:00Z" }];
  assert.throws(() => evaluateMilestoneMergeGate(input), /legacy-ci/u);
  input.statuses.push({ id: 2, sha: null, context: "legacy-ci", state: "success",
    created_at: "2026-10-01T00:01:00Z" });
  assert.equal(evaluateMilestoneMergeGate(input).checkedStatuses, 1);
});

test("newer failed status wins when GitHub timestamps share a second", () => {
  const input = fixture();
  input.statuses = [
    { id: 10, sha: null, context: "legacy-ci", state: "success",
      created_at: "2026-10-01T00:00:00Z" },
    { id: 11, sha: null, context: "legacy-ci", state: "failure",
      created_at: "2026-10-01T00:00:00Z" },
  ];
  assert.throws(() => evaluateMilestoneMergeGate(input), /legacy-ci/u);
  input.statuses.reverse();
  assert.throws(() => evaluateMilestoneMergeGate(input), /legacy-ci/u);
  input.statuses[0] = { ...input.statuses[0], id: undefined };
  assert.throws(() => evaluateMilestoneMergeGate(input), /malformed/u);
});

test("rejects unsigned, non-OpenPGP, or DCO-mismatched commits", () => {
  for (const verification of [
    { verified: false, reason: "unsigned", signature: null },
    { verified: true, reason: "valid", signature: "ssh signature" },
  ]) {
    const input = fixture();
    input.commits[0].commit.verification = verification;
    assert.throws(() => evaluateMilestoneMergeGate(input), /OpenPGP/u);
  }
  const input = fixture();
  input.commits[0].commit.message = "fix: checked change\n\nSigned-off-by: Someone Else <other@example.test>";
  assert.throws(() => evaluateMilestoneMergeGate(input), /DCO/u);
});

test("rejects an absent, stale, or blocking current-head review record", () => {
  for (const change of [
    { headSha: "b".repeat(40) }, { verdict: "blockers" },
    { evidenceReference: "" }, { reviewedAt: "invalid" },
  ]) {
    const input = fixture();
    input.review = { ...input.review, ...change };
    assert.throws(() => evaluateMilestoneMergeGate(input), /review/u);
  }
});
