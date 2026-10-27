import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { archiveAdversarialCaseReport, assertAdversarialMatrixParity, assertCompletedAdversarialRun, parseAdversarialTap,
  runIsolatedAdversarialCases } from "./adversarial-case-report.mjs";

const matrixFor = (report) => ({
  format: "tr-adversarial-matrix-v1",
  summary: { ...report.summary },
  cases: report.cases.map(({ id, status }) => ({
    id, status, invariant: `invariant-${id}`, boundary: "api",
    expected: "http:403/forbidden", observed: "http:403/forbidden",
  })),
});

test("reports every isolated outcome after a case fails", () => {
  const directory = mkdtempSync(join(tmpdir(), "tr-adversarial-report-"));
  try {
    const file = join(directory, "cases.mjs");
    writeFileSync(file, `import { test } from "node:test";
test("case-a", () => {});
test("case-b", () => { throw new Error("deliberate failure"); });
test("case-c", () => {});
`);
    const report = runIsolatedAdversarialCases([file]);
    assert.deepEqual(report.summary, { total: 3, passed: 2, failed: 1 });
    assert.deepEqual(report.cases, [
      { id: "case-a", status: "passed", reason: "passed" },
      { id: "case-b", status: "failed", reason: "assertion-failed" },
      { id: "case-c", status: "passed", reason: "passed" },
    ]);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects duplicate IDs and classifies missing outcomes", () => {
  assert.throws(() => parseAdversarialTap(`# Subtest: case-a
ok 1 - case-a
# Subtest: case-a
ok 2 - case-a
# tests 2
`), /Duplicate isolated adversarial case/u);
  const report = parseAdversarialTap(`# Subtest: case-a
ok 1 - case-a
# Subtest: case-b
# tests 2
`);
  assert.deepEqual(report.cases[1], { id: "case-b", status: "failed", reason: "missing-outcome" });
});

test("rejects an outcome attributed to another isolated case", () => {
  assert.throws(() => parseAdversarialTap("# Subtest: case-a\nok 1 - case-b\n# tests 1\n"),
    /outcome ID differs from subtest/u);
  assert.throws(() => parseAdversarialTap("# Subtest: case-a\nnot ok 1 - case-b\n# tests 1\n"),
    /outcome ID differs from subtest/u);
});

test("rejects multiple outcomes for one isolated case", () => {
  assert.throws(() => parseAdversarialTap(
    "# Subtest: case-a\nok 1 - case-a\nnot ok 2 - case-a\n# tests 1\n"),
  /Multiple isolated adversarial outcomes/u);
});

test("does not accept an interrupted or abnormal runner as a complete failed-case report", () => {
  const report = parseAdversarialTap("# Subtest: case-a\nnot ok 1 - case-a\n# tests 1\n");
  assert.doesNotThrow(() => assertCompletedAdversarialRun({ status: 1, signal: null }, report));
  assert.throws(() => assertCompletedAdversarialRun({ status: null, signal: "SIGTERM" }, report),
    /did not complete normally/u);
  assert.throws(() => assertCompletedAdversarialRun({ status: 2, signal: null }, report),
    /did not complete normally/u);
  assert.throws(() => assertCompletedAdversarialRun({ status: 0, signal: null }, report),
    /disagrees with per-case outcomes/u);
});

test("archives the complete case report once under a private source-scoped path", async () => {
  const directory = mkdtempSync(join(tmpdir(), "tr-adversarial-archive-"));
  try {
    const report = parseAdversarialTap(`# Subtest: case-a
ok 1 - case-a
# Subtest: case-b
not ok 2 - case-b
# tests 2
`);
    const matrix = matrixFor(report);
    const sourceRevision = "a".repeat(40);
    const archived = await archiveAdversarialCaseReport(report, sourceRevision, directory, matrix);
    const bytes = readFileSync(archived.path);
    assert.deepEqual(JSON.parse(bytes), {
      format: "tr-adversarial-case-archive-v2", sourceRevision,
      isolatedReport: report, governedDemoMatrix: matrix,
    });
    assert.equal(statSync(archived.path).mode & 0o077, 0);
    assert.equal(archived.summary.failed, 1);
    await assert.rejects(archiveAdversarialCaseReport(report, sourceRevision, directory, matrix),
      { code: "EEXIST" });
    assert.deepEqual(readFileSync(archived.path), bytes);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("rejects a public archive directory or malformed source revision", async () => {
  const directory = mkdtempSync(join(tmpdir(), "tr-adversarial-public-"));
  try {
    const report = parseAdversarialTap("# Subtest: case-a\nok 1 - case-a\n# tests 1\n");
    const matrix = matrixFor(report);
    await assert.rejects(archiveAdversarialCaseReport(report, "bad", directory, matrix),
      /source revision/u);
    chmodSync(directory, 0o755);
    await assert.rejects(archiveAdversarialCaseReport(report, "a".repeat(40), directory, matrix),
      /private directory/u);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("requires complete invariant metadata with exact isolated case parity", () => {
  const report = parseAdversarialTap("# Subtest: case-a\nok 1 - case-a\n# tests 1\n");
  const matrix = matrixFor(report);
  assert.doesNotThrow(() => assertAdversarialMatrixParity(report, matrix));
  assert.throws(() => assertAdversarialMatrixParity(report, { ...matrix,
    cases: [{ ...matrix.cases[0], invariant: "" }],
  }), /invariant/u);
  assert.throws(() => assertAdversarialMatrixParity(report, { ...matrix,
    cases: [{ ...matrix.cases[0], id: "other-case" }],
  }), /IDs differ/u);
  assert.throws(() => assertAdversarialMatrixParity(report, { ...matrix,
    summary: { ...matrix.summary, total: 2 },
  }), /2 !== 1/u);
});
