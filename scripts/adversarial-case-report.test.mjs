import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { archiveAdversarialCaseReport, assertAdversarialMatrixParity, assertCompletedAdversarialRun, parseAdversarialTap,
  runIsolatedAdversarialCases } from "./adversarial-case-report.mjs";
import { buildAdversarialParityReport } from "./check-adversarial-parity.mjs";

const matrixFor = (report) => ({
  format: "tr-adversarial-matrix-v1",
  summary: { ...report.summary },
  cases: report.cases.map(({ id, status }) => ({
    id, status, invariant: `invariant-${id}`, boundary: "api",
    expected: "http:403/forbidden", observed: "http:403/forbidden",
  })),
});

test("parity reports every isolated outcome when the governed demo aborts", () => {
  const isolatedReport = {
    format: "tr-adversarial-case-report-v1",
    summary: { total: 3, passed: 2, failed: 1 },
    cases: [
      { id: "case-a", status: "passed", reason: "passed" },
      { id: "case-b", status: "failed", reason: "assertion-failed" },
      { id: "case-c", status: "passed", reason: "passed" },
    ],
  };
  const report = buildAdversarialParityReport(isolatedReport, {
    status: 1, signal: null, stdout: "", stderr: "demo setup failed",
  }, true);
  assert.equal(report.status, "failed");
  assert.equal(report.demoCaseCount, null);
  assert.equal(report.missingCaseCount, null);
  assert.deepEqual(report.issues, ["isolated-cases-failed", "governed-demo-process-failed",
    "governed-demo-report-unavailable"]);
  assert.deepEqual(report.isolatedReport.cases, isolatedReport.cases);
  assert.equal(report.demoFailure.reason, "demo setup failed");
});

test("default parity mode rejects an empty isolated case set", () => {
  const empty = {
    format: "tr-adversarial-case-report-v1",
    summary: { total: 0, passed: 0, failed: 0 }, cases: [],
  };
  assert.throws(() => buildAdversarialParityReport(empty, {
    status: 0, signal: null, stdout: JSON.stringify({ adversarialMatrix: {
      format: "tr-adversarial-matrix-v1", summary: { total: 0, failed: 0 }, cases: [],
    } }),
  }), /Isolated adversarial case report is invalid/u);
});

test("parity rejects an isolated summary that hides a failed case", () => {
  const isolated = {
    format: "tr-adversarial-case-report-v1",
    summary: { total: 1, passed: 1, failed: 0 },
    cases: [{ id: "case-a", status: "failed", reason: "assertion-failed" }],
  };
  assert.throws(() => buildAdversarialParityReport(isolated, {
    status: 0, signal: null, stdout: "{}",
  }), /Isolated adversarial case report is invalid/u);
});

test("parity rejects a governed demo summary that hides a failed case", () => {
  const isolated = {
    format: "tr-adversarial-case-report-v1",
    summary: { total: 1, passed: 1, failed: 0 },
    cases: [{ id: "case-a", status: "passed", reason: "passed" }],
  };
  const matrix = {
    format: "tr-adversarial-matrix-v1",
    summary: { total: 1, passed: 1, failed: 0 },
    cases: [{ id: "case-a", status: "failed" }],
  };
  const report = buildAdversarialParityReport(isolated, {
    status: 0, signal: null, stdout: JSON.stringify({ adversarialMatrix: matrix }),
  });
  assert.equal(report.status, "failed");
  assert.ok(report.issues.includes("governed-demo-report-unavailable"));
});

test("parseable demo output without cases retains the isolated diagnostic report", () => {
  const isolated = {
    format: "tr-adversarial-case-report-v1",
    summary: { total: 1, passed: 1, failed: 0 },
    cases: [{ id: "case-a", status: "passed", reason: "passed" }],
  };
  const report = buildAdversarialParityReport(isolated, {
    status: 0, signal: null, stdout: JSON.stringify({ adversarialMatrix: {
      format: "tr-adversarial-matrix-v1", summary: {},
    } }),
  });
  assert.equal(report.status, "failed");
  assert.deepEqual(report.issues, ["governed-demo-report-unavailable"]);
  assert.deepEqual(report.isolatedReport, isolated);
  assert.equal(report.missingCaseCount, null);
});

test("parity retains a failed governed matrix instead of losing per-case reasons", () => {
  const cases = Array.from({ length: 198 }, (_, index) => ({
    id: `case-${index}`, status: index === 5 ? "failed" : "passed",
    reason: index === 5 ? "assertion-failed" : "passed",
  }));
  const isolatedReport = {
    format: "tr-adversarial-case-report-v1",
    summary: { total: 198, passed: 197, failed: 1 }, cases,
  };
  const report = buildAdversarialParityReport(isolatedReport, {
    status: 1, signal: null, stderr: "case-5 failed",
    stdout: JSON.stringify({ adversarialMatrix: matrixFor(isolatedReport) }),
  }, true);
  assert.equal(report.status, "failed");
  assert.equal(report.missingCaseCount, 0);
  assert.equal(report.governedDemoMatrix.cases[5].status, "failed");
  assert.equal(report.isolatedReport.cases[5].reason, "assertion-failed");
  assert.ok(report.issues.includes("governed-demo-cases-failed"));
});

test("parity keeps the compact success report and rejects a missing isolated case", () => {
  const cases = Array.from({ length: 198 }, (_, index) => ({
    id: `case-${index}`, status: "passed", reason: "passed",
  }));
  const isolatedReport = {
    format: "tr-adversarial-case-report-v1",
    summary: { total: 198, passed: 198, failed: 0 }, cases,
  };
  const demoResult = {
    status: 0, signal: null, stderr: "",
    stdout: JSON.stringify({ adversarialMatrix: matrixFor(isolatedReport) }),
  };
  const passed = buildAdversarialParityReport(isolatedReport, demoResult, true);
  assert.deepEqual(passed, {
    format: "tr-adversarial-parity-v1", demoCaseCount: 198,
    extractedCaseCount: 198, missingCaseCount: 0, missingIds: [],
  });
  const incomplete = buildAdversarialParityReport({
    ...isolatedReport,
    summary: { total: 197, passed: 197, failed: 0 },
    cases: cases.slice(1),
  }, demoResult, true);
  assert.equal(incomplete.status, "failed");
  assert.deepEqual(incomplete.missingIds, ["case-0"]);
  assert.ok(incomplete.issues.includes("governed-demo-case-not-isolated"));
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

test("archive parity rejects summaries that contradict case outcomes", () => {
  const report = parseAdversarialTap("# Subtest: case-a\nok 1 - case-a\n# tests 1\n");
  const matrix = matrixFor(report);
  assert.throws(() => assertAdversarialMatrixParity({ ...report,
    cases: [{ ...report.cases[0], status: "failed", reason: "assertion-failed" }],
  }, matrix), /Isolated adversarial summary contradicts case outcomes/u);
  assert.throws(() => assertAdversarialMatrixParity(report, { ...matrix,
    cases: [{ ...matrix.cases[0], status: "failed" }],
  }), /Governed matrix summary contradicts case outcomes/u);
});
