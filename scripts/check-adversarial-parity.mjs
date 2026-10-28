import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runIsolatedAdversarialCases } from "./adversarial-case-report.mjs";

const scripts = dirname(fileURLToPath(import.meta.url));
const root = dirname(scripts);

function hasConsistentCaseCounts(report) {
  const cases = report?.cases;
  const summary = report?.summary;
  if (!Array.isArray(cases) || !Number.isSafeInteger(summary?.total)
    || !Number.isSafeInteger(summary?.passed) || !Number.isSafeInteger(summary?.failed)
    || summary.total !== cases.length || summary.passed < 0 || summary.failed < 0) {
    return false;
  }
  const failed = cases.filter((entry) => entry?.status === "failed").length;
  return cases.every((entry) => entry?.status === "passed" || entry?.status === "failed")
    && summary.failed === failed && summary.passed === cases.length - failed;
}

export function buildAdversarialParityReport(isolatedReport, demoResult, requireFull = false) {
  if (isolatedReport?.format !== "tr-adversarial-case-report-v1"
    || !hasConsistentCaseCounts(isolatedReport)
    || isolatedReport.cases.length === 0) {
    throw new Error("Isolated adversarial case report is invalid");
  }
  const issues = [];
  if (isolatedReport.summary.failed !== 0) issues.push("isolated-cases-failed");
  if (demoResult.error || demoResult.signal || demoResult.status !== 0) {
    issues.push("governed-demo-process-failed");
  }
  let matrix;
  try {
    matrix = JSON.parse(demoResult.stdout).adversarialMatrix;
    if (matrix?.format !== "tr-adversarial-matrix-v1"
      || !hasConsistentCaseCounts(matrix)) {
      throw new Error("Governed demo matrix is invalid");
    }
  } catch {
    matrix = undefined;
    issues.push("governed-demo-report-unavailable");
  }
  const isolatedIds = isolatedReport.cases.map(({ id }) => id);
  const demoIds = matrix?.cases.map(({ id }) => id) ?? [];
  const demo = new Set(demoIds);
  const extracted = new Set(isolatedIds);
  if (demoIds.length !== demo.size) issues.push("duplicate-governed-demo-case-id");
  if (isolatedIds.length !== extracted.size) issues.push("duplicate-isolated-case-id");
  if (matrix && matrix.summary.total !== 198) issues.push("governed-demo-case-count-changed");
  if (matrix && matrix.summary.failed !== 0) issues.push("governed-demo-cases-failed");
  const unknownIds = matrix ? isolatedIds.filter((id) => !demo.has(id)) : null;
  const missingIds = matrix ? demoIds.filter((id) => !extracted.has(id)) : null;
  if (unknownIds?.length) issues.push("isolated-case-id-not-in-demo");
  if (requireFull && missingIds?.length) issues.push("governed-demo-case-not-isolated");
  const result = {
    format: "tr-adversarial-parity-v1",
    demoCaseCount: matrix?.cases.length ?? null,
    extractedCaseCount: isolatedIds.length,
    missingCaseCount: missingIds?.length ?? null,
    missingIds,
  };
  if (issues.length > 0) {
    return { ...result, status: "failed", issues, unknownIds,
      isolatedReport, ...(matrix ? { governedDemoMatrix: matrix } : {}),
      ...(demoResult.error || demoResult.signal || demoResult.status !== 0 ? {
        demoFailure: {
          exitCode: demoResult.status,
          signal: demoResult.signal,
          reason: String(demoResult.error?.message ?? demoResult.stderr ?? "").slice(-1000),
        },
      } : {}) };
  }
  return result;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  // Run independent cases first so a broken sequential demo cannot suppress their outcomes.
  const isolatedReport = runIsolatedAdversarialCases();
  const demoResult = spawnSync(process.execPath, [join(scripts, "demo-governed-registry.mjs")], {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 300_000,
  });
  const report = buildAdversarialParityReport(
    isolatedReport, demoResult, process.argv.includes("--require-full"),
  );
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (report.status === "failed") process.exitCode = 1;
}
