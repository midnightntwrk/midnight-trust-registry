import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runIsolatedAdversarialCases } from "./adversarial-case-report.mjs";

const scripts = dirname(fileURLToPath(import.meta.url));
const root = dirname(scripts);
const run = (args) => {
  const result = spawnSync(process.execPath, args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 300_000,
  });
  if (result.error || result.status !== 0) {
    const detail = result.error?.message || result.stderr?.slice(-4000)
      || result.stdout?.slice(-4000) || String(result.status);
    throw new Error(`Adversarial parity input failed: ${detail}`);
  }
  return result.stdout;
};

const report = JSON.parse(run([join(scripts, "demo-governed-registry.mjs")])).adversarialMatrix;
assert.equal(report.format, "tr-adversarial-matrix-v1");
assert.equal(report.summary.total, 198, "Review the expected governed-demo case count before changing it");
assert.equal(report.summary.failed, 0);
const demoIds = report.cases.map(({ id }) => id);
assert.equal(new Set(demoIds).size, demoIds.length, "Governed demo has duplicate case IDs");

const isolatedReport = runIsolatedAdversarialCases();
assert.equal(isolatedReport.summary.failed, 0, "Isolated adversarial tests failed");
const extractedIds = isolatedReport.cases.map(({ id }) => id);
assert.ok(extractedIds.length > 0, "No named isolated adversarial tests were reported");
assert.equal(new Set(extractedIds).size, extractedIds.length, "Isolated tests have duplicate case IDs");
const extracted = new Set(extractedIds);
const demo = new Set(demoIds);
const unknownIds = extractedIds.filter((id) => !demo.has(id));
assert.deepEqual(unknownIds, [], "Isolated test IDs must match governed-demo case IDs");
const missingIds = demoIds.filter((id) => !extracted.has(id));

process.stdout.write(`${JSON.stringify({
  format: "tr-adversarial-parity-v1",
  demoCaseCount: demoIds.length,
  extractedCaseCount: extractedIds.length,
  missingCaseCount: missingIds.length,
  missingIds,
}, null, 2)}\n`);
if (process.argv.includes("--require-full")) {
  assert.deepEqual(missingIds, [], "Not every governed-demo case has an isolated test");
}
