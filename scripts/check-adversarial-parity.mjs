import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scripts = dirname(fileURLToPath(import.meta.url));
const root = dirname(scripts);
const testFiles = readdirSync(scripts)
  .filter((name) => /^adversarial-.*\.test\.mjs$/u.test(name) && name !== "adversarial-matrix.test.mjs")
  .map((name) => join(scripts, name));
assert.ok(testFiles.length > 0, "No isolated adversarial test files found");

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
assert.equal(report.summary.total, 180, "Review the expected governed-demo case count before changing it");
assert.equal(report.summary.failed, 0);
const demoIds = report.cases.map(({ id }) => id);
assert.equal(new Set(demoIds).size, demoIds.length, "Governed demo has duplicate case IDs");

const tap = run(["--test", "--test-reporter=tap", ...testFiles]);
const extractedIds = [...tap.matchAll(/^# Subtest: ([a-z][a-z0-9-]+)$/gmu)].map((match) => match[1]);
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
