import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const scripts = dirname(fileURLToPath(import.meta.url));
const root = dirname(scripts);

export const isolatedAdversarialTestFiles = () => readdirSync(scripts)
  .filter((name) => /^adversarial-.*\.test\.mjs$/u.test(name)
    && name !== "adversarial-matrix.test.mjs"
    && name !== "adversarial-case-report.test.mjs")
  .map((name) => join(scripts, name));

export const parseAdversarialTap = (tap) => {
  const cases = [];
  const seen = new Set();
  for (const block of tap.split(/^# Subtest: /mu).slice(1)) {
    const id = block.slice(0, block.indexOf("\n"));
    assert.match(id, /^[a-z][a-z0-9-]+$/u, "Isolated adversarial test needs a stable case ID");
    assert.equal(seen.has(id), false, `Duplicate isolated adversarial case: ${id}`);
    seen.add(id);
    const outcome = block.match(/^((?:not )?ok) \d+ - ([a-z][a-z0-9-]+)(?: # (SKIP|TODO).*)?$/mu);
    const status = outcome?.[1] === "ok" && outcome[3] === undefined ? "passed" : "failed";
    const failureType = block.match(/^\s+failureType: '([^']+)'$/mu)?.[1];
    cases.push({
      id,
      status,
      reason: status === "passed" ? "passed"
        : outcome?.[3] === "SKIP" || outcome?.[3] === "TODO" ? "skipped-or-todo"
          : failureType === "testCodeFailure" ? "assertion-failed"
            : failureType === "cancelledByParent" ? "cancelled"
              : outcome === null ? "missing-outcome" : "test-failed",
    });
  }
  cases.sort((left, right) => left.id.localeCompare(right.id, "en"));
  const count = Number(tap.match(/^# tests (\d+)$/mu)?.[1]);
  assert.ok(Number.isSafeInteger(count),
    `Isolated test runner did not provide a test count: ${tap.slice(-300)}`);
  assert.equal(cases.length, count, "Isolated case outcomes do not cover every test");
  const failed = cases.filter((entry) => entry.status === "failed").length;
  return {
    format: "tr-adversarial-case-report-v1",
    summary: { total: cases.length, passed: cases.length - failed, failed },
    cases,
  };
};

export const runIsolatedAdversarialCases = (files = isolatedAdversarialTestFiles()) => {
  assert.ok(files.length > 0, "No isolated adversarial test files found");
  const result = spawnSync(process.execPath, ["--test", "--test-reporter=tap", ...files], {
    cwd: root,
    env: { ...process.env, NODE_TEST_CONTEXT: undefined },
    encoding: "utf8",
    maxBuffer: 16 * 1024 * 1024,
    timeout: 600_000,
  });
  if (result.error) throw result.error;
  if (!result.stdout) throw new Error(`Isolated test runner produced no TAP: ${result.stderr?.slice(-500)}`);
  const report = parseAdversarialTap(result.stdout);
  if ((result.status === 0) !== (report.summary.failed === 0)) {
    throw new Error(`Isolated test exit status disagrees with per-case outcomes: ${result.status}`);
  }
  return report;
};

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.length !== 2) throw new Error("Usage: node scripts/adversarial-case-report.mjs");
  const report = runIsolatedAdversarialCases();
  assert.equal(report.summary.total, 196, "Review the expected governed-demo case count before changing it");
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  if (report.summary.failed > 0) process.exitCode = 1;
}
