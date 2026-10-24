import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { readdirSync } from "node:fs";
import { link, lstat, mkdir, open, realpath, unlink } from "node:fs/promises";
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

export async function archiveAdversarialCaseReport(report, sourceRevision,
  directory = join(root, "artifacts", "adversarial-reports")) {
  assert.match(sourceRevision, /^[0-9a-f]{40}$/u, "Archive needs a Git source revision");
  assert.equal(report?.format, "tr-adversarial-case-report-v1");
  assert.equal(report.summary?.total, report.cases?.length);
  assert.equal(report.summary.passed + report.summary.failed, report.summary.total);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const privateDirectory = await realpath(directory);
  const stat = await lstat(privateDirectory);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Adversarial report archive must be a private directory");
  }
  const path = join(privateDirectory, `cases-${sourceRevision}.json`);
  const temporary = join(privateDirectory, `.cases-${sourceRevision}.${randomUUID()}.tmp`);
  const bytes = Buffer.from(`${JSON.stringify({
    format: "tr-adversarial-case-archive-v1",
    sourceRevision,
    report,
  }, null, 2)}\n`);
  try {
    const file = await open(temporary, "wx", 0o600);
    try {
      await file.writeFile(bytes);
      await file.sync();
    } finally {
      await file.close();
    }
    await link(temporary, path);
    const dir = await open(privateDirectory, "r");
    try {
      await dir.sync();
    } finally {
      await dir.close();
    }
  } finally {
    await unlink(temporary).catch(() => {});
  }
  return { path, sourceRevision, sha256: createHash("sha256").update(bytes).digest("hex"),
    summary: report.summary };
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  if (process.argv.length !== 2 && !(process.argv.length === 3 && process.argv[2] === "--archive")) {
    throw new Error("Usage: node scripts/adversarial-case-report.mjs [--archive]");
  }
  let sourceRevision;
  if (process.argv[2] === "--archive") {
    sourceRevision = execFileSync("git", ["rev-parse", "HEAD"],
      { cwd: root, encoding: "utf8" }).trim();
    const dirty = execFileSync("git", ["status", "--porcelain", "--untracked-files=normal"],
      { cwd: root, encoding: "utf8" }).trim();
    if (dirty !== "") throw new Error("Adversarial archive requires a clean Git checkout");
  }
  const report = runIsolatedAdversarialCases();
  assert.equal(report.summary.total, 198, "Review the expected governed-demo case count before changing it");
  const output = sourceRevision === undefined
    ? report : await archiveAdversarialCaseReport(report, sourceRevision);
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
  if (report.summary.failed > 0) process.exitCode = 1;
}
