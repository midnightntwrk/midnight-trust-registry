import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { parseAdversarialTap, runIsolatedAdversarialCases } from "./adversarial-case-report.mjs";

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
