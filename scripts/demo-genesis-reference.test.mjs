import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { test } from "node:test";

import { demoGenesisReference } from "./demo-genesis-reference.mjs";

test("demo references are deterministic, distinct, and cannot be mistaken for approvals", () => {
  const standalone = demoGenesisReference("standalone");
  const preview = demoGenesisReference("preview");
  assert.deepEqual(standalone, demoGenesisReference("standalone"));
  assert.notEqual(standalone.fixtureSha256, preview.fixtureSha256);
  for (const result of [standalone, preview]) {
    assert.match(result.exampleReference, /^demo:chain-spec:(?:standalone|preview):sha256:[a-f0-9]{64}$/u);
    assert.equal(result.usableForWizardApproval, false);
    assert.equal(result.releaseQualified, false);
    assert.equal("expectedGenesisHash" in result, false);
    assert.equal("reviewerFingerprint" in result, false);
    assert.equal("approvedAt" in result, false);
  }
  assert.throws(() => demoGenesisReference("preprod"), /standalone\|preview/u);
});

test("CLI emits only the requested synthetic environment", () => {
  const result = JSON.parse(execFileSync(process.execPath,
    ["scripts/demo-genesis-reference.mjs", "preview"], { encoding: "utf8" }));
  assert.deepEqual(result, demoGenesisReference("preview"));
});
