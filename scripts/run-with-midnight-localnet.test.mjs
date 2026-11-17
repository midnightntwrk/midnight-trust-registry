import assert from "node:assert/strict";
import { test } from "node:test";

import { runWithMidnightLocalnet } from "./run-with-midnight-localnet.mjs";

test("runs a shared-stack workload only after successful discovery", async () => {
  const calls = [];
  const result = await runWithMidnightLocalnet(["--", "node", "smoke.mjs"], {
    discover: async () => { calls.push("discover"); },
    run: async (command, args) => { calls.push([command, args]); return 0; },
  });
  assert.equal(result, 0);
  assert.deepEqual(calls, ["discover", ["node", ["smoke.mjs"]]]);
});

test("failed discovery never runs the workload or starts the shared project", async () => {
  let ran = false;
  await assert.rejects(runWithMidnightLocalnet(["node", "smoke.mjs"], {
    discover: async () => { throw new Error("Indexer GraphQL request failed"); },
    run: async () => { ran = true; return 0; },
  }), /Ask the designated owner/u);
  assert.equal(ran, false);
});

test("rejects an absent command before probing the stack", async () => {
  let probed = false;
  await assert.rejects(runWithMidnightLocalnet(["--"], {
    discover: async () => { probed = true; },
  }), /Usage: pnpm localnet:run/u);
  assert.equal(probed, false);
});
