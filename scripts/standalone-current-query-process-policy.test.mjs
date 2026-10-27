import assert from "node:assert/strict";
import { test } from "node:test";

import { assertCurrentQueryProcessIdentity } from "./standalone-current-query-process-policy.mjs";

const identity = {
  apiContainerId: "a".repeat(64),
  apiStartedAt: "2026-01-01T00:00:00Z",
  apiRestartCount: 0,
};

test("requires an identified API process before comparing two current reads", () => {
  assert.doesNotThrow(() => assertCurrentQueryProcessIdentity(identity));
  for (const bad of [null, [], {},
    { ...identity, apiContainerId: "not-a-container" },
    { ...identity, apiStartedAt: "not-a-date" },
    { ...identity, apiRestartCount: -1 },
    { ...identity, apiRestartCount: 0.5 },
    ...Object.keys(identity).map((key) => {
      const missing = { ...identity };
      delete missing[key];
      return missing;
    })]) {
    assert.throws(() => assertCurrentQueryProcessIdentity(bad), /process identity is incomplete/u);
  }
});
