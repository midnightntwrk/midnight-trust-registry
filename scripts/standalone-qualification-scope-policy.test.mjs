import assert from "node:assert/strict";
import { test } from "node:test";

import {
  assertApiRestartScope,
  assertCurrentQueryScope,
} from "./standalone-qualification-scope-policy.mjs";

const current = {
  releaseQualified: false,
  apiEgressCanaryDenied: true,
  apiDnsCanaryDenied: true,
  actorJourneys: "not-run",
  hostAndBrowserEgress: "not-verified",
  independentFinality: "not-verified",
  planToDeploymentBinding: "not-verified",
};
const restart = {
  releaseQualified: false,
  apiEgressCanaryDenied: true,
  apiDnsCanaryDenied: true,
};

test("accepts only the limited scope actually reported by the probes", () => {
  assert.doesNotThrow(() => assertCurrentQueryScope(current));
  assert.doesNotThrow(() => assertApiRestartScope(restart));
});

test("rejects missing, malformed, or upgraded current-query scope fields", () => {
  for (const report of [null, [], "read-only", ...Object.keys(current).flatMap((key) => {
    const missing = { ...current };
    delete missing[key];
    return [missing, { ...current, [key]: null }, { ...current, [key]: "verified" }];
  })]) {
    assert.throws(() => assertCurrentQueryScope(report), /evidence scope/u);
  }
});

test("rejects missing, malformed, or upgraded API restart scope fields", () => {
  for (const report of [null, [], "restart", ...Object.keys(restart).flatMap((key) => {
    const missing = { ...restart };
    delete missing[key];
    return [missing, { ...restart, [key]: null }, { ...restart, [key]: "verified" }];
  })]) {
    assert.throws(() => assertApiRestartScope(report), /evidence scope/u);
  }
});
