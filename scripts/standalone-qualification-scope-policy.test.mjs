import assert from "node:assert/strict";
import { test } from "node:test";

import {
  assertApiRestartScope,
  assertCurrentQueryScope,
} from "./standalone-qualification-scope-policy.mjs";

const current = {
  format: "tr-standalone-current-query-journey-v2",
  sourceRevision: "a".repeat(40),
  apiContainerId: "b".repeat(64),
  networkId: "c".repeat(64),
  installInventorySha256: "d".repeat(64),
  planSha256: "e".repeat(64),
  selectedStateSha256: "f".repeat(64),
  planContractAddress: `0x${"1".repeat(64)}`,
  planExpectedGenesisHash: `0x${"2".repeat(64)}`,
  registryId: "test-registry",
  currentEpochId: "test-epoch",
  finalizedCheckpoints: [`0x${"3".repeat(64)}`, `0x${"4".repeat(64)}`],
  releaseQualified: false,
  apiEgressCanaryDenied: true,
  apiDnsCanaryDenied: true,
  actorJourneys: "not-run",
  hostAndBrowserEgress: "not-verified",
  independentFinality: "not-verified",
  planToDeploymentBinding: "not-verified",
  counts: { issuer: 1, verifier: 1, auditor: 1, recognition: 1 },
  resolvedLookups: { issuer: 1, verifier: 1, auditor: 1, recognition: 1 },
  ambiguousLookups: { issuer: 0, verifier: 0, auditor: 0 },
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
    return [missing, { ...current, [key]: null },
      ...(["registryId", "currentEpochId"].includes(key)
        ? [] : [{ ...current, [key]: "verified" }])];
  })]) {
    assert.throws(() => assertCurrentQueryScope(report), /evidence scope/u);
  }
});

test("rejects malformed finality checkpoints and incomplete runtime identity", () => {
  for (const mutation of [
    { finalizedCheckpoints: [] },
    { finalizedCheckpoints: [current.finalizedCheckpoints[0]] },
    { finalizedCheckpoints: [current.finalizedCheckpoints[0], "not-a-block"] },
    { finalizedCheckpoints: [current.finalizedCheckpoints[0], `0x${"0".repeat(64)}`] },
    { apiContainerId: "short" },
    { planSha256: "short" },
    { planContractAddress: `0x${"0".repeat(64)}` },
    { planExpectedGenesisHash: `0x${"0".repeat(64)}` },
    { currentEpochId: "" },
  ]) {
    assert.throws(() => assertCurrentQueryScope({ ...current, ...mutation }), /evidence scope/u);
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
