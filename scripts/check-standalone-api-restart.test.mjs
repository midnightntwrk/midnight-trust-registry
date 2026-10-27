import assert from "node:assert/strict";
import { test } from "node:test";

import { observeStandaloneApiRestart } from "./check-standalone-api-restart.mjs";

const initial = {
  kind: "standalone-api-runtime-topology-observation",
  releaseQualified: false,
  apiContainerId: "a".repeat(64),
  networkId: "network-1",
  sourceRevision: "b".repeat(40),
  installInventorySha256: "9".repeat(64),
  apiStartedAt: "2026-01-01T00:00:00.000Z",
  apiRestartCount: 0,
};
const resumed = { ...initial, apiStartedAt: "2026-01-01T00:01:00.000Z", apiRestartCount: 1 };
const journey = {
  format: "tr-standalone-current-query-journey-v2",
  releaseQualified: false,
  apiContainerId: initial.apiContainerId,
  networkId: initial.networkId,
  sourceRevision: initial.sourceRevision,
  installInventorySha256: initial.installInventorySha256,
  planSha256: "c".repeat(64),
  selectedStateSha256: "d".repeat(64),
  registryId: "registry-1",
  currentEpochId: "epoch-1",
  finalizedCheckpoints: [`0x${"e".repeat(64)}`, `0x${"e".repeat(64)}`],
  apiEgressCanaryDenied: true,
  apiDnsCanaryDenied: true,
};

function dependencies(overrides = {}) {
  let observations = 0;
  return {
    journey: async () => journey,
    observe: async () => { observations += 1; return observations === 1 ? initial : resumed; },
    restart: async () => {},
    wait: async () => {},
    ...overrides,
  };
}

test("checks signed-plan current reads and egress before and after the same API container restarts", async () => {
  let restarts = 0;
  const result = await observeStandaloneApiRestart("/setup", "/bundle", {},
    dependencies({ restart: async (id) => { assert.equal(id, initial.apiContainerId); restarts += 1; } }));
  assert.equal(restarts, 1);
  assert.equal(result.format, "tr-standalone-api-restart-observation-v1");
  assert.equal(result.selectedStateSha256, journey.selectedStateSha256);
  assert.equal(result.installInventorySha256, journey.installInventorySha256);
  assert.equal(result.afterRestartCount, 1);
  assert.equal(result.releaseQualified, false);
});

test("refuses to restart when the first journey and runtime identity differ", async () => {
  let restarted = false;
  await assert.rejects(observeStandaloneApiRestart("/setup", "/bundle", {}, dependencies({
    journey: async () => ({ ...journey, apiContainerId: "f".repeat(64) }),
    restart: async () => { restarted = true; },
  })), /do not match/u);
  assert.equal(restarted, false);
  await assert.rejects(observeStandaloneApiRestart("/setup", "/bundle", {}, dependencies({
    journey: async () => ({ ...journey, installInventorySha256: undefined }),
    restart: async () => { restarted = true; },
  })), /do not match/u);
  assert.equal(restarted, false);
});

test("refuses to restart when the preflight did not prove API egress denial", async () => {
  let restarted = false;
  await assert.rejects(observeStandaloneApiRestart("/setup", "/bundle", {}, dependencies({
    journey: async () => ({ ...journey, apiDnsCanaryDenied: false }),
    restart: async () => { restarted = true; },
  })), /do not match/u);
  assert.equal(restarted, false);
});

test("rejects restart without new process identity or with a second unexpected restart", async () => {
  for (const state of [initial, { ...resumed, apiRestartCount: 2 }]) {
    await assert.rejects(observeStandaloneApiRestart("/setup", "/bundle", {}, dependencies({
      observe: async () => state,
    })), /did not return healthy/u);
  }
});

test("rejects selected-state or signed-plan drift after restart", async () => {
  for (const change of [{ selectedStateSha256: "f".repeat(64) },
    { planSha256: "f".repeat(64) }, { installInventorySha256: "f".repeat(64) },
    { apiContainerId: "f".repeat(64) },
    { apiEgressCanaryDenied: false }]) {
    let reads = 0;
    await assert.rejects(observeStandaloneApiRestart("/setup", "/bundle", {}, dependencies({
      journey: async () => { reads += 1; return reads === 1 ? journey : { ...journey, ...change }; },
    })), /changed across restart/u);
  }
});

test("fails closed when the API cannot be observed after its post-restart journey", async () => {
  let observations = 0;
  await assert.rejects(observeStandaloneApiRestart("/setup", "/bundle", {}, dependencies({
    observe: async () => {
      observations += 1;
      if (observations === 3) throw new Error("post-restart topology unavailable");
      return observations === 1 ? initial : resumed;
    },
  })), /post-restart topology unavailable/u);
});
