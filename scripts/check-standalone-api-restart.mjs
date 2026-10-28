#!/usr/bin/env node

import { execFile } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { observeStandaloneApiRuntime } from "./check-standalone-api-runtime.mjs";
import { observeStandaloneCurrentQueryJourney } from "./check-standalone-current-query-journey.mjs";

const run = promisify(execFile);
const CONTAINER_ID = /^[0-9a-f]{64}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

async function restartContainer(id) {
  await run("docker", ["restart", id], { timeout: 60_000, maxBuffer: 1024 * 1024 });
}

const delay = (ms) => new Promise((resolveDelay) => setTimeout(resolveDelay, ms));

function matchingTopology(topology, journey) {
  return topology?.kind === "standalone-api-runtime-topology-observation"
    && topology.releaseQualified === false
    && topology.apiContainerId === journey.apiContainerId
    && topology.networkId === journey.networkId
    && topology.sourceRevision === journey.sourceRevision
    && SHA256.test(topology.installInventorySha256 ?? "")
    && topology.installInventorySha256 === journey.installInventorySha256
    && CONTAINER_ID.test(topology.apiContainerId ?? "")
    && typeof topology.apiStartedAt === "string"
    && Number.isFinite(Date.parse(topology.apiStartedAt))
    && Number.isSafeInteger(topology.apiRestartCount)
    && topology.apiRestartCount >= 0;
}

function sameProcess(left, right) {
  return left.apiContainerId === right.apiContainerId
    && left.networkId === right.networkId
    && left.sourceRevision === right.sourceRevision
    && left.installInventorySha256 === right.installInventorySha256
    && left.apiStartedAt === right.apiStartedAt
    && left.apiRestartCount === right.apiRestartCount;
}

/** Opt-in API process restart observation; not node recovery or independent finality. */
export async function observeStandaloneApiRestart(setupDirectory, bundle, env = process.env,
  dependencies = {}) {
  const journey = dependencies.journey ?? observeStandaloneCurrentQueryJourney;
  const observe = dependencies.observe ?? observeStandaloneApiRuntime;
  const restart = dependencies.restart ?? restartContainer;
  const wait = dependencies.wait ?? delay;
  const before = await journey(setupDirectory, bundle, env);
  const initial = await observe(bundle, env);
  if (before?.format !== "tr-standalone-current-query-journey-v2"
    || before.releaseQualified !== false || before.apiEgressCanaryDenied !== true
    || before.apiDnsCanaryDenied !== true || !matchingTopology(initial, before)) {
    throw new Error("Approved current-query journey and running API container do not match");
  }

  await restart(initial.apiContainerId);
  let resumed;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const candidate = await observe(bundle, env);
      if (matchingTopology(candidate, before) && candidate.apiContainerId === initial.apiContainerId
        && candidate.apiRestartCount === initial.apiRestartCount + 1
        && candidate.apiStartedAt !== initial.apiStartedAt) {
        resumed = candidate;
        break;
      }
    } catch {
      // The health observer may fail while the same container starts.
    }
    if (attempt < 29) await wait(2_000);
  }
  if (resumed === undefined) {
    throw new Error("Approved API container did not return healthy after exactly one restart");
  }
  const after = await journey(setupDirectory, bundle, env);
  const finalTopology = await observe(bundle, env);
  if (after?.format !== before.format || after.releaseQualified !== false
    || after.apiEgressCanaryDenied !== true || after.apiDnsCanaryDenied !== true
    || !matchingTopology(finalTopology, after) || !sameProcess(resumed, finalTopology)
    || before.sourceRevision !== after.sourceRevision
    || before.apiContainerId !== after.apiContainerId
    || before.networkId !== after.networkId
    || before.installInventorySha256 !== after.installInventorySha256
    || before.planSha256 !== after.planSha256
    || before.selectedStateSha256 !== after.selectedStateSha256
    || before.registryId !== after.registryId
    || before.currentEpochId !== after.currentEpochId) {
    throw new Error("API signed plan, selected state, or container changed across restart");
  }
  return {
    format: "tr-standalone-api-restart-observation-v1",
    sourceRevision: before.sourceRevision,
    apiContainerId: before.apiContainerId,
    networkId: before.networkId,
    installInventorySha256: before.installInventorySha256,
    planSha256: before.planSha256,
    selectedStateSha256: before.selectedStateSha256,
    beforeStartedAt: initial.apiStartedAt,
    afterStartedAt: resumed.apiStartedAt,
    beforeRestartCount: initial.apiRestartCount,
    afterRestartCount: resumed.apiRestartCount,
    finalizedCheckpoints: [...before.finalizedCheckpoints, ...after.finalizedCheckpoints],
    apiEgressCanaryDenied: true,
    apiDnsCanaryDenied: true,
    scope: "Same pinned API container and selected current state survived one restart with API-container egress denial; not node, wallet, browser, backup/restore, governed-write, or independently authenticated finality evidence",
    releaseQualified: false,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4) {
      throw new Error("Usage: check-standalone-api-restart.mjs <private-setup-dir> <verified-install-bundle>");
    }
    console.log(JSON.stringify(await observeStandaloneApiRestart(process.argv[2], process.argv[3]), null, 2));
  } catch (error) {
    console.error(`Standalone API restart observation inconclusive: ${error instanceof Error ? error.message : "unknown error"}`);
    process.exitCode = 1;
  }
}
