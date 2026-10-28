#!/usr/bin/env node

import { execFile } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { observeStandaloneApiRuntime } from "./check-standalone-api-runtime.mjs";
import { observeStandaloneCurrentQueryJourney } from "./check-standalone-current-query-journey.mjs";
import { assertApiRestartContinuity, assertApiRestartPreflight,
  isResumedApiProcess } from "./standalone-api-restart-policy.mjs";
import { API_RESTART_SCOPE } from "./standalone-qualification-scope-policy.mjs";

const run = promisify(execFile);

async function restartContainer(id) {
  await run("docker", ["restart", id], { timeout: 60_000, maxBuffer: 1024 * 1024 });
}

const delay = (ms) => new Promise((resolveDelay) => setTimeout(resolveDelay, ms));

/** Opt-in API process restart observation; not node recovery or independent finality. */
export async function observeStandaloneApiRestart(setupDirectory, bundle, env = process.env,
  dependencies = {}) {
  const journey = dependencies.journey ?? observeStandaloneCurrentQueryJourney;
  const observe = dependencies.observe ?? observeStandaloneApiRuntime;
  const restart = dependencies.restart ?? restartContainer;
  const wait = dependencies.wait ?? delay;
  const before = await journey(setupDirectory, bundle, env);
  const initial = await observe(bundle, env);
  assertApiRestartPreflight(before, initial);

  await restart(initial.apiContainerId);
  let resumed;
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const candidate = await observe(bundle, env);
      if (isResumedApiProcess(candidate, before, initial)) {
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
  assertApiRestartContinuity(before, after, resumed, finalTopology);
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
    scope: API_RESTART_SCOPE,
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
