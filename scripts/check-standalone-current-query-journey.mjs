#!/usr/bin/env node

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assessStandaloneJourneyPrerequisites } from "./check-standalone-journey-prerequisites.mjs";
import { observeStandaloneApiEgress } from "./check-standalone-api-egress.mjs";
import { probeStandaloneApiCurrentReads } from "./check-standalone-api-reads.mjs";
import { standaloneSetupStatus } from "./standalone-setup-wizard.mjs";
import { assertStableCurrentReads, checkedCurrentRead, checkedCurrentQueryEgress } from "./standalone-current-query-report-policy.mjs";
import { CURRENT_QUERY_SCOPE } from "./standalone-qualification-scope-policy.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;

/** A real-runtime current-query slice, never a governed-write or release verdict. */
export async function observeStandaloneCurrentQueryJourney(setupDirectory, bundle, env = process.env,
  dependencies = {}) {
  const status = await (dependencies.setupStatus ?? standaloneSetupStatus)(setupDirectory);
  const prerequisites = assessStandaloneJourneyPrerequisites(status);
  if (!prerequisites.ledgerPrerequisitesObserved) {
    throw new Error(`Standalone ledger prerequisites missing: ${prerequisites.missing.join(", ")}`);
  }
  if (typeof status.stackProject !== "string" || status.stackProject.length === 0
    || status.stackProject !== env.TR_STACK_NAME
    || !SHA256.test(status.stackNetworkId ?? "")
    || !SHA256.test(status.installInventorySha256 ?? "")) {
    throw new Error("Approved wizard install, project, or network differs from the selected API runtime");
  }

  const read = dependencies.read ?? probeStandaloneApiCurrentReads;
  const egress = dependencies.egress ?? observeStandaloneApiEgress;
  const first = checkedCurrentRead(await read(bundle, env), status);
  checkedCurrentQueryEgress(await egress(bundle, env), first);
  const second = checkedCurrentRead(await read(bundle, env), status);
  assertStableCurrentReads(first, second);
  return {
    format: "tr-standalone-current-query-journey-v2",
    sourceRevision: status.sourceRevision,
    apiContainerId: first.apiContainerId,
    networkId: first.networkId,
    installInventorySha256: first.installInventorySha256,
    planSha256: first.planSha256,
    planContractAddress: first.planContractAddress,
    planExpectedGenesisHash: first.planExpectedGenesisHash,
    selectedStateSha256: first.selectedStateSha256,
    registryId: first.registryId,
    currentEpochId: first.currentEpochId,
    finalizedCheckpoints: [first.sourceFinalizedBlockHash, second.sourceFinalizedBlockHash],
    counts: first.counts,
    resolvedLookups: first.resolvedLookups,
    ambiguousLookups: first.ambiguousLookups,
    apiEgressCanaryDenied: true,
    apiDnsCanaryDenied: true,
    scope: CURRENT_QUERY_SCOPE,
    actorJourneys: "not-run",
    hostAndBrowserEgress: "not-verified",
    independentFinality: "not-verified",
    planToDeploymentBinding: "not-verified",
    releaseQualified: false,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4) {
      throw new Error("Usage: check-standalone-current-query-journey.mjs <private-setup-dir> <verified-install-bundle>");
    }
    console.log(JSON.stringify(await observeStandaloneCurrentQueryJourney(
      process.argv[2], process.argv[3]), null, 2));
  } catch (error) {
    console.error(`Standalone current-query journey inconclusive: ${error instanceof Error ? error.message : "unknown error"}`);
    process.exitCode = 1;
  }
}
