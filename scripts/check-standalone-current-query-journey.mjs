#!/usr/bin/env node

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { assessStandaloneJourneyPrerequisites } from "./check-standalone-journey-prerequisites.mjs";
import { observeStandaloneApiEgress } from "./check-standalone-api-egress.mjs";
import { probeStandaloneApiCurrentReads } from "./check-standalone-api-reads.mjs";
import { standaloneSetupStatus } from "./standalone-setup-wizard.mjs";
import { assertCurrentQueryProcessIdentity } from "./standalone-current-query-process-policy.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const BLOCK_HASH = /^0x[0-9a-f]{64}$/u;
const ROLES = ["issuer", "verifier", "auditor", "recognition"];
const AUTHORIZATION_ROLES = ["issuer", "verifier", "auditor"];

function checkedRead(report, status) {
  assertCurrentQueryProcessIdentity(report);
  if (report?.format !== "tr-standalone-api-current-read-probe-v4"
    || report.releaseQualified !== false || report.sourceRevision !== status.sourceRevision
    || report.routeReadback !== "same-container-signed-plan-current-only"
    || !SHA256.test(report.planSha256 ?? "")
    || !SHA256.test(report.installInventorySha256 ?? "")
    || !BLOCK_HASH.test(report.planContractAddress ?? "")
    || /^0x0{64}$/u.test(report.planContractAddress)
    || !BLOCK_HASH.test(report.planExpectedGenesisHash ?? "")
    || /^0x0{64}$/u.test(report.planExpectedGenesisHash)
    || !SHA256.test(report.selectedStateSha256 ?? "")
    || !BLOCK_HASH.test(report.sourceFinalizedBlockHash ?? "")
    || /^0x0{64}$/u.test(report.sourceFinalizedBlockHash)
    || typeof report.registryId !== "string" || report.registryId.length === 0
    || typeof report.currentEpochId !== "string" || report.currentEpochId.length === 0
    || typeof report.apiContainerId !== "string" || report.apiContainerId.length === 0
    || typeof report.networkId !== "string" || report.networkId.length === 0
    || !ROLES.every((role) => Number.isSafeInteger(report.counts?.[role])
      && report.counts[role] > 0
      && Number.isSafeInteger(report.resolvedLookups?.[role])
      && report.resolvedLookups[role] > 0
      && report.resolvedLookups[role] <= report.counts[role])
    || !AUTHORIZATION_ROLES.every((role) => Number.isSafeInteger(report.ambiguousLookups?.[role])
      && report.ambiguousLookups[role] >= 0
      && report.ambiguousLookups[role] <= report.counts[role])) {
    throw new Error("Live current-query readback is incomplete or has no resolved actor role");
  }
  if (report.planContractAddress !== status.deployedContractAddress
    || report.planExpectedGenesisHash !== status.approvedGenesisHash
    || report.networkId !== status.stackNetworkId
    || report.installInventorySha256 !== status.installInventorySha256) {
    throw new Error("Live signed API runtime differs from the approved wizard install, deployment, genesis, or network");
  }
  return report;
}

function checkedEgress(report, first) {
  if (report?.kind !== "standalone-api-egress-observation"
    || report.releaseQualified !== false
    || report.sourceRevision !== first.sourceRevision
    || report.apiContainerId !== first.apiContainerId
    || report.networkId !== first.networkId
    || report.bridgePositiveControlReachable !== true
    || report.bridgeDnsCanaryReachable !== true
    || report.apiCanaryConnectionDenied !== true
    || report.apiBridgeDnsRouteDenied !== true
    || report.apiRoutesConfinedToLedgerSubnet !== true) {
    throw new Error("Live API egress probe did not preserve the pinned runtime identity and denial");
  }
  return report;
}

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
  const first = checkedRead(await read(bundle, env), status);
  const denial = checkedEgress(await egress(bundle, env), first);
  const second = checkedRead(await read(bundle, env), status);
  if (second.apiContainerId !== first.apiContainerId
    || second.apiStartedAt !== first.apiStartedAt
    || second.apiRestartCount !== first.apiRestartCount
    || second.networkId !== first.networkId
    || second.installInventorySha256 !== first.installInventorySha256
    || second.planSha256 !== first.planSha256
    || second.planContractAddress !== first.planContractAddress
    || second.planExpectedGenesisHash !== first.planExpectedGenesisHash
    || second.selectedStateSha256 !== first.selectedStateSha256
    || second.registryId !== first.registryId
    || second.currentEpochId !== first.currentEpochId
    || ROLES.some((role) => second.counts[role] !== first.counts[role]
      || second.resolvedLookups[role] !== first.resolvedLookups[role])
    || AUTHORIZATION_ROLES.some((role) =>
      second.ambiguousLookups[role] !== first.ambiguousLookups[role])) {
    throw new Error("Current-query install, deployment, signed plan, or selected actor reads changed during egress probe");
  }
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
    scope: "Live signed-plan current-only API role and recognition queries with API-container TCP/DNS canary denial; not a governed mutation or complete actor journey",
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
    console.error(`Standalone current-query journey inconclusive: ${error.message}`);
    process.exitCode = 1;
  }
}
