#!/usr/bin/env node

import { resolve } from "node:path";
import console from "node:console";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { assessStandaloneJourneyPrerequisites } from "./check-standalone-journey-prerequisites.mjs";
import { observeStandaloneCurrentQueryJourney } from "./check-standalone-current-query-journey.mjs";
import { observeStandaloneApiRestart } from "./check-standalone-api-restart.mjs";
import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { standaloneSetupStatus } from "./standalone-setup-wizard.mjs";

const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

/** Runs only the existing read-only probes after checking the exact-source install. */
export async function observeStandaloneQualification(setupDirectory, bundle, sourceRevision,
  { apiRestart = false, env = process.env } = {}, dependencies = {}) {
  if (!SHA.test(sourceRevision ?? "")) {
    throw new Error("Candidate source revision must be a full lowercase commit SHA");
  }
  const verifyBundle = dependencies.verifyBundle ?? verifyStandaloneInstallBundle;
  const setupStatus = dependencies.setupStatus ?? standaloneSetupStatus;
  const install = await verifyBundle(bundle);
  if (install.sourceRevision !== sourceRevision || !SHA256.test(install.inventorySha256 ?? "")) {
    throw new Error("Install bundle source does not match the selected candidate");
  }
  const status = await setupStatus(setupDirectory);
  if (status.installInventorySha256 !== install.inventorySha256) {
    throw new Error("Setup install inventory differs from the verified candidate bundle");
  }
  const prerequisites = assessStandaloneJourneyPrerequisites(status, sourceRevision);
  const report = {
    format: "tr-standalone-qualification-observation-v1",
    sourceRevision,
    inventorySha256: install.inventorySha256,
    prerequisites,
    currentQuery: "not-run",
    apiRestart: "not-run",
    governedActorJourneys: "not-run",
    independentFinality: "not-verified",
    fullEgressDenial: "not-verified",
    deployedRecovery: "not-run",
    independentSecurityReview: "not-verified",
    releaseQualified: false,
  };
  if (!prerequisites.ledgerPrerequisitesObserved) return report;
  if (typeof env.TR_STACK_NAME !== "string" || status.stackProject !== env.TR_STACK_NAME
    || !SHA256.test(status.stackNetworkId ?? "")
    || !/^0x[0-9a-f]{64}$/u.test(status.approvedGenesisHash ?? "")
    || !/^0x[0-9a-f]{64}$/u.test(status.deployedContractAddress ?? "")) {
    throw new Error("Approved setup project, network, genesis, or deployment identity is incomplete");
  }

  const query = dependencies.query ?? observeStandaloneCurrentQueryJourney;
  report.currentQuery = await query(setupDirectory, bundle, env);
  if (report.currentQuery?.format !== "tr-standalone-current-query-journey-v2"
    || report.currentQuery.sourceRevision !== sourceRevision
    || report.currentQuery.installInventorySha256 !== install.inventorySha256
    || report.currentQuery.networkId !== status.stackNetworkId
    || report.currentQuery.planContractAddress !== status.deployedContractAddress
    || report.currentQuery.planExpectedGenesisHash !== status.approvedGenesisHash
    || report.currentQuery.releaseQualified !== false) {
    throw new Error("Current-query observer disagrees with the approved setup deployment");
  }
  if (apiRestart) {
    const restart = dependencies.restart ?? observeStandaloneApiRestart;
    report.apiRestart = await restart(setupDirectory, bundle, env);
    if (report.apiRestart?.format !== "tr-standalone-api-restart-observation-v1"
      || report.apiRestart.sourceRevision !== sourceRevision
      || report.apiRestart.installInventorySha256 !== install.inventorySha256
      || report.apiRestart.apiContainerId !== report.currentQuery.apiContainerId
      || report.apiRestart.networkId !== report.currentQuery.networkId
      || report.apiRestart.planSha256 !== report.currentQuery.planSha256
      || report.apiRestart.selectedStateSha256 !== report.currentQuery.selectedStateSha256
      || report.apiRestart.releaseQualified !== false) {
      throw new Error("API restart observer returned an incompatible result");
    }
  }
  return report;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [, , setup, bundle, sourceRevision, flag] = process.argv;
    if (process.argv.length < 5 || process.argv.length > 6
      || (flag !== undefined && flag !== "--api-restart")) {
      throw new Error("Usage: observe-standalone-qualification.mjs <private-setup-dir> <verified-install-bundle> <candidate-source-sha> [--api-restart]");
    }
    const report = await observeStandaloneQualification(setup, bundle, sourceRevision,
      { apiRestart: flag === "--api-restart" });
    console.log(JSON.stringify(report, null, 2));
    process.exitCode = report.prerequisites.ledgerPrerequisitesObserved ? 0 : 2;
  } catch (error) {
    console.error(`Standalone qualification observation failed: ${error.message}`);
    process.exitCode = 1;
  }
}
