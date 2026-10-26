#!/usr/bin/env node

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { standaloneSetupStatus } from "./standalone-setup-wizard.mjs";

const SHA = /^[0-9a-f]{40}$/u;

/** Only checks wizard-recorded prerequisites, not an actor run or independent finality. */
export function assessStandaloneJourneyPrerequisites(status) {
  if (!status || typeof status !== "object" || !SHA.test(status.sourceRevision ?? "")
    || !Array.isArray(status.stagedVerifierKeys) || status.releaseQualified !== false) {
    throw new Error("Invalid standalone wizard status; inspect the private setup record");
  }
  const gates = {
    setupUnlocked: status.setupLock === "absent",
    installStaged: status.install === "verified-staged-bytes-only",
    stackObserved: status.stackConfiguration === "observed-ledger-bridge-only",
    genesisApproved: status.localLedger === "operator-pinned-reviewer-signature-verified",
    deploymentObserved: status.deployment === "observed",
    recordedKeyInsertionsReconciled: status.stagedVerifierKeys.length > 0
      && status.stagedVerifierKeys.every((entry) => entry?.state === "verified"),
    committeeApproved: status.maintenanceApproval
      === "deployment-bound-roster-signature-verified-transition-pending",
    maintenanceObserved: status.maintenanceTransition === "observed"
      && status.maintenanceLastReadback === "observed"
      && status.maintenanceTransitionAlert === null,
  };
  const missing = Object.entries(gates).filter(([, passed]) => !passed).map(([name]) => name);
  return {
    format: "tr-standalone-journey-prerequisites-v1",
    sourceRevision: status.sourceRevision,
    gates,
    missing,
    ledgerPrerequisitesObserved: missing.length === 0,
    completeVerifierKeyInventory: "not-verified",
    actorJourney: "not-run",
    signedApiPlan: "not-verified",
    egressDenied: "not-verified",
    independentFinality: "not-verified",
    releaseQualified: false,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) {
      throw new Error("Usage: check-standalone-journey-prerequisites.mjs <private-setup-dir>");
    }
    const report = assessStandaloneJourneyPrerequisites(await standaloneSetupStatus(process.argv[2]));
    console.log(JSON.stringify(report, null, 2));
    if (!report.ledgerPrerequisitesObserved) process.exitCode = 2;
  } catch (error) {
    console.error(`Standalone journey prerequisite check failed: ${error.message}`);
    process.exitCode = 1;
  }
}
