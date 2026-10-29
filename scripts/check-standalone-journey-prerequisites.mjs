#!/usr/bin/env node

import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { standaloneSetupStatus } from "./standalone-setup-wizard.mjs";
import { assessStandaloneJourneyPrerequisites } from "./standalone-journey-prerequisites-policy.mjs";

export { assessStandaloneJourneyPrerequisites };

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4) {
      throw new Error("Usage: check-standalone-journey-prerequisites.mjs <private-setup-dir> <candidate-source-sha>");
    }
    const report = assessStandaloneJourneyPrerequisites(
      await standaloneSetupStatus(process.argv[2]), process.argv[3]);
    console.log(JSON.stringify(report, null, 2));
    if (!report.ledgerPrerequisitesObserved) process.exitCode = 2;
  } catch (error) {
    console.error(`Standalone journey prerequisite check failed: ${error.message}`);
    process.exitCode = 1;
  }
}
