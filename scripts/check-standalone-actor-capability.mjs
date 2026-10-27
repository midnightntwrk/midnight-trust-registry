#!/usr/bin/env node

import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SHA256 = /^[0-9a-f]{64}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const ROLES = new Set(["issuer", "verifier", "auditor", "maintainer", "recognition"]);

/** A health response is a configuration observation, never actor or finality evidence. */
export function assessStandaloneActorCapability(health, expectedPlanSha256, requiredRoles = ["issuer"]) {
  if (!SHA256.test(expectedPlanSha256) || !Array.isArray(requiredRoles)
    || requiredRoles.length === 0 || requiredRoles.some((role) => !ROLES.has(role))
    || new Set(requiredRoles).size !== requiredRoles.length) {
    throw new Error("Expected plan SHA-256 and distinct known actor roles are required");
  }
  if (health?.status !== "ok" || health.sourceMode !== "local-ledger"
    || !SHA256.test(health.localPlanSha256 ?? "")
    || !HASH.test(health.finalizedBlockHash ?? "")
    || /^0x0{64}$/u.test(health.finalizedBlockHash)
    || !Array.isArray(health.configuredGovernedProposalRoles)
    || health.configuredGovernedProposalRoles.some((role) => !ROLES.has(role))
    || new Set(health.configuredGovernedProposalRoles).size !== health.configuredGovernedProposalRoles.length) {
    throw new Error("Health response is not a pinned local-ledger API observation");
  }
  const missingRoles = requiredRoles.filter((role) => !health.configuredGovernedProposalRoles.includes(role));
  return {
    format: "tr-standalone-actor-capability-v1",
    planMatchesCandidate: health.localPlanSha256 === expectedPlanSha256,
    finalizedBlockHash: health.finalizedBlockHash,
    configuredRoles: health.configuredGovernedProposalRoles,
    missingRoles,
    requestedPortsConfigured: missingRoles.length === 0 && health.localPlanSha256 === expectedPlanSha256,
    actorJourney: "not-run",
    observationAuthenticity: "not-independently-verified",
    independentFinality: "not-verified",
    liveStatusAuthority: "not-verified",
    releaseQualified: false,
  };
}

async function readHealth(path) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.size === 0n || before.size > 64n * 1024n) {
      throw new Error("Health response must be a bounded regular file");
    }
    const bytes = await file.readFile();
    const after = await file.stat({ bigint: true });
    if (BigInt(bytes.length) !== before.size || after.dev !== before.dev || after.ino !== before.ino
      || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs) {
      throw new Error("Health response changed during read");
    }
    return JSON.parse(bytes.toString("utf8"));
  } finally {
    await file.close();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length < 4) {
      throw new Error("Usage: check-standalone-actor-capability.mjs <health-json-file> <signed-plan-sha256> [role ...]");
    }
    const report = assessStandaloneActorCapability(await readHealth(process.argv[2]), process.argv[3],
      process.argv.length > 4 ? process.argv.slice(4) : ["issuer"]);
    console.log(JSON.stringify(report, null, 2));
    if (!report.requestedPortsConfigured) process.exitCode = 2;
  } catch (error) {
    console.error(`Standalone actor capability check failed: ${error.message}`);
    process.exitCode = 1;
  }
}
