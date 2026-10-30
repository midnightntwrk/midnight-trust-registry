#!/usr/bin/env node

import { execFile } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { observeStandaloneApiRuntime } from "./check-standalone-api-runtime.mjs";

const run = promisify(execFile);
const CONTAINER_ID = /^[0-9a-f]{64}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
/** @param {unknown} value */
const canonicalTimestamp = (value) => {
  const parsed = typeof value === "string" ? Date.parse(value) : Number.NaN;
  return Number.isFinite(parsed) && new Date(parsed).toISOString() === value;
};

/** @param {string[]} args */
async function docker(args) {
  const { stdout } = await run("docker", args, { timeout: 180_000,
    maxBuffer: 1024 * 1024 });
  return stdout;
}

/** @param {Awaited<ReturnType<typeof observeStandaloneApiRuntime>>} report */
function checkedTopology(report) {
  if (report?.kind !== "standalone-api-runtime-topology-observation"
    || report.releaseQualified !== false
    || report.approvalMountReadOnly !== true
    || report.trustAnchorMountReadOnly !== true
    || report.internalNetworkOnly !== true
    || report.hostPortPublished !== false
    || !CONTAINER_ID.test(report.apiContainerId ?? "")
    || !SHA256.test(report.installInventorySha256 ?? "")
    || typeof report.apiStartedAt !== "string"
    || !Number.isFinite(Date.parse(report.apiStartedAt))
    || !Number.isSafeInteger(report.apiRestartCount) || report.apiRestartCount < 0
    || typeof report.networkId !== "string" || report.networkId.length === 0
    || !/^[0-9a-f]{40}$/u.test(report.sourceRevision ?? "")) {
    throw new Error("API runtime topology observation is incomplete");
  }
  return report;
}

/** @param {string} stdout */
function checkedCurrentReadReport(stdout) {
  let report;
  try {
    report = JSON.parse(stdout);
  } catch {
    throw new Error("Packaged API current-read probe did not return JSON");
  }
  if (report?.format !== "tr-local-api-current-read-observation-v4"
    || report.releaseQualified !== false
    || report.apiOrigin !== "http://127.0.0.1:4400"
    || !/^[0-9a-f]{40}$/u.test(report.planSourceRevision ?? "")
    || !/^[0-9a-f]{64}$/u.test(report.planSha256 ?? "")
    || !SHA256.test(report.planInstallInventorySha256 ?? "")
    || !/^0x[0-9a-f]{64}$/u.test(report.planContractAddress ?? "")
    || /^0x0{64}$/u.test(report.planContractAddress)
    || !/^0x[0-9a-f]{64}$/u.test(report.planExpectedGenesisHash ?? "")
    || /^0x0{64}$/u.test(report.planExpectedGenesisHash)
    || !/^[0-9a-f]{64}$/u.test(report.selectedStateSha256 ?? "")
    || !canonicalTimestamp(report.observedAt)
    || !canonicalTimestamp(report.planNotAfter)
    || Date.parse(report.observedAt) > Date.parse(report.planNotAfter)
    || !/^0x[0-9a-f]{64}$/u.test(report.sourceFinalizedBlockHash ?? "")
    || /^0x0{64}$/u.test(report.sourceFinalizedBlockHash)
    || typeof report.registryId !== "string" || report.registryId.length === 0
    || typeof report.currentEpochId !== "string" || report.currentEpochId.length === 0
    || !["issuer", "verifier", "auditor", "recognition"].every((role) =>
      Number.isSafeInteger(report.counts?.[role]) && report.counts[role] >= 0)
    || !["issuer", "verifier", "auditor", "recognition"].every((role) =>
      Number.isSafeInteger(report.resolvedLookups?.[role])
      && report.resolvedLookups[role] >= 0
      && report.resolvedLookups[role] <= report.counts[role])
    || !["issuer", "verifier", "auditor"].every((role) =>
      Number.isSafeInteger(report.ambiguousLookups?.[role])
      && report.ambiguousLookups[role] >= 0
      && report.ambiguousLookups[role] <= report.counts[role])) {
    throw new Error("Packaged API current-read probe returned an invalid report");
  }
  return report;
}

/**
 * Same-container readback only; the node/indexer finality trust boundary is unchanged.
 * @param {string} bundle
 * @param {NodeJS.ProcessEnv} [env]
 * @param {{ observe?: typeof observeStandaloneApiRuntime, execDocker?: (args: string[]) => Promise<string> }} [dependencies]
 */
export async function probeStandaloneApiCurrentReads(bundle, env = process.env, dependencies = {}) {
  const observe = dependencies.observe ?? observeStandaloneApiRuntime;
  const execDocker = dependencies.execDocker ?? docker;
  const before = checkedTopology(await observe(bundle, env));
  const reviewerFingerprint = env.TR_API_REVIEWER_FINGERPRINT;
  if (typeof reviewerFingerprint !== "string" || !/^[0-9A-F]{40}$/u.test(reviewerFingerprint)) {
    throw new Error("Approved API reviewer fingerprint is missing");
  }
  const args = ["exec", before.apiContainerId, "node", "/app/bin/trust-registry-api.mjs",
    "observe-local-ledger-api", "--local-ledger-plan", "/run/trust-registry/api-plan.json",
    "--local-ledger-signature", "/run/trust-registry/api-plan.sig",
    "--local-ledger-keyring", "/run/trust-registry/reviewer-keyring",
    "--local-ledger-reviewer", reviewerFingerprint,
    "--api-origin", "http://127.0.0.1:4400"];
  const current = checkedCurrentReadReport(await execDocker(args));
  if (current.planSourceRevision !== before.sourceRevision) {
    throw new Error("Signed API plan source differs from the verified running image");
  }
  if (current.planInstallInventorySha256 !== before.installInventorySha256) {
    throw new Error("Signed API plan install inventory differs from the verified running image bundle");
  }
  const after = checkedTopology(await observe(bundle, env));
  if (before.apiContainerId !== after.apiContainerId
    || before.apiStartedAt !== after.apiStartedAt
    || before.apiRestartCount !== after.apiRestartCount
    || before.networkId !== after.networkId
    || before.installInventorySha256 !== after.installInventorySha256
    || before.sourceRevision !== after.sourceRevision) {
    throw new Error("API runtime container, install inventory, or internal network changed during current-read probe");
  }
  return {
    format: "tr-standalone-api-current-read-probe-v4",
    sourceRevision: before.sourceRevision,
    apiContainerId: before.apiContainerId,
    apiStartedAt: before.apiStartedAt,
    apiRestartCount: before.apiRestartCount,
    networkId: before.networkId,
    installInventorySha256: current.planInstallInventorySha256,
    planSha256: current.planSha256,
    planContractAddress: current.planContractAddress,
    planExpectedGenesisHash: current.planExpectedGenesisHash,
    planNotAfter: current.planNotAfter,
    observedAt: current.observedAt,
    registryId: current.registryId,
    sourceFinalizedBlockHash: current.sourceFinalizedBlockHash,
    selectedStateSha256: current.selectedStateSha256,
    currentEpochId: current.currentEpochId,
    counts: current.counts,
    resolvedLookups: current.resolvedLookups,
    ambiguousLookups: current.ambiguousLookups,
    routeReadback: "same-container-signed-plan-current-only",
    scope: "Selected by-ID readback and counted successful 200 resolves; ambiguous lookups checked for fail-closed 409 only. Counts include stale records and repeated lookup scopes; this is not independent finality or actor evidence.",
    independentFinality: "not-verified",
    egressDenied: "not-verified",
    actorJourneys: "not-run",
    releaseQualified: false,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) {
      throw new Error("Usage: check-standalone-api-reads.mjs <verified-install-bundle>");
    }
    console.log(JSON.stringify(await probeStandaloneApiCurrentReads(process.argv[2])));
  } catch (error) {
    console.error(`Standalone API current-read probe failed: ${error instanceof Error ? error.message : "unknown error"}`);
    process.exitCode = 1;
  }
}
