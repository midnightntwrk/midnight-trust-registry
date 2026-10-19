#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";

import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import {
  createLocalNetworkDeploymentActionReader,
  deployLocalTrustRegistryOnce,
  deployLocalTrustRegistryStagedOnce,
  FileDeploymentAttemptJournal,
  reconcileLocalStagedDeployment,
} from "@midnight-ntwrk/trust-registry-integration";

import { checkLocalLedgerPreflight } from "./local-ledger-preflight.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const PLAN_FIELDS = ["format", "journalPath", "network", "providerModulePath",
  "providerModuleSha256", "releaseManifestPath", "sourceRevision"];
const STAGED_PLAN_FIELDS = [...PLAN_FIELDS, "initialVerifierKeyName"];
const NETWORK_FIELDS = ["allowedHosts", "expectedGenesisHash", "indexerHttpUrl",
  "indexerWsUrl", "networkId", "rpcUrl"];

const exactFields = (value, fields) => value !== null && typeof value === "object"
  && !Array.isArray(value) && Object.keys(value).sort().join("\0") === [...fields].sort().join("\0");

export function validateLocalDeploymentPlan(plan) {
  const full = exactFields(plan, PLAN_FIELDS) && plan.format === "tr-local-deployment-plan-v1";
  const staged = exactFields(plan, STAGED_PLAN_FIELDS)
    && plan.format === "tr-local-staged-deployment-plan-v1"
    && typeof plan.initialVerifierKeyName === "string"
    && /^[A-Za-z][A-Za-z0-9_]{0,127}$/u.test(plan.initialVerifierKeyName);
  if ((!full && !staged)
    || !REVISION.test(plan.sourceRevision) || !SHA256.test(plan.providerModuleSha256)
    || !exactFields(plan.network, NETWORK_FIELDS)
    || plan.network.networkId !== "undeployed"
    || !HASH.test(plan.network.expectedGenesisHash)
    || /^0x0{64}$/u.test(plan.network.expectedGenesisHash)
    || !["rpcUrl", "indexerHttpUrl", "indexerWsUrl"].every(
      (field) => typeof plan.network[field] === "string" && plan.network[field].length > 0)
    || !Array.isArray(plan.network.allowedHosts) || plan.network.allowedHosts.length === 0
    || plan.network.allowedHosts.some((host) => typeof host !== "string" || host.length === 0)
    || !["journalPath", "providerModulePath", "releaseManifestPath"].every(
      (field) => typeof plan[field] === "string" && isAbsolute(plan[field]))) {
    throw new Error("Local deployment requires an exact source, genesis, endpoint, and provider approval plan");
  }
  return plan;
}

async function regularFile(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size === 0 || stat.size > 16 * 1024 * 1024) {
    throw new Error("Approved deployment input must be a bounded regular file");
  }
  return readFile(path);
}

/** The provider module is privileged code; the approved hash is checked before import. */
async function loadApprovedDeploymentMaterial(plan, dependencies, approval = {}) {
  validateLocalDeploymentPlan(plan);
  const manifestBytes = await regularFile(plan.releaseManifestPath);
  if (approval.expectedReleaseManifestSha256
    && createHash("sha256").update(manifestBytes).digest("hex") !== approval.expectedReleaseManifestSha256) {
    throw new Error("Release manifest bytes changed after setup approval");
  }
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  if (manifest?.format !== "tr-release-candidate-manifest-v2"
    || manifest.sourceRevision !== plan.sourceRevision) {
    throw new Error("Approved source SHA disagrees with the release manifest");
  }
  const moduleBytes = await regularFile(plan.providerModulePath);
  if (createHash("sha256").update(moduleBytes).digest("hex") !== plan.providerModuleSha256) {
    throw new Error("Provider module bytes disagree with the approved SHA-256");
  }
  setNetworkId("undeployed");
  await (dependencies.validateEndpoints ?? createLocalNetworkDeploymentActionReader)(plan.network);
  await (dependencies.observe ?? checkLocalLedgerPreflight)({
    format: "tr-local-ledger-pin-v1",
    networkId: "undeployed",
    sourceRevision: plan.sourceRevision,
    rpcUrl: plan.network.rpcUrl,
    expectedGenesisHash: plan.network.expectedGenesisHash,
    allowedHosts: plan.network.allowedHosts,
  });
  const module = await (dependencies.loadProvider ?? ((path) => import(pathToFileURL(path).href)))(
    plan.providerModulePath,
  );
  if (typeof module.createLocalDeploymentMaterial !== "function") {
    throw new Error("Approved provider module must export createLocalDeploymentMaterial");
  }
  const material = await module.createLocalDeploymentMaterial({
    network: plan.network, releaseManifest: manifest,
  });
  return { manifest, material };
}

export async function runLocalDeployment(plan, dependencies = {}) {
  const { manifest, material } = await loadApprovedDeploymentMaterial(plan, dependencies);
  try {
    if (!material || typeof material !== "object" || !material.bootstrap
      || !material.providers || !material.contractMaintenanceSigningKey) {
      throw new Error("Provider module did not return bootstrap, providers, and maintenance signing key");
    }
    const deployOnce = dependencies.deployOnce ?? (plan.format === "tr-local-staged-deployment-plan-v1"
      ? deployLocalTrustRegistryStagedOnce : deployLocalTrustRegistryOnce);
    const result = await deployOnce({
      network: plan.network,
      bootstrap: material.bootstrap,
      releaseManifest: manifest,
      providers: material.providers,
      contractMaintenanceSigningKey: material.contractMaintenanceSigningKey,
      sourceRevision: plan.sourceRevision,
      ...(plan.format === "tr-local-staged-deployment-plan-v1" ? {
        initialVerifierKeyName: plan.initialVerifierKeyName,
      } : {}),
      journal: new FileDeploymentAttemptJournal(plan.journalPath),
    });
    return {
      kind: "local-deployment-submission-observation",
      sourceRevision: plan.sourceRevision,
      receipt: result.receipt,
      readbackStatus: result.readback.status,
    };
  } finally {
    if (typeof material?.stop === "function") {
      try {
        await material.stop();
      } catch {
        // Never hide a submitted receipt behind a wallet shutdown error.
        console.error("Provider cleanup failed; inspect the journal and local chain before any action");
      }
    }
  }
}

/** Inspects the original journal and finalized image; never enters the SDK deploy path. */
export async function reconcileLocalDeployment(plan, dependencies = {}, approval = {}) {
  if (plan?.format !== "tr-local-staged-deployment-plan-v1") {
    throw new Error("Read-only deployment reconciliation requires a staged local plan");
  }
  const { manifest, material } = await loadApprovedDeploymentMaterial(plan, dependencies, approval);
  try {
    if (!material || typeof material !== "object" || !material.bootstrap
      || !material.contractMaintenanceSigningKey) {
      throw new Error("Approved provider did not return staged bootstrap and maintenance key");
    }
    const entry = await (dependencies.inspectDeployment ?? (async (intent) =>
      new FileDeploymentAttemptJournal(plan.journalPath).inspectApproved(intent)))({
      network: plan.network,
      bootstrap: material.bootstrap,
      releaseManifest: manifest,
      contractMaintenanceSigningKey: material.contractMaintenanceSigningKey,
      sourceRevision: plan.sourceRevision,
      initialVerifierKeyName: plan.initialVerifierKeyName,
    });
    if (entry === null) throw new Error("No approved staged deployment reservation exists");
    if (entry.submitted === null) {
      if (approval.expectedDeploymentReceipt) {
        throw new Error("Deployment journal lost the setup-recorded receipt; preserve both records for recovery");
      }
      return { kind: "local-deployment-reconciliation", readbackStatus: "unknown-no-receipt" };
    }
    const receipt = {
      networkId: entry.submitted.networkId,
      contractAddress: entry.submitted.contractAddress,
      txId: entry.submitted.txId,
      blockHash: entry.submitted.blockHash,
      blockHeight: entry.submitted.blockHeight,
    };
    if (approval.expectedDeploymentReceipt
      && ["networkId", "contractAddress", "txId", "blockHash", "blockHeight"]
        .some((field) => receipt[field] !== approval.expectedDeploymentReceipt[field])) {
      throw new Error("Deployment journal receipt disagrees with the setup-recorded receipt");
    }
    const readback = await (dependencies.readback ?? reconcileLocalStagedDeployment)({
      network: plan.network,
      receipt,
      bootstrap: material.bootstrap,
      releaseManifest: manifest,
      initialVerifierKeyName: plan.initialVerifierKeyName,
      bootstrapMaintenanceVerifyingKey: entry.reservation.bootstrapMaintenanceVerifyingKey,
    });
    return { kind: "local-deployment-reconciliation", receipt,
      receiptAttribution: "journal-recorded-not-independently-inclusion-verified",
      readbackStatus: readback.status,
      ...(readback.finalizedBlockHash ? { finalizedBlockHash: readback.finalizedBlockHash } : {}) };
  } finally {
    if (typeof material?.stop === "function") {
      try {
        await material.stop();
      } catch {
        console.error("Provider cleanup failed; preserve the deployment journal and inspect the local chain");
      }
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    throw new Error("Usage: node scripts/local-ledger-deploy.mjs <approved-plan.json>");
  }
  try {
    const plan = JSON.parse((await regularFile(resolve(process.argv[2]))).toString("utf8"));
    console.log(JSON.stringify(await runLocalDeployment(plan)));
  } catch {
    // SDK errors can contain wallet internals. Preserve the journal and avoid printing a private cause.
    console.error("Local deployment failed or has unknown outcome; inspect the private journal and finalized chain before retrying");
    process.exitCode = 1;
  }
}
