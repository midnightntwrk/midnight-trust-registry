#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";

import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import {
  createLocalNetworkDeploymentActionReader,
  deployLocalTrustRegistryOnce,
  FileDeploymentAttemptJournal,
} from "@midnight-ntwrk/trust-registry-integration";

import { checkLocalLedgerPreflight } from "./local-ledger-preflight.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const PLAN_FIELDS = ["format", "journalPath", "network", "providerModulePath",
  "providerModuleSha256", "releaseManifestPath", "sourceRevision"];
const NETWORK_FIELDS = ["allowedHosts", "expectedGenesisHash", "indexerHttpUrl",
  "indexerWsUrl", "networkId", "rpcUrl"];

const exactFields = (value, fields) => value !== null && typeof value === "object"
  && !Array.isArray(value) && Object.keys(value).sort().join("\0") === [...fields].sort().join("\0");

export function validateLocalDeploymentPlan(plan) {
  if (!exactFields(plan, PLAN_FIELDS) || plan.format !== "tr-local-deployment-plan-v1"
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
export async function runLocalDeployment(plan, dependencies = {}) {
  validateLocalDeploymentPlan(plan);
  const manifest = JSON.parse((await regularFile(plan.releaseManifestPath)).toString("utf8"));
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
  try {
    if (!material || typeof material !== "object" || !material.bootstrap
      || !material.providers || !material.contractMaintenanceSigningKey) {
      throw new Error("Provider module did not return bootstrap, providers, and maintenance signing key");
    }
    const result = await (dependencies.deployOnce ?? deployLocalTrustRegistryOnce)({
      network: plan.network,
      bootstrap: material.bootstrap,
      releaseManifest: manifest,
      providers: material.providers,
      contractMaintenanceSigningKey: material.contractMaintenanceSigningKey,
      sourceRevision: plan.sourceRevision,
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
