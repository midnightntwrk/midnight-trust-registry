#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import {
  createLocalNetworkDeploymentActionReader,
  FileDeploymentAttemptJournal,
  FileVerifierKeyInsertionJournal,
  reconcileLocalVerifierKeyInsertion,
  submitLocalVerifierKeyInsertion,
  VerifierKeyInsertionOutcomeUnknownError,
} from "@midnight-ntwrk/trust-registry-integration";

import { checkLocalLedgerPreflight } from "./local-ledger-preflight.mjs";
import { validateLocalDeploymentPlan } from "./local-ledger-deploy.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const FIELDS = ["circuitName", "deploymentJournalPath", "format", "initialVerifierKeyName",
  "journalPath", "network", "providerModulePath", "providerModuleSha256",
  "releaseManifestPath", "sourceRevision"];
const exactFields = (value, fields) => value !== null && typeof value === "object"
  && !Array.isArray(value) && Object.keys(value).sort().join("\0") === [...fields].sort().join("\0");

export function validateLocalVerifierKeyInsertionPlan(plan) {
  if (!exactFields(plan, FIELDS)
    || plan.format !== "tr-local-verifier-key-insertion-plan-v1"
    || !SHA256.test(plan.providerModuleSha256)
    || !["circuitName", "initialVerifierKeyName"].every((field) =>
      typeof plan[field] === "string" && /^[A-Za-z][A-Za-z0-9_]{0,127}$/u.test(plan[field]))
    || !["deploymentJournalPath", "journalPath", "providerModulePath", "releaseManifestPath"]
      .every((field) => typeof plan[field] === "string" && isAbsolute(plan[field]))) {
    throw new Error("Verifier-key insertion requires an exact local approval plan");
  }
  validateLocalDeploymentPlan({
    format: "tr-local-deployment-plan-v1",
    sourceRevision: plan.sourceRevision,
    network: plan.network,
    providerModulePath: plan.providerModulePath,
    providerModuleSha256: plan.providerModuleSha256,
    releaseManifestPath: plan.releaseManifestPath,
    journalPath: plan.journalPath,
  });
  const expectedJournalPath = join(dirname(resolve(plan.deploymentJournalPath)),
    `verifier-${plan.circuitName}.json`);
  if (resolve(plan.journalPath) !== expectedJournalPath) {
    throw new Error("Verifier-key insertion requires the fixed per-circuit journal path");
  }
  return plan;
}

async function regularFile(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size === 0 || stat.size > 16 * 1024 * 1024) {
    throw new Error("Approved verifier-key input must be a bounded regular file");
  }
  return readFile(path);
}

export async function runLocalVerifierKeyInsertion(plan, dependencies = {}, mode = "submit", approval = {}) {
  validateLocalVerifierKeyInsertionPlan(plan);
  if (mode !== "submit" && mode !== "reconcile") throw new Error("Unsupported insertion mode");
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
  try {
    if (!material || typeof material !== "object" || !material.bootstrap
      || !material.providers || !material.contractMaintenanceSigningKey) {
      throw new Error("Provider module did not return bootstrap, providers, and maintenance signing key");
    }
    const deployment = await (dependencies.inspectDeployment ?? (async (intent) =>
      new FileDeploymentAttemptJournal(plan.deploymentJournalPath).inspectApproved(intent)))({
      network: plan.network,
      bootstrap: material.bootstrap,
      releaseManifest: manifest,
      contractMaintenanceSigningKey: material.contractMaintenanceSigningKey,
      sourceRevision: plan.sourceRevision,
      initialVerifierKeyName: plan.initialVerifierKeyName,
    });
    if (deployment?.submitted === null || deployment?.submitted === undefined) {
      throw new Error("A finalized staged deployment receipt is required before key insertion");
    }
    if (approval.expectedDeploymentReceipt
      && ["networkId", "contractAddress", "txId", "blockHash", "blockHeight"]
        .some((field) => deployment.submitted[field] !== approval.expectedDeploymentReceipt[field])) {
      throw new Error("Deployment journal receipt disagrees with the setup-approved receipt");
    }
    const receipt = {
      networkId: deployment.submitted.networkId,
      contractAddress: deployment.submitted.contractAddress,
      txId: deployment.submitted.txId,
      blockHash: deployment.submitted.blockHash,
      blockHeight: deployment.submitted.blockHeight,
    };
    const input = {
      network: plan.network,
      sourceRevision: plan.sourceRevision,
      receipt,
      bootstrap: material.bootstrap,
      releaseManifest: manifest,
      bootstrapMaintenanceVerifyingKey: deployment.reservation.bootstrapMaintenanceVerifyingKey,
      circuitName: plan.circuitName,
      journal: new FileVerifierKeyInsertionJournal(plan.journalPath),
      providers: material.providers,
      contractMaintenanceSigningKey: material.contractMaintenanceSigningKey,
    };
    if (mode === "reconcile") {
      const readback = await (dependencies.reconcile ?? reconcileLocalVerifierKeyInsertion)(input);
      return { kind: "local-verifier-key-insertion-reconciliation", circuitName: plan.circuitName,
        readback };
    }
    const result = await (dependencies.submit ?? submitLocalVerifierKeyInsertion)(input);
    return { kind: "local-verifier-key-insertion-observation", circuitName: plan.circuitName,
      receipt: result.receipt, readbackStatus: result.readback };
  } finally {
    if (typeof material?.stop === "function") {
      try {
        await material.stop();
      } catch {
        console.error("Provider cleanup failed; preserve journals and inspect the local chain");
      }
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length < 3 || process.argv.length > 4
    || (process.argv[3] !== undefined && process.argv[3] !== "--reconcile")) {
    throw new Error("Usage: node scripts/local-ledger-insert-verifier-key.mjs <approved-plan.json> [--reconcile]");
  }
  try {
    const plan = JSON.parse((await regularFile(resolve(process.argv[2]))).toString("utf8"));
    const result = await runLocalVerifierKeyInsertion(
      plan, {}, process.argv[3] === "--reconcile" ? "reconcile" : "submit",
    );
    console.log(JSON.stringify(result));
    const status = result.readbackStatus ?? result.readback?.status;
    if (status !== "verified") process.exitCode = 2;
  } catch (error) {
    if (error instanceof VerifierKeyInsertionOutcomeUnknownError && error.receipt) {
      console.log(JSON.stringify({ kind: "local-verifier-key-insertion-error", receipt: error.receipt }));
    }
    console.error("Verifier-key insertion is incomplete or ambiguous; preserve journals and inspect finalized state");
    process.exitCode = 1;
  }
}
