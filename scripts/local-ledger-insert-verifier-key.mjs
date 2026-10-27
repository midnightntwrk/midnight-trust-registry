#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import {
  createLocalNetworkDeploymentActionReader,
  FileDeploymentAttemptJournal,
  FileVerifierKeyInsertionJournal,
  getLocalNetworkProfile,
  reconcileLocalVerifierKeyInsertion,
  submitLocalVerifierKeyInsertion,
} from "@midnight-ntwrk/trust-registry-integration";

import { checkLocalLedgerPreflight } from "./local-ledger-preflight.mjs";
import { loadRecheckedApprovedProvider, readApprovedProviderIdentity } from "./approved-provider-identity.mjs";
import { assertApprovedProviderImportBoundary, assertApprovedProviderTree } from "./immutable-provider-tree.mjs";
import { validateLocalVerifierKeyInsertionPlan } from "./local-verifier-key-insertion-plan-policy.mjs";

export { validateLocalVerifierKeyInsertionPlan };

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
  const providerIdentity = await readApprovedProviderIdentity(plan.providerModulePath, plan.providerModuleSha256);
  if (dependencies.loadProvider === undefined) {
    const tree = assertApprovedProviderTree(plan.providerModulePath, process.env.TR_IMMUTABLE_PROVIDER_ROOT);
    assertApprovedProviderImportBoundary(tree.root);
  }
  setNetworkId(getLocalNetworkProfile().networkId);
  await (dependencies.validateEndpoints ?? createLocalNetworkDeploymentActionReader)(plan.network);
  await (dependencies.observe ?? checkLocalLedgerPreflight)({
    format: "tr-local-ledger-pin-v1",
    networkId: getLocalNetworkProfile().networkId,
    sourceRevision: plan.sourceRevision,
    rpcUrl: plan.network.rpcUrl,
    expectedGenesisHash: plan.network.expectedGenesisHash,
    allowedHosts: plan.network.allowedHosts,
  });
  const module = await loadRecheckedApprovedProvider(plan.providerModulePath,
    plan.providerModuleSha256, providerIdentity, dependencies.loadProvider);
  const factory = module !== null && typeof module === "object"
    && Object.hasOwn(module, "createLocalDeploymentMaterial")
    ? /** @type {Record<string, unknown>} */ (module).createLocalDeploymentMaterial : undefined;
  if (typeof factory !== "function") {
    throw new Error("Approved provider module must export createLocalDeploymentMaterial");
  }
  const material = await factory({
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
  console.error("Direct verifier-key insertion is disabled: use standalone-setup-wizard.mjs insert-key or reconcile-key with signed setup approvals");
  process.exitCode = 2;
}
