#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import {
  createLocalNetworkDeploymentActionReader,
  deployLocalTrustRegistryOnce,
  deployLocalTrustRegistryStagedOnce,
  FileDeploymentAttemptJournal,
  getLocalNetworkProfile,
  reconcileLocalStagedDeployment,
} from "@midnight-ntwrk/trust-registry-integration";

import { checkLocalLedgerPreflight } from "./local-ledger-preflight.mjs";
import { loadRecheckedApprovedProvider, readApprovedProviderIdentity } from "./approved-provider-identity.mjs";
import { assertApprovedProviderImportBoundary, assertApprovedProviderTree } from "./immutable-provider-tree.mjs";
import { validateLocalDeploymentPlan } from "./local-deployment-plan-policy.mjs";

export { validateLocalDeploymentPlan };

/** @typedef {ReturnType<typeof validateLocalDeploymentPlan>} LocalDeploymentPlan */
/** @typedef {Parameters<typeof deployLocalTrustRegistryOnce>[0]} DeploymentInput */
/** @typedef {Parameters<typeof deployLocalTrustRegistryStagedOnce>[0]} StagedDeploymentInput */
/** @typedef {Awaited<ReturnType<typeof deployLocalTrustRegistryOnce>>} DeploymentResult */
/** @typedef {Pick<DeploymentInput, "bootstrap" | "providers" | "contractMaintenanceSigningKey"> &
 * {stop?: () => Promise<void>}} DeploymentMaterial */
/** @typedef {{validateEndpoints?: typeof createLocalNetworkDeploymentActionReader,
 * observe?: typeof checkLocalLedgerPreflight,
 * loadProvider?: (modulePath: string) => Promise<unknown>,
 * deployOnce?: (input: DeploymentInput | StagedDeploymentInput) => Promise<DeploymentResult>,
 * inspectDeployment?: FileDeploymentAttemptJournal["inspectApproved"],
 * readback?: typeof reconcileLocalStagedDeployment}} DeploymentDependencies */
/** @typedef {{expectedReleaseManifestSha256?: string,
 * expectedDeploymentReceipt?: Partial<DeploymentResult["receipt"]>}} DeploymentApproval */
/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/** @param {string} path */
async function regularFile(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size === 0 || stat.size > 16 * 1024 * 1024) {
    throw new Error("Approved deployment input must be a bounded regular file");
  }
  return readFile(path);
}

/** The provider module is privileged code; the approved hash is checked before import. */
/** @param {LocalDeploymentPlan} plan
 * @param {DeploymentDependencies} dependencies
 * @param {DeploymentApproval} approval
 * @param {"createLocalDeploymentMaterial" | "createLocalMaintenanceMaterial"} factoryName */
async function loadApprovedMaterial(plan, dependencies, approval, factoryName) {
  validateLocalDeploymentPlan(plan);
  const manifestBytes = await regularFile(plan.releaseManifestPath);
  if (approval.expectedReleaseManifestSha256
    && createHash("sha256").update(manifestBytes).digest("hex") !== approval.expectedReleaseManifestSha256) {
    throw new Error("Release manifest bytes changed after setup approval");
  }
  const parsedManifest = /** @type {unknown} */ (JSON.parse(manifestBytes.toString("utf8")));
  if (!isRecord(parsedManifest)
    || parsedManifest.format !== "tr-release-candidate-manifest-v2"
    || parsedManifest.sourceRevision !== plan.sourceRevision) {
    throw new Error("Approved source SHA disagrees with the release manifest");
  }
  if (!isRecord(parsedManifest.verifierKeySha256)
    || Object.keys(parsedManifest.verifierKeySha256).length === 0
    || Object.entries(parsedManifest.verifierKeySha256).some(([name, hash]) =>
      name.length === 0 || typeof hash !== "string" || !/^[0-9a-f]{64}$/u.test(hash))) {
    throw new Error("Release manifest verifier-key catalog is malformed");
  }
  const manifest = /** @type {DeploymentInput["releaseManifest"]} */ (parsedManifest);
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
  const factory = module !== null && typeof module === "object" && Object.hasOwn(module, factoryName)
    ? /** @type {Record<string, unknown>} */ (module)[factoryName] : undefined;
  if (typeof factory !== "function") {
    throw new Error(`Approved provider module must export ${factoryName}`);
  }
  const material = await /** @type {(input: {network: LocalDeploymentPlan["network"],
   * releaseManifest: DeploymentInput["releaseManifest"]}) => Promise<unknown>} */ (factory)({
    network: plan.network, releaseManifest: manifest,
  });
  return { manifest, material };
}

/** @param {LocalDeploymentPlan} plan
 * @param {DeploymentDependencies} [dependencies]
 * @param {DeploymentApproval} [approval] */
export async function loadApprovedDeploymentMaterial(plan, dependencies = {}, approval = {}) {
  return loadApprovedMaterial(plan, dependencies, approval, "createLocalDeploymentMaterial");
}

/** @param {LocalDeploymentPlan} plan
 * @param {DeploymentDependencies} [dependencies]
 * @param {DeploymentApproval} [approval] */
export async function loadApprovedMaintenanceMaterial(plan, dependencies = {}, approval = {}) {
  return loadApprovedMaterial(plan, dependencies, approval, "createLocalMaintenanceMaterial");
}

/** @param {LocalDeploymentPlan} plan
 * @param {DeploymentDependencies} [dependencies]
 * @param {DeploymentApproval} [approval] */
export async function runLocalDeployment(plan, dependencies = {}, approval = {}) {
  const { manifest, material } = await loadApprovedDeploymentMaterial(plan, dependencies, approval);
  try {
    if (!isRecord(material) || !material.bootstrap
      || !material.providers || !material.contractMaintenanceSigningKey) {
      throw new Error("Provider module did not return bootstrap, providers, and maintenance signing key");
    }
    const approvedMaterial = /** @type {DeploymentMaterial} */ (material);
    const deploymentInput = {
      network: plan.network,
      bootstrap: approvedMaterial.bootstrap,
      releaseManifest: manifest,
      providers: approvedMaterial.providers,
      contractMaintenanceSigningKey: approvedMaterial.contractMaintenanceSigningKey,
      sourceRevision: plan.sourceRevision,
      journal: new FileDeploymentAttemptJournal(plan.journalPath),
    };
    const result = plan.format === "tr-local-staged-deployment-plan-v1"
      ? await (dependencies.deployOnce ?? deployLocalTrustRegistryStagedOnce)({
        ...deploymentInput, initialVerifierKeyName: plan.initialVerifierKeyName,
      })
      : await (dependencies.deployOnce ?? deployLocalTrustRegistryOnce)(deploymentInput);
    return {
      kind: "local-deployment-submission-observation",
      sourceRevision: plan.sourceRevision,
      receipt: result.receipt,
      readbackStatus: result.readback.status,
    };
  } finally {
    if (isRecord(material) && typeof material.stop === "function") {
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
/** @param {LocalDeploymentPlan} plan
 * @param {DeploymentDependencies} [dependencies]
 * @param {DeploymentApproval} [approval] */
export async function reconcileLocalDeployment(plan, dependencies = {}, approval = {}) {
  if (plan?.format !== "tr-local-staged-deployment-plan-v1") {
    throw new Error("Read-only deployment reconciliation requires a staged local plan");
  }
  const { manifest, material } = await loadApprovedDeploymentMaterial(plan, dependencies, approval);
  try {
    if (!isRecord(material) || !material.bootstrap
      || !material.contractMaintenanceSigningKey) {
      throw new Error("Approved provider did not return staged bootstrap and maintenance key");
    }
    const approvedMaterial = /** @type {DeploymentMaterial} */ (material);
    const entry = await (dependencies.inspectDeployment ?? (async (intent) =>
      new FileDeploymentAttemptJournal(plan.journalPath).inspectApproved(intent)))({
      network: plan.network,
      bootstrap: approvedMaterial.bootstrap,
      releaseManifest: manifest,
      contractMaintenanceSigningKey: approvedMaterial.contractMaintenanceSigningKey,
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
    const expectedReceipt = approval.expectedDeploymentReceipt;
    const receiptFields = /** @type {const} */ (["networkId", "contractAddress", "txId",
      "blockHash", "blockHeight"]);
    if (expectedReceipt && receiptFields.some((field) => receipt[field] !== expectedReceipt[field])) {
      throw new Error("Deployment journal receipt disagrees with the setup-recorded receipt");
    }
    const readback = await (dependencies.readback ?? reconcileLocalStagedDeployment)({
      network: plan.network,
      receipt,
      bootstrap: approvedMaterial.bootstrap,
      releaseManifest: manifest,
      initialVerifierKeyName: plan.initialVerifierKeyName,
      bootstrapMaintenanceVerifyingKey: entry.reservation.bootstrapMaintenanceVerifyingKey,
    });
    return { kind: "local-deployment-reconciliation", receipt,
      receiptAttribution: "journal-recorded-not-independently-inclusion-verified",
      readbackStatus: readback.status,
      ...(readback.finalizedBlockHash ? { finalizedBlockHash: readback.finalizedBlockHash } : {}) };
  } finally {
    if (isRecord(material) && typeof material.stop === "function") {
      try {
        await material.stop();
      } catch {
        console.error("Provider cleanup failed; preserve the deployment journal and inspect the local chain");
      }
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  console.error("Direct deployment is disabled: use standalone-setup-wizard.mjs deploy with signed setup approvals");
  process.exitCode = 2;
}
