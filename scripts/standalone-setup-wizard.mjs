#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { open, lstat, mkdir, readFile, realpath, rename, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  FileMaintenanceTransitionJournal, prepareLocalNetworkCommitteeTransition,
  reconcileLocalNetworkCommitteeTransition, submitLocalNetworkCommitteeTransition,
  validateMaintenancePolicy,
  VerifierKeyInsertionOutcomeUnknownError,
} from "@midnight-ntwrk/trust-registry-integration";
import { ContractMaintenanceAuthority } from "@midnight-ntwrk/midnight-js-protocol/ledger";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { checkLocalLedgerPreflight } from "./local-ledger-preflight.mjs";
import {
  loadApprovedMaintenanceMaterial, reconcileLocalDeployment, runLocalDeployment,
  validateLocalDeploymentPlan,
} from "./local-ledger-deploy.mjs";
import {
  runLocalVerifierKeyInsertion, validateLocalVerifierKeyInsertionPlan,
} from "./local-ledger-insert-verifier-key.mjs";

const FORMAT = "tr-standalone-setup-v1";
const RECORD = "setup-record.json";
const FINGERPRINT = /^[A-F0-9]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const execFileAsync = promisify(execFile);
const validLocalDeploymentReceipt = (receipt) => receipt?.networkId === "undeployed"
  && HASH.test(receipt.contractAddress) && !/^0x0{64}$/u.test(receipt.contractAddress)
  && HASH.test(receipt.blockHash) && !/^0x0{64}$/u.test(receipt.blockHash)
  && typeof receipt.txId === "string" && receipt.txId.length > 0
  && Number.isSafeInteger(receipt.blockHeight) && receipt.blockHeight >= 0;

async function regularBytes(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size === 0 || stat.size > 16 * 1024 * 1024) {
    throw new Error("Setup input must be a bounded regular file");
  }
  return readFile(path);
}

async function privateDirectory(path) {
  const stat = await lstat(path);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Setup directory must be owned by this user and accessible only to them");
  }
  return realpath(path);
}

async function readRecord(directory) {
  const root = await privateDirectory(resolve(directory));
  const record = JSON.parse((await regularBytes(join(root, RECORD))).toString("utf8"));
  if (record?.format !== FORMAT || typeof record?.sourceRevision !== "string") {
    throw new Error("Invalid standalone setup record");
  }
  return { root, record };
}

async function writeRecord(root, record) {
  const temp = join(root, `.setup-record.${process.pid}.${Date.now()}.tmp`);
  const file = await open(temp, "wx", 0o600);
  try {
    await file.writeFile(`${JSON.stringify(record, null, 2)}\n`);
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(temp, join(root, RECORD));
}

async function writePrivateSnapshot(path, bytes) {
  const file = await open(path, "wx", 0o600);
  try {
    await file.writeFile(bytes);
    await file.sync();
  } finally {
    await file.close();
  }
}

async function withLock(directory, action) {
  const root = await privateDirectory(resolve(directory));
  const lockPath = join(root, ".setup.lock");
  const lock = await open(lockPath, "wx", 0o600);
  try {
    await lock.close();
    return await action(root);
  } finally {
    await unlink(lockPath);
  }
}

export async function initializeStandaloneSetup(directory, bundleDirectory, dependencies = {}) {
  const bundle = await realpath(resolve(bundleDirectory));
  const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(bundle);
  const inventory = await regularBytes(join(bundle, "install-inventory.json"));
  if (JSON.parse(inventory).sourceRevision !== verified.sourceRevision) {
    throw new Error("Verified install inventory changed during setup");
  }
  const root = resolve(directory);
  await mkdir(root, { mode: 0o700 });
  const record = {
    format: FORMAT,
    sourceRevision: verified.sourceRevision,
    createdAt: new Date().toISOString(),
    install: { bundle, inventorySha256: sha256(inventory), verified },
  };
  await writeRecord(root, record);
  return record;
}

export async function observeStandaloneLedger(directory, pinPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (record.deployment) throw new Error("Cannot replace the genesis pin after deployment was reserved");
    if (record.genesisApproval) throw new Error("Cannot replace the genesis observation after reviewer approval");
    const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    if (sha256(inventory) !== record.install.inventorySha256) {
      throw new Error("Installed inventory changed since setup verification");
    }
    const pinBytes = await regularBytes(resolve(pinPath));
    const pin = JSON.parse(pinBytes);
    if (pin.sourceRevision !== record.sourceRevision) {
      throw new Error("Genesis pin source revision disagrees with the installed bundle");
    }
    const observation = await (dependencies.preflight ?? checkLocalLedgerPreflight)(pin);
    record.ledgerObservation = {
      pinSha256: sha256(pinBytes),
      expectedGenesisHash: pin.expectedGenesisHash,
      rpcUrl: pin.rpcUrl,
      allowedHosts: pin.allowedHosts,
      observation,
    };
    await writeRecord(root, record);
    return record.ledgerObservation;
  });
}

export async function verifyDetachedReviewerSignature(
  documentPath, signaturePath, keyringDirectory, expectedFingerprint,
) {
  if (!FINGERPRINT.test(expectedFingerprint)) throw new Error("Reviewer signing-key fingerprint must be canonical");
  await privateDirectory(keyringDirectory);
  const { stdout } = await execFileAsync("gpg", [
    "--batch", "--no-auto-key-retrieve", "--homedir", keyringDirectory,
    "--status-fd=1", "--verify", signaturePath, documentPath,
  ], { timeout: 30_000, maxBuffer: 1024 * 1024 });
  const valid = [...stdout.matchAll(/^\[GNUPG:\] VALIDSIG ([A-F0-9]{40})(?: |$)/gmu)];
  if (valid.length !== 1 || valid[0][1] !== expectedFingerprint
    || /^\[GNUPG:\] (?:EXPKEYSIG|REVKEYSIG|BADSIG|ERRSIG|KEYEXPIRED|KEYREVOKED|SIGEXPIRED) /mu.test(stdout)) {
    throw new Error("Detached approval signature does not match the pinned reviewer key");
  }
}

async function verifiedApprovalEvidence(
  root, label, document, signature, keyringDirectory, expectedFingerprint, dependencies,
) {
  if (document.length > 32 * 1024 || signature.length > 64 * 1024) {
    throw new Error(`${label} approval document or signature exceeds the bounded evidence size`);
  }
  const snapshot = join(root, `.${label}-approval-${randomUUID()}`);
  const documentSnapshot = `${snapshot}.json`;
  const signatureSnapshot = `${snapshot}.sig`;
  try {
    await writePrivateSnapshot(documentSnapshot, document);
    await writePrivateSnapshot(signatureSnapshot, signature);
    await (dependencies.verifySignature ?? verifyDetachedReviewerSignature)(
      documentSnapshot, signatureSnapshot, resolve(keyringDirectory), expectedFingerprint,
    );
  } finally {
    await unlink(documentSnapshot).catch(() => {});
    await unlink(signatureSnapshot).catch(() => {});
  }
  return {
    reviewerFingerprint: expectedFingerprint,
    documentSha256: sha256(document),
    signatureSha256: sha256(signature),
    documentBase64: document.toString("base64"),
    signatureBase64: signature.toString("base64"),
    verification: "detached-signature-verified-against-operator-pinned-key",
  };
}

export async function approveStandaloneGenesis(
  directory, documentPath, signaturePath, keyringDirectory, expectedFingerprint, dependencies = {},
) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (!record.ledgerObservation) throw new Error("Observe the local ledger before requesting genesis approval");
    if (record.genesisApproval || record.deployment) throw new Error("Genesis approval is already recorded or deployment reserved");
    if (!FINGERPRINT.test(expectedFingerprint)) throw new Error("Reviewer signing-key fingerprint must be canonical");
    const document = await regularBytes(resolve(documentPath));
    const signature = await regularBytes(resolve(signaturePath));
    if (document.length > 32 * 1024 || signature.length > 64 * 1024) {
      throw new Error("Genesis approval document or signature exceeds the bounded evidence size");
    }
    const approval = JSON.parse(document);
    const expectedFields = ["approvedAt", "expectedGenesisHash", "format", "installInventorySha256",
      "networkId", "pinSha256", "reviewedReference", "reviewerFingerprint", "rpcUrl", "sourceRevision"];
    const approvedAt = Date.parse(approval?.approvedAt);
    if (approval === null || typeof approval !== "object" || Array.isArray(approval)
      || Object.keys(approval).sort().join("\0") !== expectedFields.join("\0")
      || approval.format !== "tr-local-genesis-approval-v1"
      || approval.sourceRevision !== record.sourceRevision
      || approval.installInventorySha256 !== record.install.inventorySha256
      || approval.networkId !== "undeployed"
      || approval.pinSha256 !== record.ledgerObservation.pinSha256
      || approval.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
      || !HASH.test(approval.expectedGenesisHash)
      || approval.rpcUrl !== record.ledgerObservation.rpcUrl
      || approval.reviewerFingerprint !== expectedFingerprint
      || typeof approval.reviewedReference !== "string"
      || approval.reviewedReference.length < 8 || approval.reviewedReference.length > 512
      || !Number.isFinite(approvedAt) || approvedAt < Date.parse(record.createdAt)
      || approvedAt > Date.now() + 5 * 60_000) {
      throw new Error("Reviewer approval does not bind the current install and observed genesis");
    }
    const evidence = await verifiedApprovalEvidence(
      root, "genesis", document, signature, keyringDirectory, expectedFingerprint, dependencies,
    );
    record.genesisApproval = {
      ...evidence,
      approvedAt: approval.approvedAt,
      reviewedReference: approval.reviewedReference,
    };
    await writeRecord(root, record);
    return {
      reviewerFingerprint: expectedFingerprint,
      documentSha256: record.genesisApproval.documentSha256,
      signatureSha256: record.genesisApproval.signatureSha256,
    };
  });
}

export async function approveStandaloneCommittee(
  directory, documentPath, signaturePath, keyringDirectory, expectedFingerprint, dependencies = {},
) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (!record.genesisApproval) throw new Error("Approve the local genesis before proposing a release committee");
    if (record.committeeApproval) throw new Error("Committee roster approval is already recorded");
    if (!FINGERPRINT.test(expectedFingerprint)) throw new Error("Governance reviewer fingerprint must be canonical");
    const document = await regularBytes(resolve(documentPath));
    const signature = await regularBytes(resolve(signaturePath));
    if (document.length > 32 * 1024 || signature.length > 64 * 1024) {
      throw new Error("Committee approval document or signature exceeds the bounded evidence size");
    }
    const approval = JSON.parse(document);
    const expectedFields = ["approvedAt", "custodians", "expectedGenesisHash", "format",
      "genesisApprovalSha256", "installInventorySha256", "maintenancePolicy", "networkId",
      "reviewedReference", "reviewerFingerprint", "sourceRevision"];
    const approvedAt = Date.parse(approval?.approvedAt);
    if (approval === null || typeof approval !== "object" || Array.isArray(approval)
      || Object.keys(approval).sort().join("\0") !== expectedFields.join("\0")
      || approval.format !== "tr-local-committee-approval-v1"
      || approval.sourceRevision !== record.sourceRevision
      || approval.installInventorySha256 !== record.install.inventorySha256
      || approval.genesisApprovalSha256 !== record.genesisApproval.documentSha256
      || approval.networkId !== "undeployed"
      || approval.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
      || approval.reviewerFingerprint !== expectedFingerprint
      || typeof approval.reviewedReference !== "string"
      || approval.reviewedReference.length < 8 || approval.reviewedReference.length > 512
      || !Number.isFinite(approvedAt)
      || approvedAt < Date.parse(record.genesisApproval.approvedAt)
      || approvedAt > Date.now() + 5 * 60_000) {
      throw new Error("Committee approval does not bind the approved install and genesis");
    }
    if (approval.maintenancePolicy === null || typeof approval.maintenancePolicy !== "object"
      || Array.isArray(approval.maintenancePolicy)
      || approval.maintenancePolicy.mode !== "committee"
      || !Array.isArray(approval.maintenancePolicy.verifyingKeys)
      || Object.keys(approval.maintenancePolicy).sort().join("\0") !== "mode\0threshold\0verifyingKeys") {
      throw new Error("Release maintenance approval requires a canonical committee policy");
    }
    validateMaintenancePolicy(approval.maintenancePolicy);
    const keys = approval.maintenancePolicy.verifyingKeys;
    try {
      new ContractMaintenanceAuthority(
        keys.map((key) => key.slice(2)), approval.maintenancePolicy.threshold, 1n,
      );
    } catch {
      throw new Error("Release committee contains a verifying key the Midnight ledger cannot use");
    }
    const custodians = approval.custodians;
    if (!Array.isArray(custodians) || custodians.length !== keys.length
      || custodians.some((entry, index) => entry === null || typeof entry !== "object" || Array.isArray(entry)
        || Object.keys(entry).sort().join("\0") !== "custodyReference\0holderRole\0verifyingKey"
        || entry.verifyingKey !== keys[index]
        || typeof entry.holderRole !== "string" || entry.holderRole.length < 3 || entry.holderRole.length > 128
        || typeof entry.custodyReference !== "string" || entry.custodyReference.length < 8
        || entry.custodyReference.length > 512)
      || new Set(custodians.map((entry) => entry.holderRole)).size !== keys.length) {
      throw new Error("Committee custody must bind distinct holder roles to every approved public key");
    }
    const evidence = await verifiedApprovalEvidence(
      root, "committee", document, signature, keyringDirectory, expectedFingerprint, dependencies,
    );
    record.committeeApproval = {
      ...evidence,
      approvedAt: approval.approvedAt,
      reviewedReference: approval.reviewedReference,
      maintenancePolicy: approval.maintenancePolicy,
      custodians,
    };
    await writeRecord(root, record);
    return {
      reviewerFingerprint: expectedFingerprint,
      documentSha256: evidence.documentSha256,
      signatureSha256: evidence.signatureSha256,
      threshold: approval.maintenancePolicy.threshold,
      committeeSize: keys.length,
    };
  });
}

export async function attemptStandaloneDeployment(directory, planPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (record.deployment) {
      throw new Error("Deployment already reserved; reconcile the journal and finalized chain before any new action");
    }
    if (!record.ledgerObservation || !record.genesisApproval) {
      throw new Error("Observe the local ledger and record detached reviewer approval before deployment");
    }
    const planBytes = await regularBytes(resolve(planPath));
    const plan = validateLocalDeploymentPlan(JSON.parse(planBytes));
    if (plan.sourceRevision !== record.sourceRevision
      || plan.network.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
      || plan.network.rpcUrl !== record.ledgerObservation.rpcUrl
      || JSON.stringify(plan.network.allowedHosts) !== JSON.stringify(record.ledgerObservation.allowedHosts)) {
      throw new Error("Deployment plan disagrees with the verified install or observed local ledger");
    }
    const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(record.install.bundle);
    const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    if (verified.sourceRevision !== record.sourceRevision
      || sha256(inventory) !== record.install.inventorySha256) {
      throw new Error("Installed bundle changed since setup verification");
    }
    const packageManifest = JSON.parse(inventory).packageManifest;
    const bundleManifestBytes = await regularBytes(join(record.install.bundle, packageManifest));
    const planManifestBytes = await regularBytes(plan.releaseManifestPath);
    if (sha256(bundleManifestBytes) !== sha256(planManifestBytes)) {
      throw new Error("Deployment release manifest disagrees with the verified install bundle");
    }
    record.deployment = {
      state: "reserved",
      planSha256: sha256(planBytes),
      journalPath: plan.journalPath,
      stagedPlan: plan.format === "tr-local-staged-deployment-plan-v1" ? {
        initialVerifierKeyName: plan.initialVerifierKeyName,
        network: plan.network,
        providerModulePath: plan.providerModulePath,
        providerModuleSha256: plan.providerModuleSha256,
        releaseManifestPath: plan.releaseManifestPath,
      } : null,
      reservedAt: new Date().toISOString(),
    };
    await writeRecord(root, record);
    try {
      const result = await (dependencies.deploy ?? runLocalDeployment)(plan);
      record.deployment = { ...record.deployment, state: "observed", result };
      await writeRecord(root, record);
      return result;
    } catch {
      record.deployment = { ...record.deployment, state: "unknown" };
      await writeRecord(root, record);
      throw new Error("Deployment outcome is unknown; inspect the journal and finalized chain, never retry blindly");
    }
  });
}

export async function reconcileStandaloneDeployment(directory, planPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (!record.deployment || !record.genesisApproval) {
      throw new Error("A reserved deployment and approved genesis are required for reconciliation");
    }
    if (record.deployment.result?.readbackStatus === "staged-bootstrap-pending"
      || Object.keys(record.verifierKeyInsertions ?? {}).length > 0) {
      throw new Error("Staged bootstrap already advanced; reconcile verifier keys instead of downgrading deployment state");
    }
    const planBytes = await regularBytes(resolve(planPath));
    const plan = validateLocalDeploymentPlan(JSON.parse(planBytes));
    if (plan.format !== "tr-local-staged-deployment-plan-v1"
      || sha256(planBytes) !== record.deployment.planSha256
      || plan.journalPath !== record.deployment.journalPath
      || plan.sourceRevision !== record.sourceRevision
      || plan.network.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
      || plan.network.rpcUrl !== record.ledgerObservation.rpcUrl
      || JSON.stringify(plan.network.allowedHosts) !== JSON.stringify(record.ledgerObservation.allowedHosts)) {
      throw new Error("Reconciliation plan disagrees with the reserved staged deployment");
    }
    const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(record.install.bundle);
    const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    if (verified.sourceRevision !== record.sourceRevision
      || sha256(inventory) !== record.install.inventorySha256) {
      throw new Error("Installed bundle changed since setup verification");
    }
    const packageManifest = JSON.parse(inventory).packageManifest;
    const bundleManifest = await regularBytes(join(record.install.bundle, packageManifest));
    const planManifest = await regularBytes(plan.releaseManifestPath);
    if (sha256(bundleManifest) !== sha256(planManifest)) {
      throw new Error("Deployment release manifest disagrees with the verified install bundle");
    }
    const approval = {
      expectedReleaseManifestSha256: sha256(planManifest),
      ...(record.deployment.result?.receipt
        ? { expectedDeploymentReceipt: record.deployment.result.receipt } : {}),
    };
    const result = await (dependencies.reconcileDeployment ?? ((approvedPlan, expected) =>
      reconcileLocalDeployment(approvedPlan, {}, expected)))(plan, approval);
    if (!["staged-bootstrap-pending", "pending", "invalid-image", "unavailable", "mismatch", "unknown-no-receipt"]
      .includes(result?.readbackStatus)
      || (result.readbackStatus === "unknown-no-receipt"
        && (result.receipt !== undefined || approval.expectedDeploymentReceipt))
      || (result.readbackStatus !== "unknown-no-receipt"
        && (!validLocalDeploymentReceipt(result.receipt)
          || result.receiptAttribution !== "journal-recorded-not-independently-inclusion-verified"))
      || (result.finalizedBlockHash !== undefined
        && !HASH.test(result.finalizedBlockHash))) {
      throw new Error("Deployment reconciliation returned an invalid observation");
    }
    if (approval.expectedDeploymentReceipt
      && ["networkId", "contractAddress", "txId", "blockHash", "blockHeight"]
        .some((field) => result.receipt?.[field] !== approval.expectedDeploymentReceipt[field])) {
      throw new Error("Deployment reconciliation changed the setup-recorded receipt");
    }
    if (result.receipt) {
      const readbackHistory = [...(record.deployment.readbackHistory ?? [])];
      if (readbackHistory.length >= 256) {
        throw new Error("Deployment reconciliation history is full; preserve the setup record for operator review");
      }
      if (record.deployment.result) readbackHistory.push(record.deployment.result);
      record.deployment = {
        ...record.deployment, state: "observed",
        readbackHistory,
        stagedPlan: record.deployment.stagedPlan ?? {
          initialVerifierKeyName: plan.initialVerifierKeyName,
          network: plan.network,
          providerModulePath: plan.providerModulePath,
          providerModuleSha256: plan.providerModuleSha256,
          releaseManifestPath: plan.releaseManifestPath,
        },
        result: {
          kind: "local-deployment-submission-observation",
          sourceRevision: plan.sourceRevision,
          receipt: result.receipt,
          readbackStatus: result.readbackStatus,
          receiptAttribution: result.receiptAttribution,
          ...(result.finalizedBlockHash
            ? { finalizedBlockHash: result.finalizedBlockHash } : {}),
        },
      };
      await writeRecord(root, record);
    }
    return result;
  });
}

async function approvedInsertionPlan(record, planPath, dependencies) {
  if (record.deployment?.state !== "observed"
    || record.deployment.result?.readbackStatus !== "staged-bootstrap-pending"
    || !validLocalDeploymentReceipt(record.deployment.result?.receipt)
    || !record.deployment.stagedPlan || !record.genesisApproval) {
    throw new Error("A finalized staged bootstrap and approved genesis are required before key insertion");
  }
  const planBytes = await regularBytes(resolve(planPath));
  const plan = validateLocalVerifierKeyInsertionPlan(JSON.parse(planBytes));
  const staged = record.deployment.stagedPlan;
  if (plan.sourceRevision !== record.sourceRevision
    || plan.network.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
    || plan.network.rpcUrl !== record.ledgerObservation.rpcUrl
    || JSON.stringify(plan.network.allowedHosts) !== JSON.stringify(record.ledgerObservation.allowedHosts)
    || plan.network.indexerHttpUrl !== staged.network.indexerHttpUrl
    || plan.network.indexerWsUrl !== staged.network.indexerWsUrl
    || plan.deploymentJournalPath !== record.deployment.journalPath
    || plan.initialVerifierKeyName !== staged.initialVerifierKeyName
    || plan.providerModulePath !== staged.providerModulePath
    || plan.providerModuleSha256 !== staged.providerModuleSha256
    || plan.releaseManifestPath !== staged.releaseManifestPath) {
    throw new Error("Insertion plan disagrees with the approved staged deployment");
  }
  const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(record.install.bundle);
  const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
  if (verified.sourceRevision !== record.sourceRevision
    || sha256(inventory) !== record.install.inventorySha256) {
    throw new Error("Installed bundle changed since setup verification");
  }
  const packageManifest = JSON.parse(inventory).packageManifest;
  const bundleManifest = await regularBytes(join(record.install.bundle, packageManifest));
  const planManifest = await regularBytes(plan.releaseManifestPath);
  if (sha256(bundleManifest) !== sha256(planManifest)) {
    throw new Error("Insertion release manifest disagrees with the verified install bundle");
  }
  return { plan, planSha256: sha256(planBytes), releaseManifestSha256: sha256(planManifest) };
}

export async function attemptStandaloneVerifierKeyInsertion(directory, planPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const { plan, planSha256, releaseManifestSha256 } = await approvedInsertionPlan(record, planPath, dependencies);
    const attempts = record.verifierKeyInsertions ?? {};
    if (Object.hasOwn(attempts, plan.circuitName)
      || Object.values(attempts).some((entry) => entry.state !== "verified")) {
      throw new Error("Prior verifier-key insertion is reserved or unresolved; reconcile without resubmitting");
    }
    record.verifierKeyInsertions = attempts;
    attempts[plan.circuitName] = {
      state: "reserved", planSha256, journalPath: plan.journalPath,
      reservedAt: new Date().toISOString(),
    };
    await writeRecord(root, record);
    try {
      const approval = {
        expectedDeploymentReceipt: record.deployment.result.receipt,
        expectedReleaseManifestSha256: releaseManifestSha256,
      };
      const result = await (dependencies.insert ?? ((approvedPlan, expected) =>
        runLocalVerifierKeyInsertion(approvedPlan, {}, "submit", expected)))(plan, approval);
      if (!["verified", "pending", "absent", "mismatch"].includes(result?.readbackStatus)) {
        throw new Error("Insertion did not return a recognized finalized-readback status");
      }
      const state = result.readbackStatus;
      attempts[plan.circuitName] = { ...attempts[plan.circuitName], state, result };
      await writeRecord(root, record);
      return result;
    } catch (error) {
      attempts[plan.circuitName] = {
        ...attempts[plan.circuitName], state: "unknown",
        ...(error instanceof VerifierKeyInsertionOutcomeUnknownError && error.receipt
          ? { receipt: error.receipt } : {}),
      };
      await writeRecord(root, record);
      throw new Error("Verifier-key insertion outcome is unknown; reconcile the journal and finalized chain, never retry blindly");
    }
  });
}

export async function reconcileStandaloneVerifierKeyInsertion(directory, planPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const { plan, planSha256, releaseManifestSha256 } = await approvedInsertionPlan(record, planPath, dependencies);
    const attempt = record.verifierKeyInsertions?.[plan.circuitName];
    if (!attempt || attempt.planSha256 !== planSha256 || attempt.journalPath !== plan.journalPath) {
      throw new Error("No matching reserved verifier-key insertion exists");
    }
    const approval = {
      expectedDeploymentReceipt: record.deployment.result.receipt,
      expectedReleaseManifestSha256: releaseManifestSha256,
    };
    const result = await (dependencies.reconcile ?? ((approvedPlan, expected) =>
      runLocalVerifierKeyInsertion(approvedPlan, {}, "reconcile", expected)))(plan, approval);
    if (!["verified", "failed-on-chain", "observed-without-receipt", "pending", "absent", "mismatch"]
      .includes(result?.readback?.status)) {
      throw new Error("Reconciliation did not return a recognized finalized-readback status");
    }
    attempt.state = result.readback.status;
    attempt.result = result;
    await writeRecord(root, record);
    return result;
  });
}

const exactFields = (value, fields) => value !== null && typeof value === "object"
  && !Array.isArray(value)
  && Object.keys(value).sort().join("\0") === [...fields].sort().join("\0");
const bytes32 = (value) => {
  if (!HASH.test(value) || /^0x0{64}$/u.test(value)) {
    throw new Error("Committee transition request contains an invalid public commitment");
  }
  return Buffer.from(value.slice(2), "hex");
};
const integer = (value) => {
  if (typeof value !== "string" || !DECIMAL.test(value)) {
    throw new Error("Committee transition request contains an invalid decimal counter");
  }
  return BigInt(value);
};

async function readApprovedCommitteeTransition(record, requestPath, dependencies = {}) {
    const staged = record.deployment?.stagedPlan;
    const receipt = record.deployment?.result?.receipt;
    if (!record.genesisApproval || !record.committeeApproval || !staged
      || record.deployment?.state !== "observed"
      || record.deployment.result?.readbackStatus !== "staged-bootstrap-pending"
      || !validLocalDeploymentReceipt(receipt)) {
      throw new Error("Approved committee and finalized staged deployment are required");
    }
    const approvalBytes = Buffer.from(record.committeeApproval.documentBase64 ?? "", "base64");
    const signedApproval = JSON.parse(approvalBytes.toString("utf8"));
    if (sha256(approvalBytes) !== record.committeeApproval.documentSha256
      || signedApproval.sourceRevision !== record.sourceRevision
      || signedApproval.installInventorySha256 !== record.install.inventorySha256
      || signedApproval.genesisApprovalSha256 !== record.genesisApproval.documentSha256
      || signedApproval.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
      || JSON.stringify(signedApproval.maintenancePolicy)
        !== JSON.stringify(record.committeeApproval.maintenancePolicy)) {
      throw new Error("Stored committee approval disagrees with signed approval bytes");
    }
    const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    if (sha256(inventory) !== record.install.inventorySha256) {
      throw new Error("Installed inventory changed since committee approval");
    }
    const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(record.install.bundle);
    if (verified.sourceRevision !== record.sourceRevision) {
      throw new Error("Installed bundle source revision changed since committee approval");
    }
    const manifestPath = join(record.install.bundle, JSON.parse(inventory).packageManifest);
    const manifestBytes = await regularBytes(manifestPath);
    const deployedManifestBytes = await regularBytes(staged.releaseManifestPath);
    if (sha256(manifestBytes) !== sha256(deployedManifestBytes)) {
      throw new Error("Staged deployment manifest disagrees with approved install bytes");
    }
    const manifest = JSON.parse(manifestBytes);
    if (manifest.format !== "tr-release-candidate-manifest-v2"
      || manifest.sourceRevision !== record.sourceRevision) {
      throw new Error("Staged deployment manifest has an invalid source or format");
    }
    const catalog = Object.keys(manifest.verifierKeySha256 ?? {});
    const expectedInsertions = catalog.filter((name) => name !== staged.initialVerifierKeyName).sort();
    const insertions = record.verifierKeyInsertions ?? {};
    if (catalog.length < 2 || !catalog.includes(staged.initialVerifierKeyName)
      || Object.keys(insertions).sort().join("\0") !== expectedInsertions.join("\0")
      || expectedInsertions.some((name) => insertions[name].state !== "verified")) {
      throw new Error("Every staged verifier key must have verified finalized readback");
    }
    const requestBytes = await regularBytes(resolve(requestPath));
    const request = JSON.parse(requestBytes);
    if (!exactFields(request, ["bootstrap", "bootstrapMaintenanceVerifyingKey", "expiresAt",
      "format", "governance", "sourceRevision"])
      || request.format !== "tr-local-committee-transition-request-v1"
      || request.sourceRevision !== record.sourceRevision
      || !HASH.test(request.bootstrapMaintenanceVerifyingKey)
      || !exactFields(request.bootstrap, ["governancePolicyCommitment", "maintainerDidCommitment",
        "maintainerId", "maintainerKeyId", "maintainerPublicKey", "maintainerThreshold",
        "registryDidCommitment", "registryId"])
      || !exactFields(request.bootstrap.maintainerPublicKey, ["x", "y"])
      || typeof request.bootstrap.registryId !== "string"
      || !exactFields(request.governance, ["actionSequence", "activeMaintainerCount",
        "maintainerThreshold", "policyCommitment", "policyVersion"])) {
      throw new Error("Committee transition request has an invalid shape or source revision");
    }
    const approval = {
      network: staged.network,
      receipt,
      bootstrap: {
        registryId: request.bootstrap.registryId,
        registryDidCommitment: bytes32(request.bootstrap.registryDidCommitment),
        governancePolicyCommitment: bytes32(request.bootstrap.governancePolicyCommitment),
        maintainerId: bytes32(request.bootstrap.maintainerId),
        maintainerDidCommitment: bytes32(request.bootstrap.maintainerDidCommitment),
        maintainerKeyId: bytes32(request.bootstrap.maintainerKeyId),
        maintainerPublicKey: {
          x: integer(request.bootstrap.maintainerPublicKey.x),
          y: integer(request.bootstrap.maintainerPublicKey.y),
        },
        maintainerThreshold: integer(request.bootstrap.maintainerThreshold),
      },
      releaseManifest: manifest,
      governance: {
        policyCommitment: bytes32(request.governance.policyCommitment),
        policyVersion: integer(request.governance.policyVersion),
        actionSequence: integer(request.governance.actionSequence),
        maintainerThreshold: integer(request.governance.maintainerThreshold),
        activeMaintainerCount: integer(request.governance.activeMaintainerCount),
      },
      maintenancePolicy: record.committeeApproval.maintenancePolicy,
      bootstrapMaintenanceVerifyingKey: request.bootstrapMaintenanceVerifyingKey,
      stagedVerifierKeyInstallation: true,
      expiresAt: new Date(request.expiresAt),
    };
    return { approval, requestBytes, manifestBytes, catalog };
}

async function approvedStandaloneCommitteeTransition(record, requestPath, dependencies = {}) {
    const { approval, requestBytes, manifestBytes, catalog } = await readApprovedCommitteeTransition(
      record, requestPath, dependencies,
    );
    setNetworkId("undeployed");
    const prepared = await (dependencies.prepareTransition ?? prepareLocalNetworkCommitteeTransition)(approval);
    if (prepared.networkId !== "undeployed" || prepared.contractAddress !== approval.receipt.contractAddress
      || !HASH.test(prepared.finalizedBlockHash) || /^0x0{64}$/u.test(prepared.finalizedBlockHash)
      || prepared.currentAuthorityCounter !== BigInt(catalog.length - 1)
      || prepared.nextAuthorityCounter !== BigInt(catalog.length)
      || prepared.threshold !== record.committeeApproval.maintenancePolicy.threshold
      || JSON.stringify(prepared.committeeVerifyingKeys)
        !== JSON.stringify(record.committeeApproval.maintenancePolicy.verifyingKeys)
      || prepared.expiresAt !== approval.expiresAt.toISOString()
      || !(prepared.dataToSign instanceof Uint8Array) || prepared.dataToSign.length === 0) {
      throw new Error("Finalized committee transition plan disagrees with approved setup state");
    }
    const signingRequest = {
      kind: "local-committee-transition-signing-request",
      sourceRevision: record.sourceRevision,
      committeeApprovalSha256: record.committeeApproval.documentSha256,
      requestSha256: sha256(requestBytes),
      releaseManifestSha256: sha256(manifestBytes),
      contractAddress: prepared.contractAddress,
      finalizedBlockHash: prepared.finalizedBlockHash,
      currentAuthorityCounter: prepared.currentAuthorityCounter.toString(),
      nextAuthorityCounter: prepared.nextAuthorityCounter.toString(),
      committeeVerifyingKeys: prepared.committeeVerifyingKeys,
      threshold: prepared.threshold,
      expiresAt: prepared.expiresAt,
      dataToSignHex: `0x${Buffer.from(prepared.dataToSign).toString("hex")}`,
      updateSha256: sha256(prepared.dataToSign),
      submission: "not-attempted",
    };
    return { approval, signingRequest, requestBytes, prepared };
}

export async function prepareStandaloneCommitteeTransition(directory, requestPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const { signingRequest } = await approvedStandaloneCommitteeTransition(
      record, requestPath, dependencies,
    );
    return signingRequest;
  });
}

const SIGNATURE = /^0x[0-9a-f]{128}$/u;
const signingRequestMatches = (saved, fresh) => exactFields(saved, Object.keys(fresh))
  && HASH.test(saved.finalizedBlockHash) && !/^0x0{64}$/u.test(saved.finalizedBlockHash)
  && Object.keys(fresh).filter((field) => field !== "finalizedBlockHash")
    .every((field) => JSON.stringify(saved[field]) === JSON.stringify(fresh[field]));

export async function submitStandaloneCommitteeTransition(
  directory, requestPath, signingRequestPath, signaturePath, dependencies = {},
) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const priorRecoveredAttempt = record.maintenanceAttempt?.state === "recovered-no-journal-approved"
      ? record.maintenanceAttempt : null;
    if (["aborted-before-journal", "recovered-no-journal-approved"]
      .includes(record.maintenanceAttempt?.state)) {
      if (record.maintenanceAttempt.state === "recovered-no-journal-approved"
        && !record.maintenanceAttempt.recoveryApproval) {
        throw new Error("Maintenance recovery approval evidence is missing");
      }
      const priorJournal = new FileMaintenanceTransitionJournal(record.maintenanceAttempt.journalPath);
      if (await priorJournal.inspect() !== null) {
        throw new Error("Aborted maintenance attempt has a journal; preserve it for recovery");
      }
      const history = record.maintenanceHistory ?? [];
      if (history.length >= 32) throw new Error("Maintenance attempt history is full; preserve it for review");
      history.push(record.maintenanceAttempt);
      record.maintenanceHistory = history;
      delete record.maintenanceAttempt;
    } else if (record.maintenanceAttempt) {
      if (record.maintenanceAttempt.state === "recovery-required-no-journal") {
        throw new Error("Maintenance crash window requires independent human recovery approval before a new attempt");
      }
      throw new Error("Maintenance transition already reserved; reconcile without resubmitting");
    }
    const { approval, signingRequest, requestBytes, prepared } = await approvedStandaloneCommitteeTransition(
      record, requestPath, dependencies,
    );
    if (priorRecoveredAttempt
      && (sha256(requestBytes) === priorRecoveredAttempt.requestSha256
        || signingRequest.finalizedBlockHash === priorRecoveredAttempt.finalizedBlockHash
        || Date.parse(signingRequest.expiresAt)
          <= Date.parse(priorRecoveredAttempt.recoveryApproval.approvedAt))) {
      throw new Error("Human-recovered maintenance requires a fresh request and signing window");
    }
    const signingRequestBytes = await regularBytes(resolve(signingRequestPath));
    const savedSigningRequest = JSON.parse(signingRequestBytes);
    if (!signingRequestMatches(savedSigningRequest, signingRequest)) {
      throw new Error("Saved signing request disagrees with fresh finalized maintenance evidence");
    }
    if (priorRecoveredAttempt
      && savedSigningRequest.finalizedBlockHash
        === priorRecoveredAttempt.finalizedBlockHash) {
      throw new Error("Recovered maintenance attempt cannot reuse the abandoned finalized checkpoint");
    }
    const signatureBytes = await regularBytes(resolve(signaturePath));
    const signed = JSON.parse(signatureBytes);
    if (!exactFields(signed, ["format", "signature", "updateSha256"])
      || signed.format !== "tr-local-committee-signature-v1"
      || signed.updateSha256 !== signingRequest.updateSha256
      || !SIGNATURE.test(signed.signature)) {
      throw new Error("External bootstrap signature does not match the approved signing request");
    }
    const signature = signed.signature.slice(2);
    prepared.authorize(signature);
    const journalPath = join(root, "committee-transition.json");
    const journal = new FileMaintenanceTransitionJournal(journalPath);
    if (await journal.inspect() !== null) {
      throw new Error("Maintenance journal already exists; reconcile the previous attempt");
    }
    record.maintenanceAttempt = {
      state: "reserved",
      requestSha256: sha256(requestBytes),
      signingRequestSha256: sha256(signingRequestBytes),
      signatureSha256: sha256(signatureBytes),
      updateSha256: signingRequest.updateSha256,
      finalizedBlockHash: savedSigningRequest.finalizedBlockHash,
      journalPath,
      reservedAt: new Date().toISOString(),
    };
    await writeRecord(root, record);
    let material;
    try {
      const staged = record.deployment.stagedPlan;
      const plan = validateLocalDeploymentPlan({
        format: "tr-local-staged-deployment-plan-v1",
        sourceRevision: record.sourceRevision,
        network: staged.network,
        providerModulePath: staged.providerModulePath,
        providerModuleSha256: staged.providerModuleSha256,
        releaseManifestPath: staged.releaseManifestPath,
        initialVerifierKeyName: staged.initialVerifierKeyName,
        journalPath: record.deployment.journalPath,
      });
      ({ material } = await (dependencies.loadMaterial ?? loadApprovedMaintenanceMaterial)(
        plan, dependencies, { expectedReleaseManifestSha256: signingRequest.releaseManifestSha256 },
      ));
      if (!material?.providers) throw new Error("Approved provider module did not return contract providers");
      const txId = await (dependencies.submit ?? submitLocalNetworkCommitteeTransition)({
        approval, signature, journal, providers: material.providers,
        approvedUpdateSha256: signingRequest.updateSha256,
        approvedFinalizedBlockHash: savedSigningRequest.finalizedBlockHash,
      });
      if (typeof txId !== "string" || txId.length === 0 || txId.length > 512) {
        throw new Error("Maintenance submission did not return a bounded transaction ID");
      }
      record.maintenanceAttempt = { ...record.maintenanceAttempt, state: "submitted", txId };
      await writeRecord(root, record);
      return { kind: "local-committee-transition-submission", txId, finalizedReadback: "pending" };
    } catch (error) {
      let journalReserved = true;
      try { journalReserved = await journal.inspect() !== null; } catch { /* An unreadable journal is unknown. */ }
      record.maintenanceAttempt = { ...record.maintenanceAttempt,
        state: journalReserved ? "unknown" : "aborted-before-journal",
        journalReserved,
        ...(journalReserved && typeof error?.txId === "string"
          && error.txId.length > 0 && error.txId.length <= 512
          ? { reportedTxId: error.txId } : {}) };
      await writeRecord(root, record);
      if (!journalReserved) {
        throw new Error("Maintenance preflight stopped before journal reservation; inspect setup and prepare again");
      }
      throw new Error("Maintenance outcome is unknown; preserve the journal and reconcile, never retry blindly");
    } finally {
      if (typeof material?.stop === "function") {
        try { await material.stop(); } catch {
          console.error("Provider cleanup failed; preserve the maintenance journal");
        }
      }
    }
  });
}

export async function reconcileStandaloneCommitteeTransition(
  directory, requestPath, signingRequestPath, dependencies = {},
) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const attempt = record.maintenanceAttempt;
    if (!attempt) throw new Error("A reserved committee transition is required for reconciliation");
    if (attempt.state === "aborted-before-journal") {
      throw new Error("No maintenance journal was reserved; prepare a new signing request instead");
    }
    const { approval, requestBytes } = await readApprovedCommitteeTransition(record, requestPath, dependencies);
    const signingRequestBytes = await regularBytes(resolve(signingRequestPath));
    const signingRequest = JSON.parse(signingRequestBytes);
    if (sha256(requestBytes) !== attempt.requestSha256
      || sha256(signingRequestBytes) !== attempt.signingRequestSha256
      || signingRequest.updateSha256 !== attempt.updateSha256
      || signingRequest.finalizedBlockHash !== attempt.finalizedBlockHash
      || attempt.journalPath !== join(root, "committee-transition.json")) {
      throw new Error("Maintenance reconciliation disagrees with the reserved signing request");
    }
    setNetworkId("undeployed");
    const result = await (dependencies.reconcile ?? reconcileLocalNetworkCommitteeTransition)({
      approval,
      journal: new FileMaintenanceTransitionJournal(attempt.journalPath),
      approvedUpdateSha256: attempt.updateSha256,
      approvedFinalizedBlockHash: attempt.finalizedBlockHash,
    });
    if (!["not-reserved", "unavailable", "pending", "invalid-image", "stale-checkpoint",
      "unresolved", "conflict", "observed"].includes(result?.status)) {
      throw new Error("Maintenance reconciliation returned an invalid status");
    }
    if ((result.txId !== null && result.txId !== undefined
        && (typeof result.txId !== "string" || result.txId.length === 0 || result.txId.length > 512))
      || (attempt.txId && result.txId && result.txId !== attempt.txId)
      || (result.status === "observed"
        && (!HASH.test(result.finalizedBlockHash) || /^0x0{64}$/u.test(result.finalizedBlockHash)))) {
      throw new Error("Maintenance reconciliation returned evidence inconsistent with the reserved attempt");
    }
    const history = attempt.reconciliationHistory ?? [];
    if (history.length >= 256) {
      throw new Error("Maintenance reconciliation history is full; preserve the setup record for review");
    }
    history.push(result);
    attempt.reconciliationHistory = history;
    if (attempt.state === "recovered-no-journal-approved") {
      if (result.status !== "not-reserved" || result.txId) {
        attempt.state = "conflict";
        attempt.alert = "post-recovery-evidence-contradiction";
      }
    } else if (result.status === "not-reserved") {
      if (attempt.txId || attempt.journalReserved
        || ["observed", "observed-without-receipt", "conflict"].includes(attempt.state)) {
        attempt.alert = "journal-missing-after-submission";
        if (!["observed", "observed-without-receipt"].includes(attempt.state)) attempt.state = "conflict";
      } else {
        attempt.state = "recovery-required-no-journal";
        attempt.alert = "independent-human-recovery-required";
      }
    } else if (attempt.txId && !result.txId) {
      attempt.alert = "journal-submitted-id-missing";
      if (attempt.state !== "observed") attempt.state = "conflict";
    } else if (result.status === "conflict") {
      attempt.alert = "conflict";
      if (attempt.state !== "observed") attempt.state = "conflict";
    } else if (result.status === "stale-checkpoint") {
      attempt.alert = "stale-checkpoint";
      if (!["observed", "conflict"].includes(attempt.state)) attempt.state = "stale-checkpoint";
    } else if (result.status === "observed") {
      if (attempt.state !== "conflict") {
        attempt.state = result.txId ? "observed" : "observed-without-receipt";
      }
    } else if (result.status === "unresolved") {
      if (!["observed", "conflict"].includes(attempt.state)) attempt.state = "unresolved";
    }
    if (result.txId) attempt.txId = result.txId;
    attempt.reconciliation = result;
    await writeRecord(root, record);
    return result;
  });
}

export async function approveStandaloneCommitteeRecovery(
  directory, requestPath, signingRequestPath, documentPath, signaturePath,
  keyringDirectory, expectedFingerprint, dependencies = {},
) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const attempt = record.maintenanceAttempt;
    if (attempt?.state !== "recovery-required-no-journal"
      || attempt.txId || attempt.reportedTxId || attempt.journalReserved
      || attempt.journalPath !== join(root, "committee-transition.json")) {
      throw new Error("Only an unresolved pre-journal crash window can receive recovery approval");
    }
    const journal = new FileMaintenanceTransitionJournal(attempt.journalPath);
    if (await journal.inspect() !== null) {
      throw new Error("Maintenance journal exists; a no-journal recovery decision is forbidden");
    }
    const { approval, requestBytes, catalog } = await readApprovedCommitteeTransition(
      record, requestPath, dependencies,
    );
    const signingRequestBytes = await regularBytes(resolve(signingRequestPath));
    const signingRequest = JSON.parse(signingRequestBytes);
    if (sha256(requestBytes) !== attempt.requestSha256
      || sha256(signingRequestBytes) !== attempt.signingRequestSha256
      || signingRequest.updateSha256 !== attempt.updateSha256
      || signingRequest.finalizedBlockHash !== attempt.finalizedBlockHash
      || signingRequest.expiresAt !== approval.expiresAt.toISOString()) {
      throw new Error("Recovery evidence disagrees with the original approved maintenance attempt");
    }
    const now = (dependencies.now ?? Date.now)();
    const expiredAt = approval.expiresAt.getTime();
    if (!Number.isSafeInteger(now) || !Number.isFinite(expiredAt)
      || now < expiredAt + 10 * 60_000) {
      throw new Error("Original maintenance signing window must expire before recovery approval");
    }
    setNetworkId("undeployed");
    const freshApproval = { ...approval, expiresAt: new Date(now + 5 * 60_000) };
    const fresh = await (dependencies.prepareTransition ?? prepareLocalNetworkCommitteeTransition)(freshApproval);
    if (fresh.networkId !== "undeployed" || fresh.contractAddress !== approval.receipt.contractAddress
      || !HASH.test(fresh.finalizedBlockHash) || /^0x0{64}$/u.test(fresh.finalizedBlockHash)
      || fresh.finalizedBlockHash === attempt.finalizedBlockHash
      || fresh.currentAuthorityCounter !== BigInt(catalog.length - 1)
      || fresh.nextAuthorityCounter !== BigInt(catalog.length)
      || fresh.threshold !== record.committeeApproval.maintenancePolicy.threshold
      || JSON.stringify(fresh.committeeVerifyingKeys)
        !== JSON.stringify(record.committeeApproval.maintenancePolicy.verifyingKeys)
      || fresh.expiresAt !== freshApproval.expiresAt.toISOString()
      || !(fresh.dataToSign instanceof Uint8Array)
      || sha256(fresh.dataToSign) !== attempt.updateSha256) {
      throw new Error("Finalized registry image changed or did not advance after the abandoned attempt");
    }
    const document = await regularBytes(resolve(documentPath));
    const signature = await regularBytes(resolve(signaturePath));
    if (document.length > 32 * 1024 || signature.length > 64 * 1024) {
      throw new Error("Maintenance recovery decision or signature exceeds the bounded evidence size");
    }
    const decision = JSON.parse(document);
    const approvedAt = Date.parse(decision?.approvedAt);
    const reservedAt = Date.parse(attempt.reservedAt);
    if (!exactFields(decision, ["approvedAt", "approvedFinalizedBlockHash", "decision",
      "expiredAt", "format", "requestSha256", "reviewedReference", "reviewerFingerprint",
      "recoveryFinalizedBlockHash", "signingRequestSha256", "sourceRevision", "updateSha256"])
      || decision.format !== "tr-local-maintenance-no-journal-recovery-v1"
      || decision.decision !== "authorize-new-attempt-after-absent-journal"
      || decision.sourceRevision !== record.sourceRevision
      || decision.requestSha256 !== attempt.requestSha256
      || decision.signingRequestSha256 !== attempt.signingRequestSha256
      || decision.updateSha256 !== attempt.updateSha256
      || decision.approvedFinalizedBlockHash !== attempt.finalizedBlockHash
      || !HASH.test(decision.recoveryFinalizedBlockHash)
      || /^0x0{64}$/u.test(decision.recoveryFinalizedBlockHash)
      || decision.recoveryFinalizedBlockHash === attempt.finalizedBlockHash
      || decision.expiredAt !== approval.expiresAt.toISOString()
      || decision.reviewerFingerprint !== expectedFingerprint
      || expectedFingerprint !== record.committeeApproval.reviewerFingerprint
      || typeof decision.reviewedReference !== "string"
      || decision.reviewedReference.length < 8 || decision.reviewedReference.length > 512
      || !Number.isFinite(approvedAt) || !Number.isFinite(reservedAt)
      || approvedAt < expiredAt + 10 * 60_000
      || approvedAt > now + 60_000 || approvedAt < reservedAt) {
      throw new Error("Signed maintenance recovery decision does not bind the expired attempt and approved reviewer");
    }
    const evidence = await verifiedApprovalEvidence(
      root, "maintenance-recovery", document, signature, keyringDirectory,
      expectedFingerprint, dependencies,
    );
    attempt.recoveryApproval = {
      ...evidence, approvedAt: decision.approvedAt,
      reviewedReference: decision.reviewedReference,
      reviewerFinalizedBlockHash: decision.recoveryFinalizedBlockHash,
      recoveryFinalizedBlockHash: fresh.finalizedBlockHash,
    };
    attempt.state = "recovered-no-journal-approved";
    attempt.alert = "human-recovered-no-journal";
    await writeRecord(root, record);
    return {
      state: attempt.state,
      recoveryApprovalSha256: evidence.documentSha256,
      recoveryFinalizedBlockHash: fresh.finalizedBlockHash,
    };
  });
}

export async function standaloneSetupStatus(directory) {
  const { root, record } = await readRecord(directory);
  let lockPresent = false;
  try {
    await lstat(join(root, ".setup.lock"));
    lockPresent = true;
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  return {
    format: FORMAT,
    sourceRevision: record.sourceRevision,
    install: "verified-staged-bytes-only",
    localLedger: record.genesisApproval ? "operator-pinned-reviewer-signature-verified"
      : record.ledgerObservation ? "node-observed-not-independently-approved" : "pending",
    deployment: record.deployment?.state ?? "pending",
    stagedVerifierKeys: Object.entries(record.verifierKeyInsertions ?? {})
      .map(([circuitName, entry]) => ({ circuitName, state: entry.state })),
    setupLock: lockPresent ? "present-inspect-before-removal" : "absent",
    maintenanceApproval: record.committeeApproval ? "roster-signature-verified-transition-pending" : "pending",
    maintenanceTransition: record.maintenanceAttempt?.state ?? "pending",
    maintenanceTransitionAlert: record.maintenanceAttempt?.alert ?? null,
    maintenanceLastReadback: record.maintenanceAttempt?.reconciliation?.status ?? null,
    offlineJourneys: "pending",
    restartRestore: "pending",
    independentReview: "pending",
    releaseQualified: false,
  };
}

async function interactive(directory) {
  const io = createInterface({ input: process.stdin, output: process.stdout });
  try {
    let record;
    try {
      ({ record } = await readRecord(directory));
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
      const bundle = await io.question("Verified install bundle directory: ");
      record = await initializeStandaloneSetup(directory, bundle);
    }
    if (!record.ledgerObservation) {
      const pin = await io.question("Candidate local genesis pin JSON (blank to stop): ");
      if (pin) await observeStandaloneLedger(directory, pin);
    }
    ({ record } = await readRecord(directory));
    if (record.ledgerObservation && !record.genesisApproval) {
      const document = await io.question("Reviewer-signed genesis approval JSON (blank to stop): ");
      if (document) {
        const signature = await io.question("Detached signature file: ");
        const keyring = await io.question("Private local GPG keyring with reviewer public key: ");
        const fingerprint = await io.question("Pinned reviewer signing-key fingerprint (40 uppercase hex): ");
        await approveStandaloneGenesis(directory, document, signature, keyring, fingerprint);
      }
    }
    ({ record } = await readRecord(directory));
    if (record.genesisApproval && !record.committeeApproval) {
      const document = await io.question("Reviewer-signed release committee roster JSON (blank to defer): ");
      if (document) {
        const signature = await io.question("Detached committee signature file: ");
        const keyring = await io.question("Private local GPG keyring with governance reviewer public key: ");
        const fingerprint = await io.question("Pinned governance signing-key fingerprint (40 uppercase hex): ");
        await approveStandaloneCommittee(directory, document, signature, keyring, fingerprint);
      }
    }
    ({ record } = await readRecord(directory));
    if (record.genesisApproval && !record.deployment) {
      const plan = await io.question("Approved deployment plan JSON (blank to stop): ");
      if (plan && await io.question("Type DEPLOY ONCE to reserve one attempt: ") === "DEPLOY ONCE") {
        await attemptStandaloneDeployment(directory, plan);
      }
    }
    console.log(JSON.stringify(await standaloneSetupStatus(directory), null, 2));
  } finally {
    io.close();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, directory, input, signature, keyring, fingerprint, extra, more] = process.argv.slice(2);
  if (!directory || !["run", "init", "observe", "approve-genesis", "approve-committee", "deploy", "reconcile-deploy", "insert-key", "reconcile-key", "prepare-committee", "submit-committee", "reconcile-committee", "approve-committee-recovery", "status"].includes(command)) {
    throw new Error("Usage: node scripts/standalone-setup-wizard.mjs <run|init|observe|approve-genesis|approve-committee|deploy|reconcile-deploy|insert-key|reconcile-key|prepare-committee|submit-committee|reconcile-committee|approve-committee-recovery|status> <private-setup-dir> [inputs]");
  }
  if (command === "run") await interactive(directory);
  else if (command === "init" && input) console.log(JSON.stringify(await initializeStandaloneSetup(directory, input)));
  else if (command === "observe" && input) console.log(JSON.stringify(await observeStandaloneLedger(directory, input)));
  else if (command === "approve-genesis" && input && signature && keyring && fingerprint) {
    console.log(JSON.stringify(await approveStandaloneGenesis(directory, input, signature, keyring, fingerprint)));
  }
  else if (command === "approve-committee" && input && signature && keyring && fingerprint) {
    console.log(JSON.stringify(await approveStandaloneCommittee(directory, input, signature, keyring, fingerprint)));
  }
  else if (command === "deploy" && input) console.log(JSON.stringify(await attemptStandaloneDeployment(directory, input)));
  else if (command === "reconcile-deploy" && input) {
    const result = await reconcileStandaloneDeployment(directory, input);
    console.log(JSON.stringify(result));
    if (result.readbackStatus !== "staged-bootstrap-pending") process.exitCode = 2;
  }
  else if (command === "insert-key" && input) {
    const result = await attemptStandaloneVerifierKeyInsertion(directory, input);
    console.log(JSON.stringify(result));
    if (result.readbackStatus !== "verified") process.exitCode = 2;
  }
  else if (command === "reconcile-key" && input) {
    const result = await reconcileStandaloneVerifierKeyInsertion(directory, input);
    console.log(JSON.stringify(result));
    if (result.readback.status !== "verified") process.exitCode = 2;
  }
  else if (command === "prepare-committee" && input) {
    console.log(JSON.stringify(await prepareStandaloneCommitteeTransition(directory, input), null, 2));
  }
  else if (command === "submit-committee" && input && signature && keyring) {
    console.log(JSON.stringify(await submitStandaloneCommitteeTransition(directory, input, signature, keyring)));
  }
  else if (command === "reconcile-committee" && input && signature) {
    const result = await reconcileStandaloneCommitteeTransition(directory, input, signature);
    console.log(JSON.stringify(result));
    if (result.status !== "observed" || !result.txId) process.exitCode = 2;
  }
  else if (command === "approve-committee-recovery" && input && signature && keyring
    && fingerprint && extra && more) {
    console.log(JSON.stringify(await approveStandaloneCommitteeRecovery(
      directory, input, signature, keyring, fingerprint, extra, more,
    )));
  }
  else if (command === "status") console.log(JSON.stringify(await standaloneSetupStatus(directory), null, 2));
  else throw new Error(`Missing input path for ${command}`);
}
