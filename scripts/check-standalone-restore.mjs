#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import { link, lstat, open, readFile, realpath, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { deploymentMarkerFromRecord, observeStandaloneRestartSnapshot,
  setupDeploymentMarker } from "./check-standalone-restart.mjs";

const SOURCE = "restore-source.json";
const DESTINATION = "restore-destination.json";
const HASH = /^0x[0-9a-f]{64}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

async function privateDirectory(directory) {
  const root = await realpath(resolve(directory));
  const stat = await lstat(root);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Restore evidence requires an owned mode-0700 setup directory");
  }
  return root;
}

async function readPrivateSnapshot(path, maxBytes = 1024 * 1024) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size === 0 || stat.size > maxBytes
    || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Restore source must be an owned private regular file");
  }
  return readFile(path);
}

async function writeEvidence(path, value) {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const file = await open(temporary, "wx", 0o600);
  try {
    try {
      await file.writeFile(`${JSON.stringify(value, null, 2)}\n`);
      await file.sync();
    } finally {
      await file.close();
    }
    await link(temporary, path);
  } finally {
    await unlink(temporary).catch(() => {});
  }
}

function deployedCheckpoint(marker) {
  return marker.state === "observed"
    && marker.readbackStatus === "staged-bootstrap-pending"
    && marker.validReceipt === true && marker.contractAddress !== null;
}

async function assertSetupBoundSnapshot(root, snapshot, requireDeployment, expectedReceiptHeight) {
  const record = JSON.parse(await readPrivateSnapshot(join(root, "setup-record.json"), 16 * 1024 * 1024));
  const marker = setupDeploymentMarker(snapshot);
  if (record.format !== "tr-standalone-setup-v1"
    || snapshot.project !== record.stack?.project
    || snapshot.sourceRevision !== record.sourceRevision
    || snapshot.installInventorySha256 !== record.install?.inventorySha256
    || snapshot.stackEnvSha256 !== record.stack?.envFileSha256
    || JSON.stringify(marker) !== JSON.stringify(deploymentMarkerFromRecord(record))) {
    throw new Error("Restore checkpoint is not bound to its setup record");
  }
  if (!Number.isSafeInteger(snapshot.finalizedHeight) || snapshot.finalizedHeight < 1
    || (deployedCheckpoint(marker)
      && record.deployment.result.receipt.blockHeight > snapshot.finalizedHeight)
    || (requireDeployment && (!deployedCheckpoint(marker)
      || record.deployment.result.receipt.blockHeight !== expectedReceiptHeight
      || snapshot.historicalHash !== record.deployment.result.receipt.blockHash))) {
    throw new Error("Restore checkpoint requires a setup-recorded deployment at a finalized height");
  }
}

async function sourceDeploymentHeight(root) {
  const record = JSON.parse(await readPrivateSnapshot(join(root, "setup-record.json"), 16 * 1024 * 1024));
  const marker = deploymentMarkerFromRecord(record);
  const height = record.deployment?.result?.receipt?.blockHeight;
  if (!deployedCheckpoint(marker) || !Number.isSafeInteger(height) || height < 1) {
    throw new Error("Restore source requires a setup-recorded deployment above genesis");
  }
  return height;
}

export function compareStandaloneRestoreSnapshots(source, destination) {
  if (source?.format !== "tr-standalone-restart-snapshot-v1"
    || destination?.format !== source.format
    || !/^[0-9a-f]{40}$/u.test(source.sourceRevision ?? "")
    || !HASH.test(source.genesisHash ?? "")
    || !HASH.test(source.finalizedHash ?? "")
    || !HASH.test(destination.finalizedHash ?? "")
    || !SHA256.test(source.installInventorySha256 ?? "")
    || !SHA256.test(source.observerSha256 ?? "")
    || !Number.isSafeInteger(source.finalizedHeight) || source.finalizedHeight < 1
    || typeof source.project !== "string" || source.project.length === 0
    || typeof source.networkId !== "string" || source.networkId.length === 0
    || typeof destination.project !== "string" || destination.project.length === 0
    || typeof destination.networkId !== "string" || destination.networkId.length === 0) {
    throw new Error("Restore checkpoint is malformed");
  }
  for (const key of ["sourceRevision", "observerSha256", "installInventorySha256", "genesisHash"]) {
    if (destination[key] !== source[key]) throw new Error(`Restore changed ${key}`);
  }
  if (destination.project === source.project || destination.networkId === source.networkId) {
    throw new Error("Restore readback requires a distinct isolated project and ledger network");
  }
  if (destination.historicalHash !== source.finalizedHash
    || !Number.isSafeInteger(destination.finalizedHeight)
    || destination.finalizedHeight <= source.finalizedHeight) {
    throw new Error("Restore lost finalized history or finality did not progress");
  }
  for (const service of ["node", "indexer", "proof-server"]) {
    if (!source.containers?.[service]?.id || !destination.containers?.[service]?.id
      || destination.containers[service].id === source.containers[service].id) {
      throw new Error(`Restore did not isolate the ${service} container`);
    }
  }
  const sourceDeployment = setupDeploymentMarker(source);
  const destinationDeployment = setupDeploymentMarker(destination);
  return {
    kind: "standalone-distinct-project-ledger-readback",
    sourceRevision: source.sourceRevision,
    sourceProject: source.project,
    destinationProject: destination.project,
    sourceFinalizedHeight: source.finalizedHeight,
    destinationFinalizedHeight: destination.finalizedHeight,
    preservedCheckpointHash: source.finalizedHash,
    deploymentEvidence: sourceDeployment.state === "observed"
      && destinationDeployment.state === "observed"
      && sourceDeployment.readbackStatus === "staged-bootstrap-pending"
      && destinationDeployment.readbackStatus === "staged-bootstrap-pending"
      && sourceDeployment.validReceipt === true
      && destinationDeployment.validReceipt === true
      && sourceDeployment.contractAddress !== null
      && sourceDeployment.contractAddress === destinationDeployment.contractAddress
      ? "matching-setup-records-ledger-only" : "pre-deployment-or-unbound-smoke",
    backupAndCrossHostCustody: "operator-evidence-required",
    contractAndWalletReadback: "not-verified",
    releaseQualified: false,
  };
}

export async function captureStandaloneRestoreSource(directory, dependencies = {}) {
  const root = await privateDirectory(directory);
  const receiptHeight = await sourceDeploymentHeight(root);
  const snapshot = await (dependencies.observeSnapshot ?? observeStandaloneRestartSnapshot)(root,
    { historicalHeight: receiptHeight, allowUnpublishedHostPorts: true });
  if (snapshot?.format !== "tr-standalone-restart-snapshot-v1"
    || !HASH.test(snapshot.finalizedHash ?? "")) {
    throw new Error("Restore source requires a finalized ledger checkpoint");
  }
  await assertSetupBoundSnapshot(root, snapshot, true, receiptHeight);
  await writeEvidence(join(root, SOURCE), snapshot);
  return { sourcePath: join(root, SOURCE), project: snapshot.project,
    finalizedHeight: snapshot.finalizedHeight, finalizedHash: snapshot.finalizedHash,
    releaseQualified: false };
}

export async function verifyStandaloneRestore(sourceDirectory, destinationDirectory, dependencies = {}) {
  const sourceRoot = await privateDirectory(sourceDirectory);
  const destinationRoot = await privateDirectory(destinationDirectory);
  if (sourceRoot === destinationRoot) throw new Error("Restore destination must use a different setup directory");
  const sourceBytes = await readPrivateSnapshot(join(sourceRoot, SOURCE));
  const source = JSON.parse(sourceBytes);
  await assertSetupBoundSnapshot(sourceRoot, source, true,
    await sourceDeploymentHeight(sourceRoot));
  if (!Number.isSafeInteger(source.finalizedHeight) || source.finalizedHeight < 1) {
    throw new Error("Restore source height is invalid");
  }
  const destination = await (dependencies.observeSnapshot ?? observeStandaloneRestartSnapshot)(destinationRoot, {
    historicalHeight: source.finalizedHeight, allowUnpublishedHostPorts: true,
  });
  await assertSetupBoundSnapshot(destinationRoot, destination, false);
  const result = compareStandaloneRestoreSnapshots(source, destination);
  await writeEvidence(join(destinationRoot, DESTINATION), {
    ...result, observedAt: new Date().toISOString(),
    sourceSnapshotSha256: createHash("sha256").update(sourceBytes).digest("hex"),
    destination,
  });
  return result;
}

if (process.argv[1] && await realpath(resolve(process.argv[1])) === fileURLToPath(import.meta.url)) {
  const [action, source, destination] = process.argv.slice(2);
  if ((action === "capture" && process.argv.length !== 4)
    || (action === "verify" && process.argv.length !== 5)
    || !["capture", "verify"].includes(action)) {
    throw new Error("Usage: node scripts/check-standalone-restore.mjs <capture setup-dir|verify source-dir destination-dir>");
  }
  const result = action === "capture"
    ? await captureStandaloneRestoreSource(source)
    : await verifyStandaloneRestore(source, destination);
  console.log(JSON.stringify(result));
}
