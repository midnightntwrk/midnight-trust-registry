#!/usr/bin/env node

import { createHash } from "node:crypto";
import { lstat, open, readFile, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { observeStandaloneRestartSnapshot } from "./check-standalone-restart.mjs";

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

async function readPrivateSnapshot(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size === 0 || stat.size > 1024 * 1024
    || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Restore source must be an owned private regular file");
  }
  return readFile(path);
}

async function writeEvidence(path, value) {
  const file = await open(path, "wx", 0o600);
  try {
    await file.writeFile(`${JSON.stringify(value, null, 2)}\n`);
    await file.sync();
  } finally {
    await file.close();
  }
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
  return {
    kind: "standalone-distinct-project-ledger-readback",
    sourceRevision: source.sourceRevision,
    sourceProject: source.project,
    destinationProject: destination.project,
    sourceFinalizedHeight: source.finalizedHeight,
    destinationFinalizedHeight: destination.finalizedHeight,
    preservedCheckpointHash: source.finalizedHash,
    backupAndCrossHostCustody: "operator-evidence-required",
    contractAndWalletReadback: "not-verified",
    releaseQualified: false,
  };
}

export async function captureStandaloneRestoreSource(directory, dependencies = {}) {
  const root = await privateDirectory(directory);
  const snapshot = await (dependencies.observeSnapshot ?? observeStandaloneRestartSnapshot)(root,
    { allowUnpublishedHostPorts: true });
  if (snapshot?.format !== "tr-standalone-restart-snapshot-v1"
    || !HASH.test(snapshot.finalizedHash ?? "")) {
    throw new Error("Restore source requires a finalized ledger checkpoint");
  }
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
  if (!Number.isSafeInteger(source.finalizedHeight) || source.finalizedHeight < 1) {
    throw new Error("Restore source height is invalid");
  }
  const destination = await (dependencies.observeSnapshot ?? observeStandaloneRestartSnapshot)(destinationRoot, {
    historicalHeight: source.finalizedHeight, allowUnpublishedHostPorts: true,
  });
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
