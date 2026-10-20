import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  captureStandaloneRestoreSource,
  compareStandaloneRestoreSnapshots,
  verifyStandaloneRestore,
} from "./check-standalone-restore.mjs";

const sourceHash = `0x${"1".repeat(64)}`;
const destinationHash = `0x${"2".repeat(64)}`;
const genesisHash = `0x${"3".repeat(64)}`;

function snapshots() {
  const source = {
    format: "tr-standalone-restart-snapshot-v1",
    sourceRevision: "a".repeat(40), observerSha256: "b".repeat(64),
    installInventorySha256: "c".repeat(64), stackEnvSha256: "d".repeat(64),
    project: "tr-standalone-local-source", networkId: "source-network-id",
    genesisHash, finalizedHeight: 42, finalizedHash: sourceHash,
    containers: Object.fromEntries(["node", "indexer", "proof-server"]
      .map((service) => [service, { id: `source-${service}` }])),
  };
  const destination = {
    ...structuredClone(source),
    project: "tr-standalone-local-destination", networkId: "destination-network-id",
    finalizedHeight: 43, finalizedHash: destinationHash, historicalHash: sourceHash,
    containers: Object.fromEntries(["node", "indexer", "proof-server"]
      .map((service) => [service, { id: `destination-${service}` }])),
  };
  return { source, destination };
}

test("restore comparison requires a distinct pinned ledger retaining finalized history", () => {
  const { source, destination } = snapshots();
  const result = compareStandaloneRestoreSnapshots(source, destination);
  assert.equal(result.preservedCheckpointHash, sourceHash);
  assert.equal(result.releaseQualified, false);
  assert.equal(result.contractAndWalletReadback, "not-verified");
  assert.equal(result.deploymentEvidence, "pre-deployment-or-unbound-smoke");
  const recorded = structuredClone(source);
  const restored = structuredClone(destination);
  recorded.setupDeployment = { state: "observed", contractAddress: `0x${"4".repeat(64)}`,
    readbackStatus: "staged-bootstrap-pending", validReceipt: true };
  restored.setupDeployment = structuredClone(recorded.setupDeployment);
  assert.equal(compareStandaloneRestoreSnapshots(recorded, restored).deploymentEvidence,
    "matching-setup-records-ledger-only");
  restored.setupDeployment.readbackStatus = "mismatch";
  assert.equal(compareStandaloneRestoreSnapshots(recorded, restored).deploymentEvidence,
    "pre-deployment-or-unbound-smoke");
  assert.throws(() => compareStandaloneRestoreSnapshots(source,
    { ...destination, finalizedHash: "invalid" }), /checkpoint is malformed/u);
  assert.throws(() => compareStandaloneRestoreSnapshots(source,
    { ...destination, networkId: "" }), /checkpoint is malformed/u);
  for (const changed of [
    { ...destination, project: source.project },
    { ...destination, networkId: source.networkId },
  ]) {
    assert.throws(() => compareStandaloneRestoreSnapshots(source, changed), /distinct isolated project/u);
  }
  for (const key of ["sourceRevision", "observerSha256", "installInventorySha256", "genesisHash"]) {
    assert.throws(() => compareStandaloneRestoreSnapshots(source, { ...destination, [key]: "changed" }),
      new RegExp(`changed ${key}`, "u"));
  }
  assert.throws(() => compareStandaloneRestoreSnapshots(source,
    { ...destination, historicalHash: destinationHash }), /lost finalized history/u);
  assert.throws(() => compareStandaloneRestoreSnapshots(source,
    { ...destination, finalizedHeight: source.finalizedHeight }), /finality did not progress/u);
  const reused = structuredClone(destination);
  reused.containers.indexer.id = source.containers.indexer.id;
  assert.throws(() => compareStandaloneRestoreSnapshots(source, reused), /isolate the indexer/u);
});

test("capture and verify write private, non-overwriting, ledger-only evidence", async () => {
  const sourceDirectory = await mkdtemp(join(tmpdir(), "tr-restore-source-"));
  const destinationDirectory = await mkdtemp(join(tmpdir(), "tr-restore-destination-"));
  const { source, destination } = snapshots();
  try {
    const record = { format: "tr-standalone-setup-v1", sourceRevision: source.sourceRevision,
      install: { inventorySha256: source.installInventorySha256 },
      stack: { project: source.project, envFileSha256: source.stackEnvSha256 } };
    await writeFile(join(sourceDirectory, "setup-record.json"), JSON.stringify(record), { mode: 0o600 });
    const capture = await captureStandaloneRestoreSource(sourceDirectory, {
      observeSnapshot: async (_directory, options) => {
        assert.equal(options.allowUnpublishedHostPorts, true);
        return source;
      },
    });
    assert.equal(capture.releaseQualified, false);
    await assert.rejects(captureStandaloneRestoreSource(sourceDirectory,
      { observeSnapshot: async () => source }), { code: "EEXIST" });
    await assert.rejects(verifyStandaloneRestore(sourceDirectory, sourceDirectory,
      { observeSnapshot: async () => destination }), /different setup directory/u);
    const wrongRecord = { ...record, stack: { ...record.stack, project: "another-project" } };
    await writeFile(join(sourceDirectory, "setup-record.json"), JSON.stringify(wrongRecord));
    await assert.rejects(verifyStandaloneRestore(sourceDirectory, destinationDirectory,
      { observeSnapshot: async () => destination }), /not bound to the source setup/u);
    await writeFile(join(sourceDirectory, "setup-record.json"), JSON.stringify(record));
    const markedSource = { ...source, setupDeployment: { state: "unknown", contractAddress: null,
      readbackStatus: null, validReceipt: false } };
    await writeFile(capture.sourcePath, JSON.stringify(markedSource));
    await assert.rejects(verifyStandaloneRestore(sourceDirectory, destinationDirectory,
      { observeSnapshot: async () => destination }), /not bound to the source setup/u);
    await writeFile(capture.sourcePath, JSON.stringify(source));
    const result = await verifyStandaloneRestore(sourceDirectory, destinationDirectory, {
      observeSnapshot: async (_directory, options) => {
        assert.equal(options.historicalHeight, 42);
        return destination;
      },
    });
    assert.equal(result.destinationFinalizedHeight, 43);
    const evidence = JSON.parse(await readFile(join(destinationDirectory, "restore-destination.json"), "utf8"));
    assert.equal(evidence.destination.historicalHash, sourceHash);
    assert.match(evidence.sourceSnapshotSha256, /^[0-9a-f]{64}$/u);
    await assert.rejects(verifyStandaloneRestore(sourceDirectory, destinationDirectory,
      { observeSnapshot: async () => destination }), { code: "EEXIST" });
    await chmod(capture.sourcePath, 0o644);
    await assert.rejects(verifyStandaloneRestore(sourceDirectory, destinationDirectory,
      { observeSnapshot: async () => destination }), /private regular file/u);
  } finally {
    await rm(sourceDirectory, { recursive: true, force: true });
    await rm(destinationDirectory, { recursive: true, force: true });
  }
});
