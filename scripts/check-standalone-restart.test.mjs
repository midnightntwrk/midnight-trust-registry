import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  captureStandaloneRestartBaseline,
  compareStandaloneRestartSnapshots,
  deploymentMarkerFromRecord,
  observeStandaloneRestartSnapshot,
  readStandaloneRestartEvidence,
  verifyStandaloneRestart,
} from "./check-standalone-restart.mjs";

const revision = "a".repeat(40);
const genesis = `0x${"1".repeat(64)}`;
const beforeHash = `0x${"2".repeat(64)}`;
const afterHash = `0x${"3".repeat(64)}`;
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const services = ["node", "indexer", "proof-server"];

test("deployment marker requires a valid reconciled staged-bootstrap receipt", () => {
  const receipt = { networkId: "undeployed", contractAddress: `0x${"4".repeat(64)}`,
    blockHash: `0x${"5".repeat(64)}`, txId: "local-tx", blockHeight: 12 };
  const record = { deployment: { state: "observed", result: {
    receipt, readbackStatus: "staged-bootstrap-pending" } } };
  assert.deepEqual(deploymentMarkerFromRecord(record), { state: "observed",
    contractAddress: receipt.contractAddress, readbackStatus: "staged-bootstrap-pending",
    validReceipt: true });
  assert.equal(deploymentMarkerFromRecord({ deployment: { state: "observed", result: {
    receipt: { ...receipt, contractAddress: `0x${"0".repeat(64)}` },
    readbackStatus: "staged-bootstrap-pending" } } }).validReceipt, false);
});

function snapshot() {
  return {
    format: "tr-standalone-restart-snapshot-v1",
    project: "tr-standalone-local-restart-test",
    networkId: "ledger-id",
    hostPortAccess: "unpublished-install-access-required",
    sourceRevision: revision,
    observerSha256: "a".repeat(64),
    installInventorySha256: "b".repeat(64),
    stackEnvSha256: "c".repeat(64),
    genesisHash: genesis,
    finalizedHeight: 11,
    finalizedHash: beforeHash,
    volumes: { node: "2026-10-20T00:00:00Z", indexer: "2026-10-20T00:00:00Z" },
    containers: Object.fromEntries(services.map((service) =>
      [service, { id: `${service}-id`, startedAt: "2026-10-20T00:00:00Z" }])),
  };
}

test("requires every service restart, intact volumes, and finalized history", () => {
  const before = snapshot();
  const after = structuredClone(before);
  after.finalizedHeight = 12;
  after.finalizedHash = afterHash;
  after.historicalHash = beforeHash;
  for (const service of services) after.containers[service].startedAt = "2026-10-20T00:01:00Z";
  const result = compareStandaloneRestartSnapshots(before, after);
  assert.equal(result.releaseQualified, false);
  assert.equal(result.deploymentEvidence, undefined);
  assert.equal(result.crossHostRestore, "not-run");
  assert.equal(result.preservedCheckpointHash, beforeHash);
  for (const service of services) {
    const unchanged = structuredClone(after);
    unchanged.containers[service].startedAt = before.containers[service].startedAt;
    assert.throws(() => compareStandaloneRestartSnapshots(before, unchanged), /did not advance/u);
  }
  const reset = structuredClone(after);
  reset.historicalHash = afterHash;
  assert.throws(() => compareStandaloneRestartSnapshots(before, reset), /lost finalized history/u);
  const staticHead = structuredClone(after);
  staticHead.finalizedHeight = before.finalizedHeight;
  assert.throws(() => compareStandaloneRestartSnapshots(before, staticHead), /finality did not progress/u);
  const replaced = structuredClone(after);
  replaced.volumes.node = "2026-10-20T00:02:00Z";
  assert.throws(() => compareStandaloneRestartSnapshots(before, replaced), /replaced node/u);
  const recreated = structuredClone(after);
  recreated.containers.node.id = "different-container";
  assert.throws(() => compareStandaloneRestartSnapshots(before, recreated), /replaced node container/u);
  const changedSource = structuredClone(after);
  changedSource.sourceRevision = "f".repeat(40);
  assert.throws(() => compareStandaloneRestartSnapshots(before, changedSource), /changed sourceRevision/u);
  const changedNetwork = structuredClone(after);
  changedNetwork.networkId = "replacement-ledger";
  assert.throws(() => compareStandaloneRestartSnapshots(before, changedNetwork), /changed networkId/u);
  const changedAccess = structuredClone(after);
  changedAccess.hostPortAccess = "effective-loopback";
  assert.throws(() => compareStandaloneRestartSnapshots(before, changedAccess), /changed hostPortAccess/u);
  const changedObserver = structuredClone(after);
  changedObserver.observerSha256 = "f".repeat(64);
  assert.throws(() => compareStandaloneRestartSnapshots(before, changedObserver), /changed observerSha256/u);
  const recordedBefore = { ...before, setupDeployment: { state: "observed",
    contractAddress: `0x${"4".repeat(64)}`, readbackStatus: "staged-bootstrap-pending",
    validReceipt: true } };
  const recordedAfter = { ...after, setupDeployment: structuredClone(recordedBefore.setupDeployment) };
  assert.equal(compareStandaloneRestartSnapshots(recordedBefore, recordedAfter).deploymentEvidence,
    "setup-recorded-deployment-ledger-only");
  const mismatch = structuredClone(recordedBefore);
  mismatch.setupDeployment.readbackStatus = "mismatch";
  assert.equal(compareStandaloneRestartSnapshots(mismatch,
    { ...after, setupDeployment: structuredClone(mismatch.setupDeployment) }).deploymentEvidence,
  "deployment-state-observed-unbound");
  const unknown = { ...before, setupDeployment: { state: "unknown", contractAddress: null } };
  assert.equal(compareStandaloneRestartSnapshots(unknown,
    { ...after, setupDeployment: structuredClone(unknown.setupDeployment) }).deploymentEvidence,
  "deployment-state-unknown-unbound");
  const legacyObserved = { ...before, setupDeployment: { state: "observed",
    contractAddress: `0x${"4".repeat(64)}` } };
  assert.equal(compareStandaloneRestartSnapshots(legacyObserved,
    { ...after, setupDeployment: structuredClone(legacyObserved.setupDeployment) }).deploymentEvidence,
  "deployment-state-observed-unbound");
  recordedAfter.setupDeployment.state = "unknown";
  assert.throws(() => compareStandaloneRestartSnapshots(recordedBefore, recordedAfter),
    /setup deployment record changed/u);
});

test("captures private immutable baseline and verifies a restarted local ledger bridge", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-restart-"));
  const bundle = join(root, "bundle");
  const directory = join(root, "private");
  await mkdir(bundle);
  await mkdir(directory, { mode: 0o700 });
  const canonicalBundle = await realpath(bundle);
  const inventory = Buffer.from("{}\n");
  const composeHash = "d".repeat(64);
  const offlineHash = "e".repeat(64);
  const project = "tr-standalone-local-restart-test";
  const env = Buffer.from([
    `TR_STACK_NAME=${project}`,
    `COMPOSE_PROJECT_NAME=${project}`,
    "TR_NODE_PORT=49944", "TR_INDEXER_PORT=48088", "TR_PROOF_PORT=46300",
    `TR_PROOF_PARAMS_DIR=${JSON.stringify(join(canonicalBundle, "proof-params"))}`,
    `TR_INDEXER_PASSWORD=${"a".repeat(48)}`,
    `TR_INDEXER_SECRET=${"b".repeat(64)}`,
    "",
  ].join("\n"));
  const record = {
    sourceRevision: revision,
    install: { bundle: canonicalBundle, inventorySha256: digest(inventory) },
    stack: { project, ports: { node: "49944", indexer: "48088", "proof-server": "46300" },
      envFileSha256: digest(env), composeSha256: composeHash, offlineComposeSha256: offlineHash,
      state: "observed-ledger-bridge-only", observation: { observedAt: "2026-10-20T00:00:00Z" } },
  };
  await writeFile(join(bundle, "install-inventory.json"), inventory);
  await writeFile(join(directory, "stack.env"), env, { mode: 0o600 });
  await writeFile(join(directory, "setup-record.json"), JSON.stringify(record), { mode: 0o600 });
  let restarted = false;
  let brokenHistory = false;
  let allowUnpublishedHostPorts;
  const dependencies = {
    verifyBundle: async () => ({ sourceRevision: revision,
      runtimeComposeSha256: composeHash, runtimeOfflineComposeSha256: offlineHash,
      images: services.map((role) => ({ role, reference: `example/${role}@sha256:${"f".repeat(64)}`,
        acceptedIds: [`sha256:${"f".repeat(64)}`] })) }),
    observeTopology: async (config, expected) => {
      assert.equal(config.project, project);
      assert.equal(expected.requirePrivateInputs, true);
      assert.equal(expected.images.length, 3);
      allowUnpublishedHostPorts = expected.allowUnpublishedHostPorts;
      return { project, networkId: "ledger-id", internalNetworkOnly: true,
        hostPortAccess: "unpublished-install-access-required", preparedInputsMatched: true,
        verifiedImageIdsMatched: true, bundleComposeFilesMatched: true };
    },
    command: async (_name, args) => {
      if (args[0] === "ps") {
        const service = args.at(-1).split("=").at(-1);
        return { stdout: `${service}-id\n` };
      }
      if (args[0] === "inspect") {
        return { stdout: JSON.stringify({ Running: true, Paused: false,
          StartedAt: restarted ? "2026-10-20T00:01:00Z" : "2026-10-20T00:00:00Z" }) };
      }
      if (args[0] === "volume") return { stdout: "2026-10-20T00:00:00Z\n" };
      throw new Error(`Unexpected Docker call: ${args.join(" ")}`);
    },
    rpc: async (method, params) => {
      if (method === "chain_getFinalizedHead") return restarted ? afterHash : beforeHash;
      if (method === "chain_getHeader") return { number: restarted ? "0xc" : "0xb" };
      if (method === "chain_getBlockHash") {
        if (params[0] === 0) return genesis;
        if (params[0] === 11) return brokenHistory ? afterHash : beforeHash;
        if (params[0] === 12) return afterHash;
      }
      throw new Error(`Unexpected RPC call: ${method}`);
    },
  };
  try {
    const expected = { sourceRevision: revision, installInventorySha256: digest(inventory), project };
    assert.deepEqual(await readStandaloneRestartEvidence(directory, expected), { status: "pending" });
    await observeStandaloneRestartSnapshot(directory, { allowUnpublishedHostPorts: true }, dependencies);
    assert.equal(allowUnpublishedHostPorts, true);
    const baseline = await captureStandaloneRestartBaseline(directory, dependencies);
    assert.equal(allowUnpublishedHostPorts, true);
    assert.equal(baseline.finalizedHash, beforeHash);
    const baselineRecord = JSON.parse(await readFile(baseline.baselinePath, "utf8"));
    assert.equal(baselineRecord.networkId, "ledger-id");
    assert.equal(baselineRecord.hostPortAccess, "unpublished-install-access-required");
    assert.deepEqual(await readStandaloneRestartEvidence(directory, expected),
      { status: "baseline-captured-verification-pending" });
    await assert.rejects(readStandaloneRestartEvidence(directory,
      { ...expected, project: "another-project" }), /not bound to this setup/u);
    await assert.rejects(captureStandaloneRestartBaseline(directory, dependencies), { code: "EEXIST" });
    restarted = true;
    brokenHistory = true;
    await assert.rejects(verifyStandaloneRestart(directory, dependencies), /lost finalized history/u);
    brokenHistory = false;
    const result = await verifyStandaloneRestart(directory, dependencies);
    assert.equal(result.releaseQualified, false);
    assert.equal(result.deploymentEvidence, "pre-deployment-smoke");
    assert.equal(JSON.parse(await readFile(join(directory, "restart-verification.json"), "utf8"))
      .baselineSha256.length, 64);
    assert.deepEqual(await readStandaloneRestartEvidence(directory, expected), {
      status: "self-attested-ledger-bridge-only", deploymentEvidence: "pre-deployment-smoke",
      beforeFinalizedHeight: 11, afterFinalizedHeight: 12,
    });
    const verificationPath = join(directory, "restart-verification.json");
    const verificationBytes = await readFile(verificationPath);
    const forged = JSON.parse(verificationBytes);
    forged.baselineSha256 = "f".repeat(64);
    await writeFile(verificationPath, JSON.stringify(forged));
    await assert.rejects(readStandaloneRestartEvidence(directory, expected), /does not match/u);
    await writeFile(verificationPath, verificationBytes);
    await assert.rejects(verifyStandaloneRestart(directory, dependencies), { code: "EEXIST" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
