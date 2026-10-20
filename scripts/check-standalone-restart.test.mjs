import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  captureStandaloneRestartBaseline,
  compareStandaloneRestartSnapshots,
  observeStandaloneRestartSnapshot,
  verifyStandaloneRestart,
} from "./check-standalone-restart.mjs";

const revision = "a".repeat(40);
const genesis = `0x${"1".repeat(64)}`;
const beforeHash = `0x${"2".repeat(64)}`;
const afterHash = `0x${"3".repeat(64)}`;
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
const services = ["node", "indexer", "proof-server"];

function snapshot() {
  return {
    format: "tr-standalone-restart-snapshot-v1",
    project: "tr-standalone-local-restart-test",
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
  const changedObserver = structuredClone(after);
  changedObserver.observerSha256 = "f".repeat(64);
  assert.throws(() => compareStandaloneRestartSnapshots(before, changedObserver), /changed observerSha256/u);
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
      return { project, preparedInputsMatched: true, verifiedImageIdsMatched: true,
        bundleComposeFilesMatched: true };
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
    await observeStandaloneRestartSnapshot(directory, { allowUnpublishedHostPorts: true }, dependencies);
    assert.equal(allowUnpublishedHostPorts, true);
    const baseline = await captureStandaloneRestartBaseline(directory, dependencies);
    assert.equal(allowUnpublishedHostPorts, false);
    assert.equal(baseline.finalizedHash, beforeHash);
    await assert.rejects(captureStandaloneRestartBaseline(directory, dependencies), { code: "EEXIST" });
    restarted = true;
    brokenHistory = true;
    await assert.rejects(verifyStandaloneRestart(directory, dependencies), /lost finalized history/u);
    brokenHistory = false;
    const result = await verifyStandaloneRestart(directory, dependencies);
    assert.equal(result.releaseQualified, false);
    assert.equal(JSON.parse(await readFile(join(directory, "restart-verification.json"), "utf8"))
      .baselineSha256.length, 64);
    await assert.rejects(verifyStandaloneRestart(directory, dependencies), { code: "EEXIST" });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
