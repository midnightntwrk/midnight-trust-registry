import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { FileVerifierKeyInsertionJournal } from "@midnight-ntwrk/trust-registry-integration";

import {
  runLocalVerifierKeyInsertion, validateLocalVerifierKeyInsertionPlan,
} from "./local-ledger-insert-verifier-key.mjs";

const root = await mkdtemp(join(tmpdir(), "tr-local-key-plan-"));
after(() => rm(root, { recursive: true, force: true }));
const sourceRevision = "a".repeat(40);
const modulePath = join(root, "provider.mjs");
const manifestPath = join(root, "manifest.json");
const privateDirectory = join(root, "private");
await mkdir(privateDirectory, { mode: 0o700 });
const moduleSource = "export const createLocalDeploymentMaterial = async () => ({});\n";
await writeFile(modulePath, moduleSource);
await writeFile(manifestPath, JSON.stringify({
  format: "tr-release-candidate-manifest-v2", sourceRevision,
  verifierKeySha256: { authorizeMaintainerAuditEvent: "b".repeat(64) },
}));
const plan = {
  format: "tr-local-verifier-key-insertion-plan-v1",
  sourceRevision,
  network: {
    networkId: "undeployed",
    rpcUrl: "http://127.0.0.1:29944",
    indexerHttpUrl: "http://127.0.0.1:28088/graphql",
    indexerWsUrl: "ws://127.0.0.1:28088/graphql/ws",
    expectedGenesisHash: `0x${"c".repeat(64)}`,
    allowedHosts: ["127.0.0.1"],
  },
  releaseManifestPath: manifestPath,
  providerModulePath: modulePath,
  providerModuleSha256: createHash("sha256").update(moduleSource).digest("hex"),
  deploymentJournalPath: join(privateDirectory, "deployment.json"),
  journalPath: join(privateDirectory, "verifier-authorizeMaintainerChange.json"),
  initialVerifierKeyName: "authorizeMaintainerAuditEvent",
  circuitName: "authorizeMaintainerChange",
};

const dependencies = (steps) => ({
  validateEndpoints: async () => { steps.push("endpoints"); },
  observe: async () => { steps.push("genesis"); },
  loadProvider: async () => {
    steps.push("provider");
    return { createLocalDeploymentMaterial: async () => ({
      bootstrap: { registryId: "test" }, providers: { marker: "provider" },
      contractMaintenanceSigningKey: "private-test-key",
      stop: async () => { steps.push("stop"); },
    }) };
  },
  inspectDeployment: async (intent) => {
    steps.push("deployment-journal");
    assert.equal(intent.initialVerifierKeyName, plan.initialVerifierKeyName);
    assert.equal(intent.sourceRevision, sourceRevision);
    return {
      reservation: { bootstrapMaintenanceVerifyingKey: `0x${"d".repeat(64)}` },
      submitted: {
        version: 1, networkId: "undeployed", contractAddress: `0x${"e".repeat(64)}`,
        txId: "deploy-tx", blockHash: `0x${"f".repeat(64)}`, blockHeight: 10,
      },
    };
  },
});

test("rejects malformed or shared-journal insertion plans", () => {
  assert.equal(validateLocalVerifierKeyInsertionPlan(plan), plan);
  assert.throws(() => validateLocalVerifierKeyInsertionPlan({ ...plan, extra: true }), /exact local/u);
  assert.throws(() => validateLocalVerifierKeyInsertionPlan({ ...plan, network: {
    ...plan.network, networkId: "preprod",
  } }), /exact source/u);
  assert.throws(() => validateLocalVerifierKeyInsertionPlan({
    ...plan, journalPath: plan.deploymentJournalPath,
  }), /fixed per-circuit journal/u);
});

test("checks source and provider bytes before network or provider access", async () => {
  const steps = [];
  await assert.rejects(runLocalVerifierKeyInsertion({
    ...plan, providerModuleSha256: "0".repeat(64),
  }, dependencies(steps)), /module bytes disagree/u);
  await assert.rejects(runLocalVerifierKeyInsertion({
    ...plan, sourceRevision: "d".repeat(40),
  }, dependencies(steps)), /source SHA disagrees/u);
  assert.deepEqual(steps, []);
});

test("submits only after approved staged receipt and routes reconciliation without submission", async () => {
  const steps = [];
  const deps = dependencies(steps);
  deps.submit = async (input) => {
    steps.push("submit");
    assert.ok(input.journal instanceof FileVerifierKeyInsertionJournal);
    assert.equal(input.receipt.txId, "deploy-tx");
    assert.equal(input.bootstrapMaintenanceVerifyingKey, `0x${"d".repeat(64)}`);
    assert.equal(input.contractMaintenanceSigningKey, "private-test-key");
    return { receipt: { txId: "insert-tx" }, readback: "pending" };
  };
  deps.reconcile = async () => {
    steps.push("reconcile");
    return { status: "observed-without-receipt" };
  };
  const submitted = await runLocalVerifierKeyInsertion(plan, deps);
  assert.deepEqual(steps, ["endpoints", "genesis", "provider", "deployment-journal", "submit", "stop"]);
  assert.equal(submitted.readbackStatus, "pending");
  steps.length = 0;
  const reconciled = await runLocalVerifierKeyInsertion(plan, deps, "reconcile");
  assert.deepEqual(steps, ["endpoints", "genesis", "provider", "deployment-journal", "reconcile", "stop"]);
  assert.deepEqual(reconciled.readback, { status: "observed-without-receipt" });
});

test("missing staged receipt stops before insertion and still closes provider", async () => {
  const steps = [];
  const deps = dependencies(steps);
  deps.inspectDeployment = async () => {
    steps.push("deployment-journal");
    return { reservation: {}, submitted: null };
  };
  deps.submit = async () => { steps.push("submit"); };
  await assert.rejects(runLocalVerifierKeyInsertion(plan, deps), /finalized staged deployment receipt/u);
  assert.deepEqual(steps, ["endpoints", "genesis", "provider", "deployment-journal", "stop"]);
});

test("wizard approval rejects changed manifest or deployment receipt before insertion", async () => {
  const steps = [];
  const deps = dependencies(steps);
  deps.submit = async () => { steps.push("submit"); };
  const manifestSha256 = createHash("sha256").update(await readFile(manifestPath)).digest("hex");
  const expectedDeploymentReceipt = {
    networkId: "undeployed", contractAddress: `0x${"e".repeat(64)}`,
    txId: "deploy-tx", blockHash: `0x${"f".repeat(64)}`, blockHeight: 10,
  };
  await assert.rejects(runLocalVerifierKeyInsertion(plan, deps, "submit", {
    expectedReleaseManifestSha256: "0".repeat(64), expectedDeploymentReceipt,
  }), /manifest bytes changed/u);
  assert.deepEqual(steps, []);
  await assert.rejects(runLocalVerifierKeyInsertion(plan, deps, "submit", {
    expectedReleaseManifestSha256: manifestSha256,
    expectedDeploymentReceipt: { ...expectedDeploymentReceipt, contractAddress: `0x${"1".repeat(64)}` },
  }), /journal receipt disagrees/u);
  assert.deepEqual(steps, ["endpoints", "genesis", "provider", "deployment-journal", "stop"]);
  assert.equal(steps.includes("submit"), false);
  steps.length = 0;
  deps.submit = async () => {
    steps.push("submit");
    return { receipt: { txId: "insert-tx" }, readback: "verified" };
  };
  const result = await runLocalVerifierKeyInsertion(plan, deps, "submit", {
    expectedReleaseManifestSha256: manifestSha256, expectedDeploymentReceipt,
  });
  assert.equal(result.readbackStatus, "verified");
  assert.deepEqual(steps, ["endpoints", "genesis", "provider", "deployment-journal", "submit", "stop"]);
});
