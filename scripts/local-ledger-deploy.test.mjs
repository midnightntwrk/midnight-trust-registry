import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { FileDeploymentAttemptJournal } from "@midnight-ntwrk/trust-registry-integration";

import { runLocalDeployment, validateLocalDeploymentPlan } from "./local-ledger-deploy.mjs";

const root = await mkdtemp(join(tmpdir(), "tr-local-deploy-plan-"));
after(() => rm(root, { recursive: true, force: true }));
const sourceRevision = "a".repeat(40);
const modulePath = join(root, "provider.mjs");
const manifestPath = join(root, "manifest.json");
const journalDirectory = join(root, "private");
await mkdir(journalDirectory, { mode: 0o700 });
const moduleSource = `export const createLocalDeploymentMaterial = async () => ({
  bootstrap: { registryId: "test" }, providers: { marker: "provider" },
  contractMaintenanceSigningKey: "private-test-key"
});\n`;
await writeFile(modulePath, moduleSource);
await writeFile(manifestPath, JSON.stringify({
  format: "tr-release-candidate-manifest-v2", sourceRevision, verifierKeySha256: {},
}));
const plan = {
  format: "tr-local-deployment-plan-v1",
  sourceRevision,
  network: {
    networkId: "undeployed",
    rpcUrl: "http://127.0.0.1:29944",
    indexerHttpUrl: "http://127.0.0.1:28088/graphql",
    indexerWsUrl: "ws://127.0.0.1:28088/graphql/ws",
    expectedGenesisHash: `0x${"b".repeat(64)}`,
    allowedHosts: ["127.0.0.1"],
  },
  releaseManifestPath: manifestPath,
  providerModulePath: modulePath,
  providerModuleSha256: createHash("sha256").update(moduleSource).digest("hex"),
  journalPath: join(journalDirectory, "deployment.json"),
};

test("rejects malformed local deployment plans", () => {
  assert.equal(validateLocalDeploymentPlan(plan), plan);
  const staged = { ...plan, format: "tr-local-staged-deployment-plan-v1",
    initialVerifierKeyName: "authorizeMaintainerAuditEvent" };
  assert.equal(validateLocalDeploymentPlan(staged), staged);
  assert.throws(() => validateLocalDeploymentPlan({ ...staged, initialVerifierKeyName: "" }), /exact source/u);
  assert.throws(() => validateLocalDeploymentPlan({ ...plan, initialVerifierKeyName: "authorizeMaintainerAuditEvent" }), /exact source/u);
  assert.throws(() => validateLocalDeploymentPlan({ ...staged, format: plan.format }), /exact source/u);
  assert.throws(() => validateLocalDeploymentPlan({ ...plan, network: {
    ...plan.network, networkId: "preprod",
  } }), /exact source/u);
  assert.throws(() => validateLocalDeploymentPlan({ ...plan, extra: true }), /exact source/u);
  assert.throws(() => validateLocalDeploymentPlan({ ...plan, journalPath: "relative.json" }), /exact source/u);
});

test("staged plan passes its circuit pin without changing the full-plan path", async () => {
  const staged = { ...plan, format: "tr-local-staged-deployment-plan-v1",
    initialVerifierKeyName: "authorizeMaintainerAuditEvent" };
  const result = await runLocalDeployment(staged, {
    validateEndpoints: async () => {},
    observe: async () => {},
    loadProvider: async () => ({ createLocalDeploymentMaterial: async () => ({
      bootstrap: { registryId: "test" }, providers: { marker: "provider" },
      contractMaintenanceSigningKey: "private-test-key",
    }) }),
    deployOnce: async (input) => {
      assert.equal(input.initialVerifierKeyName, staged.initialVerifierKeyName);
      assert.ok(input.journal instanceof FileDeploymentAttemptJournal);
      return { receipt: { networkId: "undeployed", txId: "tx-staged" },
        readback: { status: "staged-bootstrap-pending" } };
    },
  });
  assert.equal(result.readbackStatus, "staged-bootstrap-pending");
});

test("checks module bytes and source before any network or provider call", async () => {
  let called = false;
  const observe = async () => { called = true; };
  await assert.rejects(runLocalDeployment({ ...plan, providerModuleSha256: "c".repeat(64) }, {
    observe,
  }), /module bytes disagree/u);
  assert.equal(called, false);
  await assert.rejects(runLocalDeployment({ ...plan, sourceRevision: "d".repeat(40) }, {
    observe,
  }), /source SHA disagrees/u);
  assert.equal(called, false);
});

test("observes the pinned node before importing the provider and passes only approved inputs", async () => {
  const steps = [];
  const result = await runLocalDeployment(plan, {
    validateEndpoints: async () => { steps.push("endpoints"); },
    observe: async (pin) => {
      steps.push("observe");
      assert.equal(pin.expectedGenesisHash, plan.network.expectedGenesisHash);
      assert.equal(pin.sourceRevision, sourceRevision);
    },
    loadProvider: async (path) => {
      steps.push("load");
      assert.equal(path, modulePath);
      return {
        createLocalDeploymentMaterial: async () => ({
          bootstrap: { registryId: "test" }, providers: { marker: "provider" },
          contractMaintenanceSigningKey: "private-test-key",
          stop: async () => { steps.push("stop"); },
        }),
      };
    },
    deployOnce: async (input) => {
      steps.push("submit");
      assert.equal(input.network, plan.network);
      assert.equal(input.sourceRevision, sourceRevision);
      assert.ok(input.journal instanceof FileDeploymentAttemptJournal);
      return { receipt: { networkId: "undeployed", txId: "tx-1" }, readback: { status: "pending" } };
    },
  });
  assert.deepEqual(steps, ["endpoints", "observe", "load", "submit", "stop"]);
  assert.deepEqual(result, {
    kind: "local-deployment-submission-observation",
    sourceRevision,
    receipt: { networkId: "undeployed", txId: "tx-1" },
    readbackStatus: "pending",
  });
  assert.equal(JSON.stringify(result).includes("private-test-key"), false);
});

test("preflight failure never imports the provider or enters the journal", async () => {
  let loaded = false;
  await assert.rejects(runLocalDeployment(plan, {
    validateEndpoints: async () => {},
    observe: async () => { throw new Error("genesis mismatch"); },
    loadProvider: async () => { loaded = true; },
  }), /genesis mismatch/u);
  assert.equal(loaded, false);
});

test("endpoint rejection prevents preflight and provider import", async () => {
  let observed = false;
  await assert.rejects(runLocalDeployment(plan, {
    validateEndpoints: async () => { throw new Error("invalid endpoint"); },
    observe: async () => { observed = true; },
  }), /invalid endpoint/u);
  assert.equal(observed, false);
});

test("invalid material still closes the provider", async () => {
  let stopped = false;
  await assert.rejects(runLocalDeployment(plan, {
    validateEndpoints: async () => {},
    observe: async () => {},
    loadProvider: async () => ({ createLocalDeploymentMaterial: async () => ({
      stop: async () => { stopped = true; },
    }) }),
  }), /did not return bootstrap/u);
  assert.equal(stopped, true);
});
