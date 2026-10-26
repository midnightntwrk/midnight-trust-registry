import assert from "node:assert/strict";
import { lstat, mkdtemp, mkdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  attemptStandaloneDeployment,
  initializeStandaloneSetup,
  observeStandaloneLedger,
  standaloneSetupStatus,
} from "./standalone-setup-wizard.mjs";

const sourceRevision = "a".repeat(40);
const expectedGenesisHash = `0x${"b".repeat(64)}`;
const pin = {
  format: "tr-local-ledger-pin-v1",
  networkId: "undeployed",
  sourceRevision,
  rpcUrl: "http://127.0.0.1:29944",
  expectedGenesisHash,
  allowedHosts: ["127.0.0.1"],
};
const plan = {
  format: "tr-local-deployment-plan-v1",
  sourceRevision,
  network: {
    networkId: "undeployed",
    rpcUrl: pin.rpcUrl,
    indexerHttpUrl: "http://127.0.0.1:28088/api/v4/graphql",
    indexerWsUrl: "ws://127.0.0.1:28088/api/v4/graphql/ws",
    expectedGenesisHash,
    allowedHosts: ["127.0.0.1"],
  },
  releaseManifestPath: "/private/release-manifest.json",
  providerModulePath: "/private/provider.mjs",
  providerModuleSha256: "c".repeat(64),
  journalPath: "/private/deployment-attempt.json",
};

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "tr-wizard-test-"));
  const bundle = join(root, "bundle");
  await mkdir(bundle);
  await writeFile(join(bundle, "install-inventory.json"), JSON.stringify({ sourceRevision, packageManifest: "release-manifest.json" }));
  await writeFile(join(bundle, "release-manifest.json"), JSON.stringify({ sourceRevision }));
  const releaseManifestPath = join(root, "release-manifest.json");
  await writeFile(releaseManifestPath, JSON.stringify({ sourceRevision }));
  const directory = join(root, "private-setup");
  const pinPath = join(root, "pin.json");
  const planPath = join(root, "plan.json");
  await writeFile(pinPath, JSON.stringify(pin));
  await writeFile(planPath, JSON.stringify({ ...plan, releaseManifestPath }));
  const verifyBundle = async () => ({ sourceRevision, packageCount: 10, imageRoles: ["node", "indexer", "proof-server"], proofParameterCount: 18 });
  await initializeStandaloneSetup(directory, bundle, { verifyBundle });
  return { directory, pinPath, planPath, releaseManifestPath, verifyBundle };
}

test("wizard records staged-byte verification but leaves RC gates open", async () => {
  const { directory, pinPath } = await fixture();
  let status = await standaloneSetupStatus(directory);
  assert.equal(status.install, "verified-staged-bytes-only");
  assert.equal(status.localLedger, "pending");
  assert.equal(status.releaseQualified, false);
  assert.equal((await lstat(directory)).mode & 0o077, 0);
  assert.equal((await lstat(join(directory, "setup-record.json"))).mode & 0o077, 0);
  await observeStandaloneLedger(directory, pinPath, {
    preflight: async () => ({ kind: "local-node-observation-only", finalizedBlockHash: `0x${"d".repeat(64)}` }),
  });
  status = await standaloneSetupStatus(directory);
  assert.equal(status.localLedger, "node-observed-not-independently-approved");
  assert.equal(status.maintenanceApproval, "pending");
});

test("an observed submission is still not a finalized or release-qualified deployment", async () => {
  const { directory, pinPath, planPath, verifyBundle } = await fixture();
  await observeStandaloneLedger(directory, pinPath, { preflight: async () => ({ kind: "local-node-observation-only" }) });
  const result = { kind: "local-deployment-submission-observation", readbackStatus: "pending" };
  assert.deepEqual(await attemptStandaloneDeployment(directory, planPath, {
    verifyBundle,
    deploy: async () => result,
  }), result);
  const status = await standaloneSetupStatus(directory);
  assert.equal(status.deployment, "observed");
  assert.equal(status.releaseQualified, false);
  assert.equal(status.maintenanceApproval, "pending");
});

test("wizard rejects a manifest substitution before reserving a deployment", async () => {
  const { directory, pinPath, planPath, releaseManifestPath, verifyBundle } = await fixture();
  await observeStandaloneLedger(directory, pinPath, { preflight: async () => ({ kind: "local-node-observation-only" }) });
  await writeFile(releaseManifestPath, JSON.stringify({ sourceRevision, changed: true }));
  await assert.rejects(attemptStandaloneDeployment(directory, planPath, { verifyBundle }), /release manifest disagrees/u);
  assert.equal((await standaloneSetupStatus(directory)).deployment, "pending");
});

test("wizard reserves once before provider execution and never retries an unknown outcome", async () => {
  const { directory, pinPath, planPath, verifyBundle } = await fixture();
  await observeStandaloneLedger(directory, pinPath, { preflight: async () => ({ kind: "local-node-observation-only" }) });
  let calls = 0;
  await assert.rejects(attemptStandaloneDeployment(directory, planPath, {
    verifyBundle,
    deploy: async () => { calls += 1; throw new Error("private wallet internals"); },
  }), /outcome is unknown/u);
  assert.equal((await standaloneSetupStatus(directory)).deployment, "unknown");
  await assert.rejects(attemptStandaloneDeployment(directory, planPath, {
    verifyBundle,
    deploy: async () => { calls += 1; },
  }), /already reserved/u);
  assert.equal(calls, 1);
  assert.doesNotMatch(await readFile(join(directory, "setup-record.json"), "utf8"), /private wallet internals/u);
});

test("wizard rejects a changed deployment genesis before reserving", async () => {
  const { directory, pinPath, planPath, verifyBundle } = await fixture();
  await observeStandaloneLedger(directory, pinPath, { preflight: async () => ({ kind: "local-node-observation-only" }) });
  await writeFile(planPath, JSON.stringify({ ...plan, network: {
    ...plan.network, expectedGenesisHash: `0x${"e".repeat(64)}`,
  } }));
  await assert.rejects(attemptStandaloneDeployment(directory, planPath, { verifyBundle }), /disagrees/u);
  assert.equal((await standaloneSetupStatus(directory)).deployment, "pending");
});
