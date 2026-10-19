import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  approveStandaloneGenesis,
  attemptStandaloneDeployment,
  initializeStandaloneSetup,
  observeStandaloneLedger,
  standaloneSetupStatus,
  verifyDetachedReviewerSignature,
} from "./standalone-setup-wizard.mjs";

const sourceRevision = "a".repeat(40);
const expectedGenesisHash = `0x${"b".repeat(64)}`;
const reviewerFingerprint = "A".repeat(40);
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
  const keyring = join(root, "reviewer-public-keyring");
  await mkdir(keyring, { mode: 0o700 });
  const approvalPath = join(root, "genesis-approval.json");
  const signaturePath = join(root, "genesis-approval.sig");
  const record = JSON.parse(await readFile(join(directory, "setup-record.json"), "utf8"));
  await writeFile(approvalPath, JSON.stringify({
    format: "tr-local-genesis-approval-v1",
    sourceRevision,
    installInventorySha256: record.install.inventorySha256,
    networkId: "undeployed",
    pinSha256: createHash("sha256").update(await readFile(pinPath)).digest("hex"),
    expectedGenesisHash,
    rpcUrl: pin.rpcUrl,
    reviewerFingerprint,
    reviewedReference: `signed-local-chain-spec:sha256:${"f".repeat(64)}`,
    approvedAt: new Date().toISOString(),
  }));
  await writeFile(signaturePath, "test-only-detached-signature");
  return { directory, pinPath, planPath, releaseManifestPath, approvalPath, signaturePath,
    keyring, verifyBundle };
}

async function approve(f) {
  return approveStandaloneGenesis(
    f.directory, f.approvalPath, f.signaturePath, f.keyring, reviewerFingerprint,
    { verifySignature: async (_document, _signature, _keyring, fingerprint) => {
      assert.equal(fingerprint, reviewerFingerprint);
    } },
  );
}

test("wizard records staged-byte verification but leaves RC gates open", async () => {
  const { directory, pinPath } = await fixture();
  let status = await standaloneSetupStatus(directory);
  assert.equal(status.install, "verified-staged-bytes-only");
  assert.equal(status.localLedger, "pending");
  assert.equal(status.setupLock, "absent");
  assert.equal(status.releaseQualified, false);
  assert.equal((await lstat(directory)).mode & 0o077, 0);
  assert.equal((await lstat(join(directory, "setup-record.json"))).mode & 0o077, 0);
  await observeStandaloneLedger(directory, pinPath, {
    preflight: async () => ({ kind: "local-node-observation-only", finalizedBlockHash: `0x${"d".repeat(64)}` }),
  });
  status = await standaloneSetupStatus(directory);
  assert.equal(status.localLedger, "node-observed-not-independently-approved");
  assert.equal(status.maintenanceApproval, "pending");
  await writeFile(join(directory, ".setup.lock"), "interrupted");
  assert.equal((await standaloneSetupStatus(directory)).setupLock, "present-inspect-before-removal");
});

test("an observed submission is still not a finalized or release-qualified deployment", async () => {
  const f = await fixture();
  const { directory, pinPath, planPath, verifyBundle } = f;
  await observeStandaloneLedger(directory, pinPath, { preflight: async () => ({ kind: "local-node-observation-only" }) });
  await assert.rejects(attemptStandaloneDeployment(directory, planPath, { verifyBundle }), /reviewer approval/u);
  await approve(f);
  const result = { kind: "local-deployment-submission-observation", readbackStatus: "pending" };
  assert.deepEqual(await attemptStandaloneDeployment(directory, planPath, {
    verifyBundle,
    deploy: async () => result,
  }), result);
  const status = await standaloneSetupStatus(directory);
  assert.equal(status.deployment, "observed");
  assert.equal(status.releaseQualified, false);
  assert.equal(status.maintenanceApproval, "pending");
  assert.equal(status.localLedger, "operator-pinned-reviewer-signature-verified");
});

test("wizard rejects a manifest substitution before reserving a deployment", async () => {
  const f = await fixture();
  const { directory, pinPath, planPath, releaseManifestPath, verifyBundle } = f;
  await observeStandaloneLedger(directory, pinPath, { preflight: async () => ({ kind: "local-node-observation-only" }) });
  await approve(f);
  await writeFile(releaseManifestPath, JSON.stringify({ sourceRevision, changed: true }));
  await assert.rejects(attemptStandaloneDeployment(directory, planPath, { verifyBundle }), /release manifest disagrees/u);
  assert.equal((await standaloneSetupStatus(directory)).deployment, "pending");
});

test("wizard reserves once before provider execution and never retries an unknown outcome", async () => {
  const f = await fixture();
  const { directory, pinPath, planPath, verifyBundle } = f;
  await observeStandaloneLedger(directory, pinPath, { preflight: async () => ({ kind: "local-node-observation-only" }) });
  await approve(f);
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
  const f = await fixture();
  const { directory, pinPath, planPath, verifyBundle } = f;
  await observeStandaloneLedger(directory, pinPath, { preflight: async () => ({ kind: "local-node-observation-only" }) });
  await approve(f);
  await writeFile(planPath, JSON.stringify({ ...plan, network: {
    ...plan.network, expectedGenesisHash: `0x${"e".repeat(64)}`,
  } }));
  await assert.rejects(attemptStandaloneDeployment(directory, planPath, { verifyBundle }), /disagrees/u);
  assert.equal((await standaloneSetupStatus(directory)).deployment, "pending");
});

test("genesis approval rejects changed source pins and cannot be replaced after acceptance", async () => {
  const f = await fixture();
  await observeStandaloneLedger(f.directory, f.pinPath, { preflight: async () => ({ kind: "local-node-observation-only" }) });
  const original = JSON.parse(await readFile(f.approvalPath, "utf8"));
  await writeFile(f.approvalPath, JSON.stringify({ ...original, expectedGenesisHash: `0x${"e".repeat(64)}` }));
  await assert.rejects(approve(f), /does not bind/u);
  await writeFile(f.approvalPath, JSON.stringify(original));
  const evidence = await approve(f);
  assert.equal(evidence.reviewerFingerprint, reviewerFingerprint);
  await assert.rejects(approve(f), /already recorded/u);
  await assert.rejects(observeStandaloneLedger(f.directory, f.pinPath, {
    preflight: async () => ({ kind: "local-node-observation-only" }),
  }), /after reviewer approval/u);
});

test("signature verification reads a private snapshot of the retained approval bytes", async () => {
  const f = await fixture();
  await observeStandaloneLedger(f.directory, f.pinPath, { preflight: async () => ({ kind: "local-node-observation-only" }) });
  const original = await readFile(f.approvalPath);
  await approveStandaloneGenesis(
    f.directory, f.approvalPath, f.signaturePath, f.keyring, reviewerFingerprint,
    { verifySignature: async (documentSnapshot, signatureSnapshot) => {
      assert.equal(Buffer.compare(await readFile(documentSnapshot), original), 0);
      assert.equal((await readFile(signatureSnapshot, "utf8")), "test-only-detached-signature");
      await writeFile(f.approvalPath, '{"format":"tampered"}');
      assert.equal(Buffer.compare(await readFile(documentSnapshot), original), 0);
    } },
  );
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(Buffer.compare(Buffer.from(record.genesisApproval.documentBase64, "base64"), original), 0);
  assert.deepEqual((await readdir(f.directory)).sort(), ["setup-record.json"]);
});

test("detached GPG verification accepts only the pinned signing key and exact bytes", async (t) => {
  if (spawnSync("gpg", ["--version"], { stdio: "ignore" }).status !== 0) {
    t.skip("gpg is not installed");
    return;
  }
  const root = await mkdtemp("/tmp/tr-gpg-");
  t.after(() => rm(root, { recursive: true, force: true }));
  const signer = join(root, "signer");
  const verifier = join(root, "verifier");
  await mkdir(signer, { mode: 0o700 });
  await mkdir(verifier, { mode: 0o700 });
  execFileSync("gpg", ["--homedir", signer, "--batch", "--pinentry-mode", "loopback",
    "--passphrase", "", "--quick-generate-key", "Setup Reviewer <reviewer@example.test>", "ed25519", "sign", "0"],
  { stdio: "pipe", timeout: 30_000 });
  const listing = execFileSync("gpg", ["--homedir", signer, "--batch", "--with-colons", "--list-secret-keys"],
    { encoding: "utf8" });
  const fingerprint = listing.split("\n").find((line) => line.startsWith("fpr:"))?.split(":")[9];
  assert.match(fingerprint, /^[A-F0-9]{40}$/u);
  const publicKey = execFileSync("gpg", ["--homedir", signer, "--batch", "--export", fingerprint]);
  execFileSync("gpg", ["--homedir", verifier, "--batch", "--import"], { input: publicKey, stdio: ["pipe", "pipe", "pipe"] });
  const document = join(root, "approval.json");
  const signature = join(root, "approval.sig");
  await writeFile(document, '{"format":"tr-local-genesis-approval-v1"}\n');
  execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign", "--output", signature, document]);
  await verifyDetachedReviewerSignature(document, signature, verifier, fingerprint);
  await assert.rejects(verifyDetachedReviewerSignature(document, signature, verifier, "B".repeat(40)), /does not match/u);
  await writeFile(document, '{"format":"tampered"}\n');
  await assert.rejects(verifyDetachedReviewerSignature(document, signature, verifier, fingerprint));
});
