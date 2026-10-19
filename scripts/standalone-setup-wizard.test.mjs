import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { sampleSigningKey, signatureVerifyingKey } from "@midnight-ntwrk/compact-runtime";
import { VerifierKeyInsertionOutcomeUnknownError } from "@midnight-ntwrk/trust-registry-integration";

import {
  approveStandaloneCommittee,
  approveStandaloneGenesis,
  attemptStandaloneDeployment,
  attemptStandaloneVerifierKeyInsertion,
  initializeStandaloneSetup,
  observeStandaloneLedger,
  prepareStandaloneCommitteeTransition,
  reconcileStandaloneCommitteeTransition,
  reconcileStandaloneDeployment,
  reconcileStandaloneVerifierKeyInsertion,
  standaloneSetupStatus,
  submitStandaloneCommitteeTransition,
  verifyDetachedReviewerSignature,
} from "./standalone-setup-wizard.mjs";

const sourceRevision = "a".repeat(40);
const expectedGenesisHash = `0x${"b".repeat(64)}`;
const reviewerFingerprint = "A".repeat(40);
const governanceFingerprint = "B".repeat(40);
const journalAttribution = "journal-recorded-not-independently-inclusion-verified";
const stagedReceipt = {
  networkId: "undeployed",
  contractAddress: `0x${"c".repeat(64)}`, blockHash: `0x${"d".repeat(64)}`,
  blockHeight: 10, txId: "staged-deployment-tx",
};
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

async function committeeDocument(f, overrides = {}) {
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  const keys = Array.from({ length: 3 }, () => `0x${signatureVerifyingKey(sampleSigningKey())}`);
  const document = {
    format: "tr-local-committee-approval-v1",
    sourceRevision,
    installInventorySha256: record.install.inventorySha256,
    genesisApprovalSha256: record.genesisApproval.documentSha256,
    networkId: "undeployed",
    expectedGenesisHash,
    reviewerFingerprint: governanceFingerprint,
    reviewedReference: "governance-decision:local-release-committee",
    approvedAt: new Date().toISOString(),
    maintenancePolicy: { mode: "committee", threshold: 2, verifyingKeys: keys },
    custodians: keys.map((verifyingKey, index) => ({
      verifyingKey, holderRole: `maintainer-${index + 1}`, custodyReference: `custody-record-${index + 1}`,
    })),
    ...overrides,
  };
  const path = join(f.directory, "committee-approval.json");
  const signature = join(f.directory, "committee-approval.sig");
  await writeFile(path, JSON.stringify(document));
  await writeFile(signature, "test-only-committee-signature");
  return { path, signature, document };
}

async function approveCommittee(f, overrides = {}) {
  const input = await committeeDocument(f, overrides);
  return approveStandaloneCommittee(f.directory, input.path, input.signature, f.keyring, governanceFingerprint, {
    verifySignature: async (_document, _signature, _keyring, fingerprint) => {
      assert.equal(fingerprint, governanceFingerprint);
    },
  });
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

async function stagedFixture() {
  const f = await fixture();
  await observeStandaloneLedger(f.directory, f.pinPath, {
    preflight: async () => ({ kind: "local-node-observation-only" }),
  });
  await approve(f);
  await writeFile(f.planPath, JSON.stringify({
    ...plan, format: "tr-local-staged-deployment-plan-v1",
    initialVerifierKeyName: "initialKey", releaseManifestPath: f.releaseManifestPath,
  }));
  const insertionPlanPath = join(f.directory, "insertion-plan.json");
  const insertionPlan = {
    format: "tr-local-verifier-key-insertion-plan-v1",
    sourceRevision, network: plan.network,
    releaseManifestPath: f.releaseManifestPath,
    providerModulePath: plan.providerModulePath,
    providerModuleSha256: plan.providerModuleSha256,
    deploymentJournalPath: plan.journalPath,
    journalPath: "/private/verifier-nextKey.json",
    initialVerifierKeyName: "initialKey", circuitName: "nextKey",
  };
  await writeFile(insertionPlanPath, JSON.stringify(insertionPlan));
  return { ...f, insertionPlanPath, insertionPlan };
}

async function committeeTransitionFixture() {
  const f = await stagedFixture();
  const manifest = {
    format: "tr-release-candidate-manifest-v2", sourceRevision,
    verifierKeySha256: { initialKey: "a".repeat(64), nextKey: "b".repeat(64), laterKey: "c".repeat(64) },
  };
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  await writeFile(join(record.install.bundle, "release-manifest.json"), JSON.stringify(manifest));
  await writeFile(f.releaseManifestPath, JSON.stringify(manifest));
  await approveCommittee(f);
  await attemptStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    deploy: async () => ({ kind: "local-deployment-submission-observation",
      readbackStatus: "staged-bootstrap-pending", receipt: stagedReceipt }),
  });
  const requestPath = join(f.directory, "committee-transition-request.json");
  const request = {
    format: "tr-local-committee-transition-request-v1", sourceRevision,
    bootstrapMaintenanceVerifyingKey: `0x${signatureVerifyingKey(sampleSigningKey())}`,
    expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
    bootstrap: {
      registryId: "registry:midnight:undeployed:test",
      registryDidCommitment: `0x${"1".repeat(64)}`,
      governancePolicyCommitment: `0x${"2".repeat(64)}`,
      maintainerId: `0x${"3".repeat(64)}`,
      maintainerDidCommitment: `0x${"4".repeat(64)}`,
      maintainerKeyId: `0x${"5".repeat(64)}`,
      maintainerPublicKey: { x: "7", y: "8" },
      maintainerThreshold: "1",
    },
    governance: {
      policyCommitment: `0x${"6".repeat(64)}`, policyVersion: "2",
      actionSequence: "4", maintainerThreshold: "2", activeMaintainerCount: "3",
    },
  };
  await writeFile(requestPath, JSON.stringify(request));
  return { ...f, requestPath, request, manifest };
}

test("wizard prepares only a complete staged transition under the signed release roster", async () => {
  const f = await committeeTransitionFixture();
  const prepareTransition = async (approval) => {
    const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
    assert.deepEqual(approval.maintenancePolicy, record.committeeApproval.maintenancePolicy);
    assert.equal(approval.stagedVerifierKeyInstallation, true);
    assert.deepEqual(approval.receipt, stagedReceipt);
    assert.deepEqual(approval.releaseManifest, f.manifest);
    assert.equal(approval.bootstrap.maintainerThreshold, 1n);
    assert.equal(approval.governance.activeMaintainerCount, 3n);
    return {
      networkId: "undeployed", contractAddress: stagedReceipt.contractAddress,
      finalizedBlockHash: `0x${"e".repeat(64)}`,
      currentAuthorityCounter: 2n, nextAuthorityCounter: 3n,
      committeeVerifyingKeys: approval.maintenancePolicy.verifyingKeys,
      threshold: approval.maintenancePolicy.threshold,
      expiresAt: approval.expiresAt.toISOString(), dataToSign: Uint8Array.from([1, 2, 3]),
    };
  };
  await assert.rejects(prepareStandaloneCommitteeTransition(f.directory, f.requestPath, {
    verifyBundle: f.verifyBundle, prepareTransition: async () => assert.fail("incomplete catalog"),
  }), /Every staged verifier key/u);
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  record.verifierKeyInsertions = { nextKey: { state: "verified" }, laterKey: { state: "verified" } };
  await writeFile(recordPath, JSON.stringify(record));
  const prepared = await prepareStandaloneCommitteeTransition(f.directory, f.requestPath, {
    verifyBundle: f.verifyBundle, prepareTransition,
  });
  assert.equal(prepared.kind, "local-committee-transition-signing-request");
  assert.equal(prepared.dataToSignHex, "0x010203");
  assert.equal(prepared.updateSha256, createHash("sha256").update(Uint8Array.from([1, 2, 3])).digest("hex"));
  assert.equal(prepared.currentAuthorityCounter, "2");
  assert.equal(prepared.submission, "not-attempted");
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceApproval,
    "roster-signature-verified-transition-pending");
  assert.equal((await standaloneSetupStatus(f.directory)).releaseQualified, false);
  const changed = { ...f.request, sourceRevision: "f".repeat(40) };
  await writeFile(f.requestPath, JSON.stringify(changed));
  await assert.rejects(prepareStandaloneCommitteeTransition(f.directory, f.requestPath, {
    verifyBundle: f.verifyBundle, prepareTransition: async () => assert.fail("changed request"),
  }), /invalid shape or source revision/u);
});

async function preparedCommitteeFixture() {
  const f = await committeeTransitionFixture();
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  record.verifierKeyInsertions = { nextKey: { state: "verified" }, laterKey: { state: "verified" } };
  await writeFile(recordPath, JSON.stringify(record));
  const prepareTransition = async (approval) => ({
    networkId: "undeployed", contractAddress: stagedReceipt.contractAddress,
    finalizedBlockHash: `0x${"e".repeat(64)}`,
    currentAuthorityCounter: 2n, nextAuthorityCounter: 3n,
    committeeVerifyingKeys: approval.maintenancePolicy.verifyingKeys,
    threshold: approval.maintenancePolicy.threshold,
    expiresAt: approval.expiresAt.toISOString(), dataToSign: Uint8Array.from([1, 2, 3]),
    authorize: (signature) => {
      if (signature !== "a".repeat(128)) throw new Error("invalid bootstrap signature");
      return { kind: "signed-maintenance" };
    },
  });
  const dependencies = { verifyBundle: f.verifyBundle, prepareTransition };
  const signingRequest = await prepareStandaloneCommitteeTransition(f.directory, f.requestPath, dependencies);
  const signingRequestPath = join(f.directory, "committee-signing-request.json");
  const signaturePath = join(f.directory, "committee-signature.json");
  await writeFile(signingRequestPath, JSON.stringify(signingRequest));
  await writeFile(signaturePath, JSON.stringify({
    format: "tr-local-committee-signature-v1",
    updateSha256: signingRequest.updateSha256,
    signature: `0x${"a".repeat(128)}`,
  }));
  return { ...f, signingRequest, signingRequestPath, signaturePath, dependencies };
}

test("wizard reserves a committee submission once and reconciles without resubmission", async () => {
  const f = await preparedCommitteeFixture();
  let submissions = 0;
  const dependencies = {
    ...f.dependencies,
    loadMaterial: async () => ({ material: { providers: {}, stop: async () => {} } }),
    submit: async (input) => {
      assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition, "reserved");
      assert.equal(input.approvedUpdateSha256, f.signingRequest.updateSha256);
      assert.equal(input.approvedFinalizedBlockHash, f.signingRequest.finalizedBlockHash);
      submissions += 1;
      return "maintenance-tx";
    },
  };
  assert.deepEqual(await submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, dependencies,
  ), { kind: "local-committee-transition-submission", txId: "maintenance-tx",
    finalizedReadback: "pending" });
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition, "submitted");
  await assert.rejects(submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, dependencies,
  ), /already reserved/u);
  const readback = await reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, {
      verifyBundle: f.verifyBundle,
      reconcile: async (input) => {
        assert.equal(input.approvedUpdateSha256, f.signingRequest.updateSha256);
        return { status: "observed", txId: "maintenance-tx", finalizedBlockHash: `0x${"f".repeat(64)}` };
      },
    },
  );
  assert.equal(readback.status, "observed");
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition, "observed");
  assert.equal((await standaloneSetupStatus(f.directory)).releaseQualified, false);
  await reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, {
      verifyBundle: f.verifyBundle,
      reconcile: async () => ({ status: "pending", txId: "maintenance-tx", finalizedBlockHash: null }),
    },
  );
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition, "observed");
  await reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, {
      verifyBundle: f.verifyBundle,
      reconcile: async () => ({ status: "conflict", txId: "maintenance-tx",
        finalizedBlockHash: `0x${"f".repeat(64)}` }),
    },
  );
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition, "observed");
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransitionAlert, "conflict");
  const recorded = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.deepEqual(recorded.maintenanceAttempt.reconciliationHistory.map((entry) => entry.status),
    ["observed", "pending", "conflict"]);
  await assert.rejects(reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, {
      verifyBundle: f.verifyBundle,
      reconcile: async () => ({ status: "observed", txId: "different-tx",
        finalizedBlockHash: `0x${"f".repeat(64)}` }),
    },
  ), /inconsistent with the reserved attempt/u);
  assert.equal(submissions, 1);
});

test("changed signing bytes and invalid external signature fail before committee reservation", async () => {
  const f = await preparedCommitteeFixture();
  await writeFile(f.signingRequestPath, JSON.stringify({
    ...f.signingRequest, updateSha256: "f".repeat(64),
  }));
  await assert.rejects(submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, f.dependencies,
  ), /disagrees with fresh finalized/u);
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition, "pending");
  await writeFile(f.signingRequestPath, JSON.stringify(f.signingRequest));
  await writeFile(f.signaturePath, JSON.stringify({
    format: "tr-local-committee-signature-v1",
    updateSha256: f.signingRequest.updateSha256,
    signature: `0x${"b".repeat(128)}`,
  }));
  await assert.rejects(submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, f.dependencies,
  ), /invalid bootstrap signature/u);
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition, "pending");
});

test("unknown committee submission stays reserved and reconciliation cannot claim finality without a receipt", async () => {
  const f = await preparedCommitteeFixture();
  await assert.rejects(submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, {
      ...f.dependencies,
      loadMaterial: async () => ({ material: { providers: {} } }),
      submit: async (input) => input.journal.executeOnce(
        await f.dependencies.prepareTransition(input.approval),
        async () => { throw new Error("ambiguous transport"); },
        input.approvedFinalizedBlockHash,
      ),
    },
  ), /outcome is unknown/u);
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition, "unknown");
  const result = await reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath,
    { verifyBundle: f.verifyBundle,
      reconcile: async () => ({ status: "observed", txId: null,
        finalizedBlockHash: `0x${"f".repeat(64)}` }) },
  );
  assert.equal(result.status, "observed");
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition, "observed-without-receipt");
  await assert.rejects(submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, f.dependencies,
  ), /already reserved/u);
});

test("failed provider preflight with no journal permits an explicit new attempt", async () => {
  const f = await preparedCommitteeFixture();
  await assert.rejects(submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, {
      ...f.dependencies, loadMaterial: async () => { throw new Error("wallet not funded"); },
    },
  ), /before journal reservation/u);
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition, "aborted-before-journal");
  await assert.rejects(reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.dependencies,
  ), /No maintenance journal was reserved/u);
  await submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, {
      ...f.dependencies,
      loadMaterial: async () => ({ material: { providers: {} } }),
      submit: async () => "maintenance-tx-after-preflight",
    },
  );
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(record.maintenanceHistory[0].state, "aborted-before-journal");
  assert.equal(record.maintenanceAttempt.state, "submitted");
});

test("a crash window with no journal requires independent recovery instead of retry", async () => {
  const f = await preparedCommitteeFixture();
  await assert.rejects(submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, {
      ...f.dependencies, loadMaterial: async () => { throw new Error("preflight"); },
    },
  ), /before journal reservation/u);
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  record.maintenanceAttempt.state = "reserved";
  await writeFile(recordPath, JSON.stringify(record));
  await reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath,
    { verifyBundle: f.verifyBundle, reconcile: async () => ({ status: "not-reserved" }) },
  );
  const status = await standaloneSetupStatus(f.directory);
  assert.equal(status.maintenanceTransition, "recovery-required-no-journal");
  assert.equal(status.maintenanceTransitionAlert, "independent-human-recovery-required");
  await assert.rejects(submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, f.dependencies,
  ), /independent human recovery approval/u);
});

test("a missing journal after submission is recorded as a conflict", async () => {
  const f = await preparedCommitteeFixture();
  await submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, {
      ...f.dependencies,
      loadMaterial: async () => ({ material: { providers: {} } }),
      submit: async () => "maintenance-recorded-tx",
    },
  );
  await reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath,
    { verifyBundle: f.verifyBundle, reconcile: async () => ({ status: "not-reserved" }) },
  );
  const status = await standaloneSetupStatus(f.directory);
  assert.equal(status.maintenanceTransition, "conflict");
  assert.equal(status.maintenanceTransitionAlert, "journal-missing-after-submission");
});

test("an unknown outcome retains a reported transaction ID without claiming inclusion", async () => {
  const f = await preparedCommitteeFixture();
  await assert.rejects(submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, {
      ...f.dependencies,
      loadMaterial: async () => ({ material: { providers: {} } }),
      submit: async (input) => {
        await input.journal.executeOnce(await f.dependencies.prepareTransition(input.approval),
          async () => "tx-reported", input.approvedFinalizedBlockHash);
        throw Object.assign(new Error("response recording failed"), { txId: "tx-reported" });
      },
    },
  ), /outcome is unknown/u);
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(record.maintenanceAttempt.state, "unknown");
  assert.equal(record.maintenanceAttempt.reportedTxId, "tx-reported");
  assert.equal(record.maintenanceAttempt.txId, undefined);
});

test("a journal lost after an unknown outcome is not treated as a pre-journal crash", async () => {
  const f = await preparedCommitteeFixture();
  await assert.rejects(submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, {
      ...f.dependencies,
      loadMaterial: async () => ({ material: { providers: {} } }),
      submit: async (input) => input.journal.executeOnce(
        await f.dependencies.prepareTransition(input.approval),
        async () => { throw new Error("lost response"); }, input.approvedFinalizedBlockHash,
      ),
    },
  ), /outcome is unknown/u);
  await rm(join(f.directory, "committee-transition.json"));
  await reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath,
    { verifyBundle: f.verifyBundle, reconcile: async () => ({ status: "not-reserved" }) },
  );
  const status = await standaloneSetupStatus(f.directory);
  assert.equal(status.maintenanceTransition, "conflict");
  assert.equal(status.maintenanceTransitionAlert, "journal-missing-after-submission");
});

test("a conflict remains visible after a later expected readback", async () => {
  const f = await preparedCommitteeFixture();
  await submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, {
      ...f.dependencies,
      loadMaterial: async () => ({ material: { providers: {} } }),
      submit: async () => "maintenance-conflict-tx",
    },
  );
  const reconcile = async (status) => reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, {
      verifyBundle: f.verifyBundle,
      reconcile: async () => ({ status, txId: "maintenance-conflict-tx",
        finalizedBlockHash: `0x${"f".repeat(64)}` }),
    },
  );
  await reconcile("conflict");
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition, "conflict");
  await reconcile("observed");
  const status = await standaloneSetupStatus(f.directory);
  assert.equal(status.maintenanceTransition, "conflict");
  assert.equal(status.maintenanceTransitionAlert, "conflict");
  assert.equal(status.maintenanceLastReadback, "observed");
});

test("a newer finalized head can retain the original approved checkpoint", async () => {
  const f = await preparedCommitteeFixture();
  const oldPrepare = f.dependencies.prepareTransition;
  let approvedCheckpoint;
  await submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, {
      ...f.dependencies,
      prepareTransition: async (approval) => ({ ...await oldPrepare(approval),
        finalizedBlockHash: `0x${"f".repeat(64)}` }),
      loadMaterial: async () => ({ material: { providers: {} } }),
      submit: async (input) => {
        approvedCheckpoint = input.approvedFinalizedBlockHash;
        return "maintenance-tx-new-head";
      },
    },
  );
  assert.equal(approvedCheckpoint, f.signingRequest.finalizedBlockHash);
});

test("wizard rejects a changed roster or incomplete key insertion before transition prepare", async () => {
  const f = await committeeTransitionFixture();
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  record.verifierKeyInsertions = { nextKey: { state: "verified" }, laterKey: { state: "pending" } };
  await writeFile(recordPath, JSON.stringify(record));
  await assert.rejects(prepareStandaloneCommitteeTransition(f.directory, f.requestPath, {
    verifyBundle: f.verifyBundle, prepareTransition: async () => assert.fail("pending key"),
  }), /Every staged verifier key/u);
  record.verifierKeyInsertions.laterKey.state = "verified";
  record.committeeApproval.maintenancePolicy.threshold = 3;
  await writeFile(recordPath, JSON.stringify(record));
  await assert.rejects(prepareStandaloneCommitteeTransition(f.directory, f.requestPath, {
    verifyBundle: f.verifyBundle, prepareTransition: async () => assert.fail("changed roster"),
  }), /disagrees with signed approval bytes/u);
});

test("wizard requires finalized staged bootstrap and binds insertion to verified install", async () => {
  const f = await stagedFixture();
  await attemptStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    deploy: async () => ({ kind: "local-deployment-submission-observation", readbackStatus: "pending" }),
  });
  await assert.rejects(attemptStandaloneVerifierKeyInsertion(f.directory, f.insertionPlanPath, {
    verifyBundle: f.verifyBundle, insert: async () => assert.fail("must not submit"),
  }), /finalized staged bootstrap/u);
  assert.deepEqual((await standaloneSetupStatus(f.directory)).stagedVerifierKeys, []);
});

test("wizard rejects a staged status without a deployment receipt", async () => {
  const f = await stagedFixture();
  await attemptStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    deploy: async () => ({ kind: "local-deployment-submission-observation",
      readbackStatus: "staged-bootstrap-pending" }),
  });
  await assert.rejects(attemptStandaloneVerifierKeyInsertion(f.directory, f.insertionPlanPath, {
    verifyBundle: f.verifyBundle, insert: async () => assert.fail("must not submit"),
  }), /finalized staged bootstrap/u);
  assert.deepEqual((await standaloneSetupStatus(f.directory)).stagedVerifierKeys, []);
});

test("read-only deployment reconciliation promotes a pending staged receipt only after verified readback", async () => {
  const f = await stagedFixture();
  await attemptStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    deploy: async () => ({ kind: "local-deployment-submission-observation",
      readbackStatus: "pending", receipt: stagedReceipt }),
  });
  const setupPath = join(f.directory, "setup-record.json");
  const olderRecord = JSON.parse(await readFile(setupPath, "utf8"));
  delete olderRecord.deployment.stagedPlan;
  await writeFile(setupPath, JSON.stringify(olderRecord));
  const changedPlan = join(f.directory, "changed-deployment-plan.json");
  await writeFile(changedPlan, JSON.stringify({
    ...plan, format: "tr-local-staged-deployment-plan-v1",
    initialVerifierKeyName: "anotherKey", releaseManifestPath: f.releaseManifestPath,
  }));
  await assert.rejects(reconcileStandaloneDeployment(f.directory, changedPlan, {
    verifyBundle: f.verifyBundle,
    reconcileDeployment: async () => assert.fail("must not inspect changed plan"),
  }), /disagrees with the reserved staged deployment/u);
  let reads = 0;
  const result = await reconcileStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    reconcileDeployment: async (_plan, approval) => {
      reads += 1;
      assert.deepEqual(approval.expectedDeploymentReceipt, stagedReceipt);
      assert.equal(approval.expectedReleaseManifestSha256,
        createHash("sha256").update(await readFile(f.releaseManifestPath)).digest("hex"));
      return { kind: "local-deployment-reconciliation", receipt: stagedReceipt,
        receiptAttribution: journalAttribution,
        readbackStatus: "staged-bootstrap-pending", finalizedBlockHash: `0x${"f".repeat(64)}` };
    },
  });
  assert.equal(result.readbackStatus, "staged-bootstrap-pending");
  assert.equal(reads, 1);
  const reconciledRecord = JSON.parse(await readFile(setupPath, "utf8"));
  assert.equal(reconciledRecord.deployment.stagedPlan.initialVerifierKeyName,
    f.insertionPlan.initialVerifierKeyName);
  assert.equal(reconciledRecord.deployment.readbackHistory[0].readbackStatus, "pending");
  assert.equal(reconciledRecord.deployment.result.finalizedBlockHash, `0x${"f".repeat(64)}`);
  assert.equal(reconciledRecord.deployment.result.receiptAttribution, journalAttribution);
  assert.equal((await standaloneSetupStatus(f.directory)).deployment, "observed");
  assert.equal((await standaloneSetupStatus(f.directory)).releaseQualified, false);
  await attemptStandaloneVerifierKeyInsertion(f.directory, f.insertionPlanPath, {
    verifyBundle: f.verifyBundle, insert: async () => ({ readbackStatus: "verified" }),
  });
  assert.equal((await standaloneSetupStatus(f.directory)).stagedVerifierKeys[0].state, "verified");
  await assert.rejects(reconcileStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    reconcileDeployment: async () => assert.fail("must not downgrade advanced bootstrap"),
  }), /bootstrap already advanced/u);
  const keyReadback = await reconcileStandaloneVerifierKeyInsertion(f.directory, f.insertionPlanPath, {
    verifyBundle: f.verifyBundle,
    reconcile: async () => ({ readback: { status: "verified" } }),
  });
  assert.equal(keyReadback.readback.status, "verified");
});

test("a deployment with no receipt remains reserved after read-only reconciliation", async () => {
  const f = await stagedFixture();
  await assert.rejects(attemptStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    deploy: async () => { throw new Error("unknown wallet outcome"); },
  }), /outcome is unknown/u);
  const result = await reconcileStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    reconcileDeployment: async () => ({ kind: "local-deployment-reconciliation",
      readbackStatus: "unknown-no-receipt" }),
  });
  assert.equal(result.readbackStatus, "unknown-no-receipt");
  assert.equal((await standaloneSetupStatus(f.directory)).deployment, "unknown");
  await assert.rejects(attemptStandaloneVerifierKeyInsertion(f.directory, f.insertionPlanPath, {
    verifyBundle: f.verifyBundle, insert: async () => assert.fail("must not insert"),
  }), /finalized staged bootstrap/u);
});

test("wizard rejects a changed reconciliation receipt without promoting deployment", async () => {
  const f = await stagedFixture();
  await attemptStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    deploy: async () => ({ kind: "local-deployment-submission-observation",
      readbackStatus: "pending", receipt: stagedReceipt }),
  });
  await assert.rejects(reconcileStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    reconcileDeployment: async () => ({ kind: "local-deployment-reconciliation",
      receipt: { ...stagedReceipt, blockHash: `0x${"1".repeat(64)}` },
      receiptAttribution: journalAttribution,
      readbackStatus: "staged-bootstrap-pending" }),
  }), /changed the setup-recorded receipt/u);
  await assert.rejects(reconcileStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    reconcileDeployment: async () => ({ kind: "local-deployment-reconciliation",
      receipt: stagedReceipt, receiptAttribution: "independently-verified",
      readbackStatus: "staged-bootstrap-pending" }),
  }), /invalid observation/u);
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(record.deployment.result.readbackStatus, "pending");
});

test("wizard retains earlier mismatched readbacks when a later read is pending", async () => {
  const f = await stagedFixture();
  await attemptStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    deploy: async () => ({ kind: "local-deployment-submission-observation",
      readbackStatus: "pending", receipt: stagedReceipt }),
  });
  let status = "mismatch";
  const reconcile = async () => reconcileStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    reconcileDeployment: async () => ({ kind: "local-deployment-reconciliation",
      receipt: stagedReceipt, receiptAttribution: journalAttribution,
      readbackStatus: status }),
  });
  assert.equal((await reconcile()).readbackStatus, "mismatch");
  status = "pending";
  assert.equal((await reconcile()).readbackStatus, "pending");
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.deepEqual(record.deployment.readbackHistory.map((entry) => entry.readbackStatus),
    ["pending", "mismatch"]);
  assert.equal(record.deployment.result.readbackStatus, "pending");
  assert.equal((await standaloneSetupStatus(f.directory)).releaseQualified, false);
});

test("wizard reserves one staged insertion and requires read-only reconciliation before the next", async () => {
  const f = await stagedFixture();
  await attemptStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    deploy: async () => ({ kind: "local-deployment-submission-observation",
      readbackStatus: "staged-bootstrap-pending", receipt: stagedReceipt }),
  });
  let calls = 0;
  const first = await attemptStandaloneVerifierKeyInsertion(f.directory, f.insertionPlanPath, {
    verifyBundle: f.verifyBundle,
    insert: async (_plan, approval) => {
      calls += 1;
      assert.deepEqual(approval.expectedDeploymentReceipt, stagedReceipt);
      assert.equal(approval.expectedReleaseManifestSha256,
        createHash("sha256").update(await readFile(f.releaseManifestPath)).digest("hex"));
      return { readbackStatus: "pending" };
    },
  });
  assert.equal(first.readbackStatus, "pending");
  assert.deepEqual((await standaloneSetupStatus(f.directory)).stagedVerifierKeys,
    [{ circuitName: "nextKey", state: "pending" }]);
  await assert.rejects(attemptStandaloneVerifierKeyInsertion(f.directory, f.insertionPlanPath, {
    verifyBundle: f.verifyBundle, insert: async () => { calls += 1; },
  }), /reserved or unresolved/u);
  assert.equal(calls, 1);
  const readback = await reconcileStandaloneVerifierKeyInsertion(f.directory, f.insertionPlanPath, {
    verifyBundle: f.verifyBundle,
    reconcile: async () => ({ readback: { status: "verified" } }),
  });
  assert.equal(readback.readback.status, "verified");
  assert.deepEqual((await standaloneSetupStatus(f.directory)).stagedVerifierKeys,
    [{ circuitName: "nextKey", state: "verified" }]);
  const nextPath = join(f.directory, "next-insertion-plan.json");
  await writeFile(nextPath, JSON.stringify({ ...f.insertionPlan,
    circuitName: "laterKey", journalPath: "/private/verifier-laterKey.json" }));
  await attemptStandaloneVerifierKeyInsertion(f.directory, nextPath, {
    verifyBundle: f.verifyBundle,
    insert: async () => ({ readbackStatus: "verified" }),
  });
  assert.deepEqual((await standaloneSetupStatus(f.directory)).stagedVerifierKeys,
    [{ circuitName: "nextKey", state: "verified" }, { circuitName: "laterKey", state: "verified" }]);
  assert.equal((await standaloneSetupStatus(f.directory)).releaseQualified, false);
});

test("wizard preserves an ambiguous insertion and rejects changed approval bytes", async () => {
  const f = await stagedFixture();
  await attemptStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    deploy: async () => ({ kind: "local-deployment-submission-observation",
      readbackStatus: "staged-bootstrap-pending", receipt: stagedReceipt }),
  });
  const changedPath = join(f.directory, "changed-insertion-plan.json");
  await writeFile(changedPath, JSON.stringify({ ...f.insertionPlan, providerModuleSha256: "d".repeat(64) }));
  await assert.rejects(attemptStandaloneVerifierKeyInsertion(f.directory, changedPath, {
    verifyBundle: f.verifyBundle, insert: async () => assert.fail("must not submit"),
  }), /disagrees with the approved staged deployment/u);
  await writeFile(changedPath, JSON.stringify({ ...f.insertionPlan, network: {
    ...f.insertionPlan.network, indexerHttpUrl: "http://127.0.0.1:28089/api/v4/graphql",
  } }));
  await assert.rejects(attemptStandaloneVerifierKeyInsertion(f.directory, changedPath, {
    verifyBundle: f.verifyBundle, insert: async () => assert.fail("must not submit"),
  }), /disagrees with the approved staged deployment/u);
  assert.deepEqual((await standaloneSetupStatus(f.directory)).stagedVerifierKeys, []);
  const publicReceipt = { outcome: "succeeded", txId: "insert-tx",
    blockHash: `0x${"e".repeat(64)}`, blockHeight: 12 };
  await assert.rejects(attemptStandaloneVerifierKeyInsertion(f.directory, f.insertionPlanPath, {
    verifyBundle: f.verifyBundle,
    insert: async () => { throw new VerifierKeyInsertionOutcomeUnknownError(
      new Error("private wallet details"), publicReceipt,
    ); },
  }), /outcome is unknown/u);
  assert.deepEqual((await standaloneSetupStatus(f.directory)).stagedVerifierKeys,
    [{ circuitName: "nextKey", state: "unknown" }]);
  await assert.rejects(attemptStandaloneVerifierKeyInsertion(f.directory, f.insertionPlanPath, {
    verifyBundle: f.verifyBundle, insert: async () => assert.fail("must not resubmit"),
  }), /reserved or unresolved/u);
  assert.doesNotMatch(await readFile(join(f.directory, "setup-record.json"), "utf8"), /private wallet details/u);
  const saved = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.deepEqual(saved.verifierKeyInsertions.nextKey.receipt, publicReceipt);
  await assert.rejects(reconcileStandaloneVerifierKeyInsertion(f.directory, changedPath, {
    verifyBundle: f.verifyBundle,
    reconcile: async () => assert.fail("must not reconcile a changed plan"),
  }), /disagrees with the approved staged deployment/u);
  const result = await reconcileStandaloneVerifierKeyInsertion(f.directory, f.insertionPlanPath, {
    verifyBundle: f.verifyBundle,
    reconcile: async () => ({ readback: { status: "observed-without-receipt" } }),
  });
  assert.equal(result.readback.status, "observed-without-receipt");
  assert.equal((await standaloneSetupStatus(f.directory)).stagedVerifierKeys[0].state,
    "observed-without-receipt");
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

test("signed release committee roster binds three distinct custodians but not a transition", async () => {
  const f = await fixture();
  await observeStandaloneLedger(f.directory, f.pinPath, { preflight: async () => ({ kind: "local-node-observation-only" }) });
  await approve(f);
  const result = await approveCommittee(f);
  assert.equal(result.threshold, 2);
  assert.equal(result.committeeSize, 3);
  const status = await standaloneSetupStatus(f.directory);
  assert.equal(status.maintenanceApproval, "roster-signature-verified-transition-pending");
  assert.equal(status.releaseQualified, false);
  await assert.rejects(approveCommittee(f), /already recorded/u);
});

test("smoke threshold and repeated custody roles cannot become release approval", async () => {
  const f = await fixture();
  await observeStandaloneLedger(f.directory, f.pinPath, { preflight: async () => ({ kind: "local-node-observation-only" }) });
  await approve(f);
  await assert.rejects(approveCommittee(f, {
    maintenancePolicy: { mode: "committee", threshold: 1,
      verifyingKeys: Array.from({ length: 3 }, () => `0x${signatureVerifyingKey(sampleSigningKey())}`) },
  }), /multi-party threshold/u);
  const validKeys = (await committeeDocument(f)).document.maintenancePolicy.verifyingKeys;
  await assert.rejects(approveCommittee(f, {
    maintenancePolicy: { mode: "committee", threshold: 2,
      verifyingKeys: [...validKeys.slice(0, 2), `0x${"f".repeat(64)}`] },
  }), /ledger cannot use/u);
  const input = await committeeDocument(f);
  await assert.rejects(approveCommittee(f, {
    custodians: input.document.custodians.map((custodian) => ({ ...custodian, holderRole: "same-maintainer" })),
  }), /distinct holder roles/u);
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceApproval, "pending");
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
