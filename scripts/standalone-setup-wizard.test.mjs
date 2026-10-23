import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { lstat, mkdtemp, mkdir, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { sampleSigningKey, signatureVerifyingKey } from "@midnight-ntwrk/compact-runtime";
import { VerifierKeyInsertionOutcomeUnknownError } from "@midnight-ntwrk/trust-registry-integration";

import {
  assertUnusedStandaloneProject,
  draftStandaloneGenesisApproval,
  draftStandaloneCommitteeApproval,
  approveStandaloneCommittee,
  approveStandaloneCommitteeDeployment,
  approveStandaloneCommitteeRecovery,
  approveStandaloneGenesis,
  attemptStandaloneDeployment,
  attemptStandaloneVerifierKeyInsertion,
  collectStandaloneGenesisCandidate,
  initializeStandaloneSetup,
  observeStandaloneLedger,
  observeStandaloneStack,
  prepareStandaloneStack,
  prepareStandaloneCommitteeTransition,
  reconcileStandaloneCommitteeTransition,
  reconcileStandaloneDeployment,
  reconcileStandaloneVerifierKeyInsertion,
  runStandaloneSetupInteractive,
  standaloneSetupStatus,
  submitStandaloneCommitteeTransition,
  verifyDetachedReviewerSignature,
} from "./standalone-setup-wizard.mjs";
import { pinnedStandaloneImages } from "./build-standalone-install.mjs";
import { demoGenesisReference } from "./demo-genesis-reference.mjs";

const sourceRevision = "a".repeat(40);
const ledgerNetworkId = "ledger-id";
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

async function fixture(format = "tr-standalone-install-v2") {
  const root = await mkdtemp(join(tmpdir(), "tr-wizard-test-"));
  const bundle = join(root, "bundle");
  await mkdir(bundle);
  const compose = await readFile(new URL("../deploy/standalone/compose.yml", import.meta.url));
  const offlineCompose = await readFile(new URL("../deploy/standalone/compose.offline.yml", import.meta.url));
  const composeSha256 = createHash("sha256").update(compose).digest("hex");
  const offlineComposeSha256 = createHash("sha256").update(offlineCompose).digest("hex");
  const images = pinnedStandaloneImages(compose.toString("utf8"));
  await writeFile(join(bundle, "install-inventory.json"), JSON.stringify({ sourceRevision,
    format, packageManifest: "release-manifest.json", images,
    ...(["tr-standalone-install-v3", "tr-standalone-install-v4", "tr-standalone-install-v5", "tr-standalone-install-v6"].includes(format) ? { runtimeCompose: {
      path: "compose.yml", sha256: composeSha256,
      offlinePath: "compose.offline.yml", offlineSha256: offlineComposeSha256,
    } } : {}),
    ...(["tr-standalone-install-v4", "tr-standalone-install-v5", "tr-standalone-install-v6"].includes(format) ? { apiRuntime: {
      manifest: "images/api.manifest.json", manifestSha256: "a".repeat(64),
      archive: "images/api.image.tar", archiveSha256: "b".repeat(64),
    } } : {}),
    ...(["tr-standalone-install-v5", "tr-standalone-install-v6"].includes(format) ? { portalRuntimes: {
      admin: { manifest: "images/admin.manifest.json", manifestSha256: "c".repeat(64),
        archive: "images/admin.image.tar", archiveSha256: "d".repeat(64) },
      applicant: { manifest: "images/applicant.manifest.json", manifestSha256: "e".repeat(64),
        archive: "images/applicant.image.tar", archiveSha256: "f".repeat(64) },
    } } : {}),
    ...(format === "tr-standalone-install-v6" ? { installRelay: {
      path: "install-relay.py", sha256: "b".repeat(64), imageRole: "node",
    } } : {}) }));
  await writeFile(join(bundle, "release-manifest.json"), JSON.stringify({ sourceRevision }));
  await writeFile(join(bundle, "compose.yml"), compose);
  await writeFile(join(bundle, "compose.offline.yml"), offlineCompose);
  if (format === "tr-standalone-install-v6") {
    await writeFile(join(bundle, "install-relay.py"), "# fixture relay\n");
  }
  await mkdir(join(bundle, "proof-params"));
  const releaseManifestPath = join(root, "release-manifest.json");
  await writeFile(releaseManifestPath, JSON.stringify({ sourceRevision }));
  const directory = join(root, "private-setup");
  const pinPath = join(root, "pin.json");
  const planPath = join(root, "plan.json");
  await writeFile(pinPath, JSON.stringify(pin));
  await writeFile(planPath, JSON.stringify({ ...plan, releaseManifestPath }));
  const verifyBundle = async () => ({ sourceRevision, packageCount: 10, imageRoles: ["node", "indexer", "proof-server"],
    proofParameterCount: 18,
    images: images.map(({ role, reference }) => ({ role, reference,
      acceptedIds: [`sha256:${reference.split("@sha256:")[1]}`] })),
    runtimeComposeSha256: format !== "tr-standalone-install-v2" ? composeSha256 : null,
    runtimeOfflineComposeSha256: format !== "tr-standalone-install-v2" ? offlineComposeSha256 : null,
    apiRuntime: ["tr-standalone-install-v4", "tr-standalone-install-v5", "tr-standalone-install-v6"].includes(format)
      ? { imageId: `sha256:${"c".repeat(64)}` } : null,
    portalRuntimes: ["tr-standalone-install-v5", "tr-standalone-install-v6"].includes(format) ? {
      admin: { imageId: `sha256:${"d".repeat(64)}` },
      applicant: { imageId: `sha256:${"e".repeat(64)}` },
    } : null,
    installRelay: format === "tr-standalone-install-v6" ? {
      path: join(bundle, "install-relay.py"), sha256: "b".repeat(64),
      image: { role: "node", reference: images.find((image) => image.role === "node").reference,
        acceptedIds: [`sha256:${images.find((image) => image.role === "node").reference.split("@sha256:")[1]}`] },
    } : null });
  if (format === "tr-standalone-install-v2") {
    // Historical test records exercise approval state transitions, not a supported new installation.
    await mkdir(directory, { mode: 0o700 });
    await writeFile(join(directory, "setup-record.json"), JSON.stringify({
      format: "tr-standalone-setup-v1", setupId: randomUUID(), sourceRevision,
      createdAt: new Date().toISOString(),
      install: { bundle, inventorySha256: createHash("sha256")
        .update(await readFile(join(bundle, "install-inventory.json"))).digest("hex"),
      verified: await verifyBundle() },
    }), { mode: 0o600 });
  } else {
    await initializeStandaloneSetup(directory, bundle, { verifyBundle });
  }
  const keyring = join(root, "reviewer-public-keyring");
  await mkdir(keyring, { mode: 0o700 });
  const approvalPath = join(root, "genesis-approval.json");
  const signaturePath = join(root, "genesis-approval.sig");
  const record = JSON.parse(await readFile(join(directory, "setup-record.json"), "utf8"));
  await writeFile(approvalPath, JSON.stringify({
    format: "tr-local-genesis-approval-v1",
    setupId: record.setupId,
    stackProject: null,
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

const stackDependencies = (f) => ({ verifyBundle: f.verifyBundle,
  assertProjectUnused: async () => {} });

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

async function committeeDeploymentDocument(f, overrides = {}) {
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  const inventory = JSON.parse(await readFile(join(record.install.bundle, "install-inventory.json"), "utf8"));
  const manifest = await readFile(join(record.install.bundle, inventory.packageManifest));
  const document = {
    format: "tr-local-committee-deployment-approval-v1",
    sourceRevision,
    committeeApprovalSha256: record.committeeApproval.documentSha256,
    deploymentPlanSha256: record.deployment.planSha256,
    deploymentReceipt: record.deployment.result.receipt,
    releaseManifestSha256: createHash("sha256").update(manifest).digest("hex"),
    expectedGenesisHash,
    reviewerFingerprint: governanceFingerprint,
    reviewedReference: "governance-decision:deployed-local-committee",
    approvedAt: new Date().toISOString(),
    ...overrides,
  };
  const path = join(f.directory, "committee-deployment-approval.json");
  const signature = join(f.directory, "committee-deployment-approval.sig");
  await writeFile(path, JSON.stringify(document));
  await writeFile(signature, "test-only-committee-deployment-signature");
  return { path, signature, document };
}

async function approveCommitteeDeployment(f, overrides = {}) {
  const input = await committeeDeploymentDocument(f, overrides);
  return approveStandaloneCommitteeDeployment(
    f.directory, input.path, input.signature, f.keyring, governanceFingerprint,
    { verifyBundle: f.verifyBundle, verifySignature: async (_document, _signature, _keyring, fingerprint) => {
      assert.equal(fingerprint, governanceFingerprint);
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

test("unsigned genesis draft binds observed bytes but does not approve them", async () => {
  const f = await fixture();
  const proposal = { reviewerFingerprint, reviewedReference: "independent-chain-spec:sha256:example",
    approvedAt: new Date().toISOString() };
  await assert.rejects(draftStandaloneGenesisApproval(f.directory, {
    ...proposal,
  }), /Observe genesis before drafting/u);
  await observeStandaloneLedger(f.directory, f.pinPath, {
    preflight: async () => ({ kind: "local-node-observation-only" }),
  });
  await assert.rejects(draftStandaloneGenesisApproval(f.directory, {
    reviewerFingerprint, reviewedReference: proposal.reviewedReference,
  }), /human-supplied approval time/u);
  await assert.rejects(draftStandaloneGenesisApproval(f.directory, {
    ...proposal,
    privateKey: "must-not-be-accepted",
  }), /Canonical reviewer metadata/u);
  await assert.rejects(draftStandaloneGenesisApproval(f.directory, {
    ...proposal,
    reviewedReference: demoGenesisReference("standalone").exampleReference,
  }), /Canonical reviewer metadata/u);
  const result = await draftStandaloneGenesisApproval(f.directory, proposal);
  assert.equal(result.state, "unsigned-human-review-required");
  assert.equal((await lstat(result.path)).mode & 0o077, 0);
  const bytes = await readFile(result.path);
  const document = JSON.parse(bytes);
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(document.installInventorySha256, record.install.inventorySha256);
  assert.equal(document.setupId, record.setupId);
  assert.equal(document.stackProject, null);
  assert.equal(document.pinSha256, record.ledgerObservation.pinSha256);
  assert.equal(document.expectedGenesisHash, expectedGenesisHash);
  assert.equal(result.documentSha256, createHash("sha256").update(bytes).digest("hex"));
  assert.equal(record.genesisApproval, undefined);
  await assert.rejects(draftStandaloneGenesisApproval(f.directory, proposal), /EEXIST/u);
  const approved = await approveStandaloneGenesis(f.directory, result.path, f.signaturePath,
    f.keyring, reviewerFingerprint, { verifySignature: async () => {} });
  assert.equal(approved.documentSha256, result.documentSha256);
});

test("unsigned committee draft requires an approved genesis and release-grade custody", async () => {
  const f = await fixture();
  const proposal = { reviewerFingerprint: governanceFingerprint,
    reviewedReference: "governance-decision:local-release-committee",
    approvedAt: new Date().toISOString() };
  await assert.rejects(draftStandaloneCommitteeApproval(f.directory, proposal), /Approve genesis/u);
  await observeStandaloneLedger(f.directory, f.pinPath, {
    preflight: async () => ({ kind: "local-node-observation-only" }),
  });
  await approve(f);
  const { document } = await committeeDocument(f);
  const releaseProposal = { ...proposal,
    maintenancePolicy: document.maintenancePolicy, custodians: document.custodians };
  await assert.rejects(draftStandaloneCommitteeApproval(f.directory, {
    ...releaseProposal, maintenancePolicy: { ...document.maintenancePolicy, threshold: 1 },
  }), /threshold/u);
  await assert.rejects(draftStandaloneCommitteeApproval(f.directory, {
    ...releaseProposal, custodians: document.custodians.map((entry) => ({ ...entry, holderRole: "shared" })),
  }), /distinct holder roles/u);
  const result = await draftStandaloneCommitteeApproval(f.directory, releaseProposal);
  assert.equal(result.state, "unsigned-human-review-required");
  assert.equal((await lstat(result.path)).mode & 0o077, 0);
  const bytes = await readFile(result.path);
  const draft = JSON.parse(bytes);
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(draft.genesisApprovalSha256, record.genesisApproval.documentSha256);
  assert.deepEqual(draft.maintenancePolicy, document.maintenancePolicy);
  assert.deepEqual(draft.custodians, document.custodians);
  assert.equal(result.documentSha256, createHash("sha256").update(bytes).digest("hex"));
  assert.equal(record.committeeApproval, undefined);
  const approved = await approveStandaloneCommittee(f.directory, result.path,
    join(f.directory, "committee-approval.sig"), f.keyring, governanceFingerprint,
    { verifySignature: async () => {} });
  assert.equal(approved.documentSha256, result.documentSha256);
  assert.equal(approved.threshold, 2);
});

test("wizard prepares a private isolated stack without starting or approving it", async () => {
  const f = await fixture("tr-standalone-install-v3");
  const requested = { project: "tr-standalone-local-qualification", nodePort: "39944",
    indexerPort: "38088", proofPort: "36300" };
  const result = await prepareStandaloneStack(f.directory, requested, stackDependencies(f));
  assert.equal(result.project, requested.project);
  assert.equal(result.state, "prepared-runtime-unobserved");
  assert.equal((await lstat(result.envFile)).mode & 0o077, 0);
  const env = await readFile(result.envFile, "utf8");
  assert.match(env, /TR_STACK_NAME=tr-standalone-local-qualification/u);
  assert.match(env, /TR_NODE_PORT=39944/u);
  assert.match(env, /TR_PROOF_PARAMS_DIR=".*\/proof-params"/u);
  assert.match(env, /TR_INDEXER_PASSWORD=[0-9a-f]{48}/u);
  assert.match(env, /TR_INDEXER_SECRET=[0-9a-f]{64}/u);
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(record.stack.state, "prepared-runtime-unobserved");
  assert.ok(!JSON.stringify(record).includes(env.match(/TR_INDEXER_SECRET=([0-9a-f]{64})/u)[1]));
  const status = await standaloneSetupStatus(f.directory);
  assert.equal(status.stackConfiguration, "prepared-runtime-unobserved");
  assert.equal(status.localLedger, "pending");
  assert.deepEqual(status.restartObservation, { status: "pending" });
  assert.equal(status.restartRestore, "pending");
  assert.equal(status.releaseQualified, false);
  await assert.rejects(prepareStandaloneStack(f.directory, requested, stackDependencies(f)),
    /already prepared/u);
});

test("wizard refuses historical v2 bundles for a new stack", async () => {
  const f = await fixture("tr-standalone-install-v2");
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  await assert.rejects(initializeStandaloneSetup(join(f.directory, "new-setup"),
    record.install.bundle, { verifyBundle: f.verifyBundle }), /requires a verified runtime Compose pin/u);
  await assert.rejects(lstat(join(f.directory, "new-setup")), { code: "ENOENT" });
  await assert.rejects(prepareStandaloneStack(f.directory, {
    project: "tr-standalone-local-qualification", nodePort: "39944",
    indexerPort: "38088", proofPort: "36300",
  }, stackDependencies(f)), /requires a verified v3\/v4\/v5 runtime Compose pin/u);
  assert.equal((await standaloneSetupStatus(f.directory)).stackConfiguration, "pending");
});

test("legacy setup without a setup-bound approval cannot reserve deployment", async () => {
  const f = await fixture("tr-standalone-install-v2");
  await observeStandaloneLedger(f.directory, f.pinPath,
    { preflight: async () => ({ kind: "local-node-observation-only" }) });
  await approve(f);
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  delete record.setupId;
  await writeFile(recordPath, JSON.stringify(record));
  await assert.rejects(attemptStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    deploy: async () => { throw new Error("must not submit"); },
  }), /Legacy setup cannot submit/u);
  assert.equal((await standaloneSetupStatus(f.directory)).deployment, "pending");
});

test("invalid restart evidence does not hide deployment and maintenance alerts", async () => {
  const f = await fixture();
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  record.maintenanceAttempt = { state: "conflict", alert: "independent-human-recovery-required" };
  await writeFile(recordPath, JSON.stringify(record));
  await writeFile(join(f.directory, "restart-baseline.json"), "truncated", { mode: 0o600 });
  const status = await standaloneSetupStatus(f.directory);
  assert.equal(status.restartObservation.status, "invalid-evidence-investigate");
  assert.equal(status.maintenanceTransitionAlert, "independent-human-recovery-required");
  assert.equal(status.maintenanceTransition, "conflict");
  assert.equal(status.releaseQualified, false);
});

test("v4 setup retains the API image pin but does not claim it is running", async () => {
  const f = await fixture("tr-standalone-install-v4");
  await prepareStandaloneStack(f.directory, {
    project: "tr-standalone-local-qualification", nodePort: "39944",
    indexerPort: "38088", proofPort: "36300",
  }, stackDependencies(f));
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(record.install.verified.apiRuntime.imageId, `sha256:${"c".repeat(64)}`);
  const status = await standaloneSetupStatus(f.directory);
  assert.equal(status.localLedger, "pending");
  assert.equal(status.releaseQualified, false);
});

test("v5 setup retains portal pins without claiming actor runtime", async () => {
  const f = await fixture("tr-standalone-install-v5");
  await prepareStandaloneStack(f.directory, {
    project: "tr-standalone-local-qualification", nodePort: "39944",
    indexerPort: "38088", proofPort: "36300",
  }, stackDependencies(f));
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(record.install.verified.portalRuntimes.admin.imageId, `sha256:${"d".repeat(64)}`);
  assert.equal(record.install.verified.portalRuntimes.applicant.imageId, `sha256:${"e".repeat(64)}`);
  const status = await standaloneSetupStatus(f.directory);
  assert.equal(status.offlineJourneys, "pending");
  assert.equal(status.releaseQualified, false);
});

test("v3 setup cannot record genesis or draft approval before stack observation", async () => {
  const f = await fixture("tr-standalone-install-v3");
  const preflight = async () => { throw new Error("must not query node"); };
  await assert.rejects(observeStandaloneLedger(f.directory, f.pinPath, { preflight }),
    /Observe the prepared local stack/u);
  await prepareStandaloneStack(f.directory, {
    project: "tr-standalone-local-qualification", nodePort: "39944",
    indexerPort: "38088", proofPort: "36300",
  }, stackDependencies(f));
  await assert.rejects(observeStandaloneLedger(f.directory, f.pinPath, { preflight }),
    /Observe the prepared local stack/u);
  await assert.rejects(draftStandaloneGenesisApproval(f.directory, {
    reviewerFingerprint, reviewedReference: "independent-chain-spec:sha256:example",
    approvedAt: new Date().toISOString(),
  }), /Observe genesis before drafting/u);
});

test("stack observation rejects changed bundled Compose bytes", async () => {
  const f = await fixture("tr-standalone-install-v3");
  await prepareStandaloneStack(f.directory, {
    project: "tr-standalone-local-qualification", nodePort: "39944",
    indexerPort: "38088", proofPort: "36300",
  }, stackDependencies(f));
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  await writeFile(join(record.install.bundle, "compose.yml"), "name: altered\n");
  await assert.rejects(observeStandaloneStack(f.directory, {
    observeTopology: async () => { throw new Error("must not inspect Docker"); },
  }), /Runtime Compose changed/u);
});

test("wizard records only selected ledger-bridge topology and egress observations", async () => {
  const f = await fixture("tr-standalone-install-v3");
  const project = "tr-standalone-local-qualification";
  await prepareStandaloneStack(f.directory, { project, nodePort: "39944",
    indexerPort: "38088", proofPort: "36300" }, stackDependencies(f));
  await writeFile(f.pinPath, JSON.stringify({ ...pin, rpcUrl: "http://127.0.0.1:39944" }));
  const result = await observeStandaloneStack(f.directory, {
    observeTopology: async (config, expected) => {
      assert.equal(config.project, project);
      assert.match(expected.proofParamsDir, /\/proof-params$/u);
      assert.match(expected.indexerPassword, /^[0-9a-f]{48}$/u);
      assert.match(expected.indexerSecret, /^[0-9a-f]{64}$/u);
      assert.equal(expected.requirePrivateInputs, true);
      assert.equal(expected.allowUnpublishedHostPorts, true);
      assert.equal(expected.sourceRevision, sourceRevision);
      assert.equal(expected.images.length, 3);
      assert.equal(expected.composeFiles.length, 2);
      return { kind: "standalone-runtime-topology-observation", project, networkId: ledgerNetworkId,
        preparedInputsMatched: true, egressDenied: "not-verified", actorJourneys: "not-run" };
    },
    observeEgress: async ({ env, expectedTopology }) => {
      assert.equal(env.TR_STACK_NAME, project);
      assert.equal(env.TR_NODE_PORT, "39944");
      assert.equal(expectedTopology.sourceRevision, sourceRevision);
      assert.equal(expectedTopology.allowOffline, true);
      assert.equal(expectedTopology.images.length, 3);
      return { kind: "standalone-ledger-egress-probe", project, networkId: ledgerNetworkId,
        scope: "canary HTTPS and DNS on ledger bridge only" };
    },
  });
  assert.equal(result.state, "observed-ledger-bridge-only");
  const status = await standaloneSetupStatus(f.directory);
  assert.equal(status.stackConfiguration, "observed-ledger-bridge-only");
  assert.equal(status.localLedger, "pending");
  assert.equal(status.deployment, "pending");
  assert.equal(status.offlineJourneys, "pending");
  assert.equal(status.releaseQualified, false);
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(record.stack.observations.length, 1);
  assert.ok(Number.isFinite(Date.parse(record.stack.observation.observedAt)));
  await assert.rejects(observeStandaloneStack(f.directory, {
    observeTopology: async () => ({ project, networkId: ledgerNetworkId }),
    observeEgress: async () => ({ project, networkId: "replacement-ledger-id" }),
  }), /Stack observations disagree/u);
  await observeStandaloneStack(f.directory, {
    observeTopology: async () => ({ project, networkId: ledgerNetworkId }),
    observeEgress: async () => ({ project, networkId: ledgerNetworkId, canaryAddress: "192.0.2.1" }),
  });
  const repeated = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(repeated.stack.observations.length, 2);
  assert.equal(repeated.stack.observations[0].egress.scope,
    "canary HTTPS and DNS on ledger bridge only");
  assert.equal(repeated.stack.observations[1].egress.canaryAddress, "192.0.2.1");
  const envPath = join(f.directory, "stack.env");
  const preparedEnv = await readFile(envPath);
  await writeFile(envPath, preparedEnv.toString("utf8").replace("TR_NODE_PORT=39944", "TR_NODE_PORT=49944"));
  await assert.rejects(observeStandaloneLedger(f.directory, f.pinPath, {
    observeTopology: async () => { throw new Error("must not inspect Docker after env drift"); },
  }), /Prepared stack environment changed/u);
  await writeFile(envPath, preparedEnv);
  const composePath = join(repeated.install.bundle, "compose.yml");
  const preparedCompose = await readFile(composePath);
  await writeFile(composePath, "name: changed\n");
  await assert.rejects(observeStandaloneLedger(f.directory, f.pinPath, {
    observeTopology: async () => { throw new Error("must not inspect Docker after Compose drift"); },
  }), /Runtime Compose changed/u);
  await writeFile(composePath, preparedCompose);
  await assert.rejects(observeStandaloneLedger(f.directory, f.pinPath, {
    observeTopology: async () => { throw new Error("effective loopback port is absent"); },
    preflight: async () => { throw new Error("must not query genesis"); },
  }), /effective loopback port is absent/u);
  assert.equal((await standaloneSetupStatus(f.directory)).localLedger, "pending");
  await writeFile(f.pinPath, JSON.stringify(pin));
  await assert.rejects(observeStandaloneLedger(f.directory, f.pinPath, {
    observeTopology: async () => ({ project, networkId: ledgerNetworkId,
      internalNetworkOnly: true }),
    preflight: async () => { throw new Error("must not query another stack"); },
  }), /exact loopback RPC endpoint/u);
  await writeFile(f.pinPath, JSON.stringify({ ...pin, rpcUrl: "http://127.0.0.1:39944" }));
  await observeStandaloneLedger(f.directory, f.pinPath, {
    observeTopology: async (config, expected) => {
      assert.equal(config.project, project);
      assert.equal(expected.composeFiles.length, 2);
      assert.equal(expected.requirePrivateInputs, true);
      assert.equal(expected.allowUnpublishedHostPorts, false);
      assert.match(expected.indexerPassword, /^[0-9a-f]{48}$/u);
      return { project, networkId: ledgerNetworkId, internalNetworkOnly: true };
    },
    preflight: async () => ({ kind: "local-node-observation-only" }),
  });
  await assert.rejects(observeStandaloneStack(f.directory, {
    observeTopology: async () => { throw new Error("must not inspect topology"); },
  }), /cannot change after local-ledger observation/u);
});

test("genesis candidate is untrusted, non-overwriting, and cannot approve the node's own hash", async () => {
  const f = await fixture("tr-standalone-install-v3");
  const project = "tr-standalone-local-qualification";
  await prepareStandaloneStack(f.directory, { project, nodePort: "39944",
    indexerPort: "38088", proofPort: "36300" }, stackDependencies(f));
  await writeFile(f.pinPath, JSON.stringify({ ...pin, rpcUrl: "http://127.0.0.1:39944" }));
  await observeStandaloneStack(f.directory, {
    observeTopology: async () => ({ project, networkId: ledgerNetworkId, preparedInputsMatched: true,
      verifiedImageIdsMatched: true, bundleComposeFilesMatched: true }),
    observeEgress: async () => ({ project, networkId: ledgerNetworkId,
      kind: "standalone-ledger-egress-probe" }),
  });
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  const observed = { project, sourceRevision,
    installInventorySha256: record.install.inventorySha256,
    observerSha256: "c".repeat(64), genesisHash: expectedGenesisHash,
    finalizedHash: `0x${"d".repeat(64)}`, finalizedHeight: 11,
    observedAt: "2026-10-20T00:00:00.000Z" };
  await assert.rejects(collectStandaloneGenesisCandidate(f.directory, {
    observeSnapshot: async () => ({ ...observed, sourceRevision: "f".repeat(40) }),
  }), /candidate disagrees/u);
  await assert.rejects(collectStandaloneGenesisCandidate(f.directory, {
    observeSnapshot: async () => ({ ...observed, genesisHash: `0x${"0".repeat(64)}` }),
  }), /candidate disagrees/u);
  await assert.rejects(collectStandaloneGenesisCandidate(f.directory, {
    observeSnapshot: async () => ({ ...observed, observedAt: "2026-10-20" }),
  }), /candidate disagrees/u);
  const collected = await collectStandaloneGenesisCandidate(f.directory, {
    observeSnapshot: async (_root, options) => {
      assert.equal(options.allowUnpublishedHostPorts, true);
      return observed;
    },
  });
  const file = JSON.parse(await readFile(collected.path, "utf8"));
  assert.equal(file.nodeReportedGenesisHash, expectedGenesisHash);
  assert.equal(file.status, "untrusted-node-observation-independent-review-required");
  assert.equal((await lstat(collected.path)).mode & 0o077, 0);
  assert.equal((await standaloneSetupStatus(f.directory)).localLedger, "pending");
  await assert.rejects(collectStandaloneGenesisCandidate(f.directory, {
    observeSnapshot: async () => observed,
  }), { code: "EEXIST" });
  assert.equal((await readdir(f.directory)).some((name) => name.includes("genesis-candidate.untrusted.json.")), false);
  await observeStandaloneLedger(f.directory, f.pinPath, {
    observeTopology: async () => ({ project, networkId: ledgerNetworkId,
      internalNetworkOnly: true }),
    preflight: async () => ({ kind: "local-node-observation-only" }),
  });
  await assert.rejects(collectStandaloneGenesisCandidate(f.directory, {
    observeSnapshot: async () => observed,
  }), /before recording a genesis pin/u);
});

test("v6 genesis pin requires the same verified installation relay across preflight", async () => {
  const f = await fixture("tr-standalone-install-v6");
  const project = "tr-standalone-local-qualification";
  await prepareStandaloneStack(f.directory, { project, nodePort: "39944",
    indexerPort: "38088", proofPort: "36300" }, stackDependencies(f));
  await observeStandaloneStack(f.directory, {
    observeTopology: async () => ({ project, networkId: ledgerNetworkId,
      internalNetworkOnly: true, hostPortAccess: "unpublished-install-access-required" }),
    observeEgress: async () => ({ project, networkId: ledgerNetworkId }),
  });
  const relay = { kind: "standalone-install-relay-observation", project,
    networkId: ledgerNetworkId, relayId: "relay-id",
    ports: { node: "60944", indexer: "60888", "proof-server": "60630" },
    relayScriptSha256: "b".repeat(64),
    topology: { internalNetworkOnly: true, hostPortAccess: "unpublished-install-access-required" } };
  await writeFile(f.pinPath, JSON.stringify({ ...pin, rpcUrl: "http://127.0.0.1:60945" }));
  await assert.rejects(observeStandaloneLedger(f.directory, f.pinPath, {
    observeInstallRelay: async () => relay,
    preflight: async () => { throw new Error("must not query wrong port"); },
  }), /does not match the verified installation relay/u);
  await writeFile(f.pinPath, JSON.stringify({ ...pin, rpcUrl: "http://127.0.0.1:60944" }));
  let calls = 0;
  await assert.rejects(observeStandaloneLedger(f.directory, f.pinPath, {
    observeInstallRelay: async () => ({ ...relay, relayId: ++calls === 1 ? "relay-id" : "replacement" }),
    preflight: async () => ({ kind: "local-node-observation-only" }),
  }), /relay changed during genesis observation/u);
  assert.equal((await standaloneSetupStatus(f.directory)).localLedger, "pending");
  const observed = await observeStandaloneLedger(f.directory, f.pinPath, {
    observeInstallRelay: async (config, verified, expected) => {
      assert.equal(config.project, project);
      assert.equal(verified.installRelay.sha256, "b".repeat(64));
      assert.equal(expected.requirePrivateInputs, true);
      return relay;
    },
    preflight: async () => ({ kind: "local-node-observation-only" }),
  });
  assert.equal(observed.installAccess.relayId, "relay-id");
  assert.equal(observed.installAccess.installationOnly, true);
});

test("v6 deployment reservation rejects a changed installation relay", async () => {
  const f = await fixture("tr-standalone-install-v6");
  const project = "tr-standalone-local-qualification";
  await prepareStandaloneStack(f.directory, { project, nodePort: "39944",
    indexerPort: "38088", proofPort: "36300" }, stackDependencies(f));
  await observeStandaloneStack(f.directory, {
    observeTopology: async () => ({ project, networkId: ledgerNetworkId,
      internalNetworkOnly: true, hostPortAccess: "unpublished-install-access-required" }),
    observeEgress: async () => ({ project, networkId: ledgerNetworkId }),
  });
  const relay = { kind: "standalone-install-relay-observation", project,
    networkId: ledgerNetworkId, relayId: "relay-id",
    ports: { node: "60944", indexer: "60888", "proof-server": "60630" },
    relayScriptSha256: "b".repeat(64),
    topology: { internalNetworkOnly: true, hostPortAccess: "unpublished-install-access-required" } };
  const relayRpc = "http://127.0.0.1:60944";
  await writeFile(f.pinPath, JSON.stringify({ ...pin, rpcUrl: relayRpc }));
  await observeStandaloneLedger(f.directory, f.pinPath, {
    observeInstallRelay: async () => relay,
    preflight: async () => ({ kind: "local-node-observation-only" }),
  });
  const approval = JSON.parse(await readFile(f.approvalPath, "utf8"));
  approval.pinSha256 = createHash("sha256").update(await readFile(f.pinPath)).digest("hex");
  approval.rpcUrl = relayRpc;
  approval.stackProject = project;
  await writeFile(f.approvalPath, JSON.stringify(approval));
  await approve(f);
  const planDocument = JSON.parse(await readFile(f.planPath, "utf8"));
  planDocument.network.rpcUrl = relayRpc;
  planDocument.network.indexerHttpUrl = "http://127.0.0.1:60888/api/v4/graphql";
  planDocument.network.indexerWsUrl = "ws://127.0.0.1:60888/api/v4/graphql/ws";
  await writeFile(f.planPath, JSON.stringify(planDocument));
  const wrongIndexer = { ...planDocument, network: { ...planDocument.network,
    indexerHttpUrl: "http://127.0.0.1:60889/api/v4/graphql" } };
  await writeFile(f.planPath, JSON.stringify(wrongIndexer));
  await assert.rejects(attemptStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    observeInstallRelay: async () => relay,
    deploy: async () => { throw new Error("must not submit"); },
  }), /plan endpoints diverged/u);
  await writeFile(f.planPath, JSON.stringify(planDocument));
  await assert.rejects(attemptStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    observeInstallRelay: async () => ({ ...relay, relayId: "replacement" }),
    deploy: async () => { throw new Error("must not submit"); },
  }), /Verified installation relay changed/u);
  assert.equal((await standaloneSetupStatus(f.directory)).deployment, "pending");
  let observations = 0;
  await assert.rejects(attemptStandaloneDeployment(f.directory, f.planPath, {
    verifyBundle: f.verifyBundle,
    observeInstallRelay: async () => (++observations === 1 ? relay
      : { ...relay, relayId: "replacement" }),
    deploy: async () => ({ kind: "local-deployment-submission-observation", readbackStatus: "pending" }),
  }), /outcome is unknown/u);
  assert.equal(observations, 2);
  assert.equal((await standaloneSetupStatus(f.directory)).deployment, "unknown");
});

test("direct-loopback deployment rechecks topology and exact indexer endpoints", async () => {
  const f = await fixture("tr-standalone-install-v3");
  const project = "tr-standalone-local-qualification";
  await prepareStandaloneStack(f.directory, { project, nodePort: "39944",
    indexerPort: "38088", proofPort: "36300" }, stackDependencies(f));
  const topology = { project, networkId: ledgerNetworkId, internalNetworkOnly: true };
  await observeStandaloneStack(f.directory, {
    observeTopology: async () => topology,
    observeEgress: async () => ({ project, networkId: ledgerNetworkId }),
  });
  const rpcUrl = "http://127.0.0.1:39944";
  await writeFile(f.pinPath, JSON.stringify({ ...pin, rpcUrl }));
  await observeStandaloneLedger(f.directory, f.pinPath, {
    observeTopology: async () => topology,
    preflight: async () => ({ kind: "local-node-observation-only" }),
  });
  const approval = JSON.parse(await readFile(f.approvalPath, "utf8"));
  approval.pinSha256 = createHash("sha256").update(await readFile(f.pinPath)).digest("hex");
  approval.rpcUrl = rpcUrl;
  approval.stackProject = project;
  await writeFile(f.approvalPath, JSON.stringify(approval));
  await approve(f);
  const planDocument = JSON.parse(await readFile(f.planPath, "utf8"));
  planDocument.network.rpcUrl = rpcUrl;
  planDocument.network.indexerHttpUrl = "http://127.0.0.1:38088/api/v4/graphql";
  planDocument.network.indexerWsUrl = "ws://127.0.0.1:38088/api/v4/graphql/ws";
  await writeFile(f.planPath, JSON.stringify(planDocument));
  const deps = { verifyBundle: f.verifyBundle,
    deploy: async () => { throw new Error("must not submit"); } };
  await assert.rejects(attemptStandaloneDeployment(f.directory, f.planPath, {
    ...deps, observeTopology: async () => ({ ...topology, networkId: "replacement" }),
  }), /direct-loopback topology changed/u);
  const wrongIndexer = { ...planDocument, network: { ...planDocument.network,
    indexerHttpUrl: "http://127.0.0.1:38089/api/v4/graphql" } };
  await writeFile(f.planPath, JSON.stringify(wrongIndexer));
  await assert.rejects(attemptStandaloneDeployment(f.directory, f.planPath, {
    ...deps, observeTopology: async () => topology,
  }), /endpoints diverged/u);
  assert.equal((await standaloneSetupStatus(f.directory)).deployment, "pending");
});

test("interactive wizard stops when stack preparation is deferred", async () => {
  const f = await fixture("tr-standalone-install-v3");
  const prompts = [];
  let closed = false;
  await runStandaloneSetupInteractive(f.directory, {
    question: async (prompt) => { prompts.push(prompt); return ""; },
    close: () => { closed = true; },
  });
  assert.deepEqual(prompts, ["New local Compose project (blank to defer): "]);
  assert.equal(closed, true);
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(record.ledgerObservation, undefined);
  assert.equal(record.stack, undefined);
});

test("interactive wizard stops before genesis until the prepared stack is observed", async () => {
  const f = await fixture("tr-standalone-install-v3");
  const project = "tr-standalone-local-qualification";
  await prepareStandaloneStack(f.directory, { project, nodePort: "39944",
    indexerPort: "38088", proofPort: "36300" }, stackDependencies(f));
  const prompts = [];
  await runStandaloneSetupInteractive(f.directory, {
    question: async (prompt) => { prompts.push(prompt); return ""; },
    close: () => {},
  });
  assert.deepEqual(prompts, ["Start the reviewed stack, then type OBSERVE STACK (blank to stop): "]);
  assert.equal((await standaloneSetupStatus(f.directory)).stackConfiguration,
    "prepared-runtime-unobserved");
  assert.equal((await standaloneSetupStatus(f.directory)).localLedger, "pending");
  await assert.rejects(observeStandaloneLedger(f.directory, f.pinPath, {
    preflight: async () => { throw new Error("must not observe genesis"); },
  }), /Observe the prepared local stack/u);

  const answers = ["OBSERVE STACK", "", ""];
  let topologyCalled = false;
  await runStandaloneSetupInteractive(f.directory, {
    question: async (prompt) => { prompts.push(prompt); return answers.shift(); },
    close: () => {},
  }, { stackObservation: {
    observeTopology: async (_config, expected) => {
      assert.match(expected.indexerSecret, /^[0-9a-f]{64}$/u);
      topologyCalled = true;
      return { project, networkId: ledgerNetworkId, preparedInputsMatched: true };
    },
    observeEgress: async () => ({ project, networkId: ledgerNetworkId,
      scope: "ledger bridge only" }),
  } });
  assert.equal(topologyCalled, true);
  assert.equal(prompts.at(-1), "Independently reviewed local genesis pin JSON (blank to stop): ");
  assert.equal((await standaloneSetupStatus(f.directory)).stackConfiguration,
    "observed-ledger-bridge-only");
  assert.equal((await standaloneSetupStatus(f.directory)).localLedger, "pending");
});

test("interactive wizard collects an untrusted genesis candidate without pinning or approving it", async () => {
  const f = await fixture("tr-standalone-install-v3");
  const project = "tr-standalone-local-qualification";
  await prepareStandaloneStack(f.directory, { project, nodePort: "39944",
    indexerPort: "38088", proofPort: "36300" }, stackDependencies(f));
  await observeStandaloneStack(f.directory, {
    observeTopology: async () => ({ project, networkId: ledgerNetworkId, preparedInputsMatched: true,
      verifiedImageIdsMatched: true, bundleComposeFilesMatched: true }),
    observeEgress: async () => ({ project, networkId: ledgerNetworkId,
      kind: "standalone-ledger-egress-probe" }),
  });
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  const prompts = [];
  const answers = ["COLLECT", ""];
  await runStandaloneSetupInteractive(f.directory, {
    question: async (prompt) => { prompts.push(prompt); return answers.shift(); },
    close: () => {},
  }, { candidateObservation: {
    observeSnapshot: async () => ({ project, sourceRevision,
      installInventorySha256: record.install.inventorySha256,
      observerSha256: "c".repeat(64), genesisHash: expectedGenesisHash,
      finalizedHash: `0x${"d".repeat(64)}`, finalizedHeight: 11,
      observedAt: "2026-10-20T00:00:00.000Z" }),
  } });
  assert.deepEqual(prompts, [
    "Collect node-reported genesis candidate for independent review? Type COLLECT or leave blank: ",
    "Independently reviewed local genesis pin JSON (blank to stop): ",
  ]);
  assert.equal((await standaloneSetupStatus(f.directory)).localLedger, "pending");
  assert.equal((await standaloneSetupStatus(f.directory)).deployment, "pending");
  const candidate = JSON.parse(await readFile(join(f.directory, "genesis-candidate.untrusted.json"), "utf8"));
  assert.equal(candidate.status, "untrusted-node-observation-independent-review-required");
  const after = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(after.ledgerObservation, undefined);
  assert.equal(after.genesisApproval, undefined);
});

test("wizard rejects a changed private stack environment before observation", async () => {
  const f = await fixture("tr-standalone-install-v3");
  const prepared = await prepareStandaloneStack(f.directory, {
    project: "tr-standalone-local-qualification", nodePort: "39944",
    indexerPort: "38088", proofPort: "36300",
  }, stackDependencies(f));
  await writeFile(prepared.envFile, "TR_STACK_NAME=other\n");
  await assert.rejects(observeStandaloneStack(f.directory, {
    observeTopology: async () => { throw new Error("must not inspect topology"); },
  }), /environment changed/u);
  assert.equal((await standaloneSetupStatus(f.directory)).stackConfiguration,
    "prepared-runtime-unobserved");
});

test("wizard refuses to attribute a stack observation to changed setup metadata", async () => {
  const f = await fixture("tr-standalone-install-v3");
  await prepareStandaloneStack(f.directory, {
    project: "tr-standalone-local-qualification", nodePort: "39944",
    indexerPort: "38088", proofPort: "36300",
  }, stackDependencies(f));
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  record.stack.project = "tr-standalone-local-other";
  await writeFile(recordPath, JSON.stringify(record));
  await assert.rejects(observeStandaloneStack(f.directory, {
    observeTopology: async () => { throw new Error("must not inspect topology"); },
  }), /disagrees with the setup record/u);
});

test("wizard rejects unsafe stack names, reused ports, and changed install bytes", async () => {
  const f = await fixture("tr-standalone-install-v3");
  const requested = { project: "tr-standalone-local-qualification", nodePort: "39944",
    indexerPort: "38088", proofPort: "36300" };
  await assert.rejects(prepareStandaloneStack(f.directory, { ...requested,
    project: "mn-passport-sdk-localnet" }, stackDependencies(f)), /namespace/u);
  await assert.rejects(prepareStandaloneStack(f.directory, { ...requested,
    proofPort: "39944" }, stackDependencies(f)), /distinct/u);
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  const inventoryPath = join(record.install.bundle, "install-inventory.json");
  const inventory = JSON.parse(await readFile(inventoryPath, "utf8"));
  inventory.images[0].reference = `midnightntwrk/test@sha256:${"f".repeat(64)}`;
  await writeFile(inventoryPath, JSON.stringify(inventory));
  await assert.rejects(prepareStandaloneStack(f.directory, requested, stackDependencies(f)),
    /inventory changed/u);
  record.install.inventorySha256 = createHash("sha256")
    .update(await readFile(inventoryPath)).digest("hex");
  await writeFile(join(f.directory, "setup-record.json"), JSON.stringify(record));
  await assert.rejects(prepareStandaloneStack(f.directory, requested, stackDependencies(f)),
    /Compose images differ/u);
  await assert.rejects(lstat(join(f.directory, "stack.env")), { code: "ENOENT" });
});

test("wizard refuses a Compose project with existing containers or persistent resources", async () => {
  const project = "tr-standalone-local-qualification";
  const results = [
    { role: 0, existing: "container-id\n" },
    { role: 1, existing: `${project}_ledger\n` },
    { role: 2, existing: `${project}_node-data\n` },
    { role: 2, existing: `${project}_indexer-data\n` },
    { role: 3, existing: "leftover-egress-network\n" },
    { role: 4, existing: "leftover-wallet-volume\n" },
  ];
  for (const { role: selectedRole, existing } of results) {
    let calls = 0;
    await assert.rejects(assertUnusedStandaloneProject(project, async (_program, args) => {
      const role = args[0] === "ps" ? 0 : args[0] === "network"
        ? (args.includes("--filter") ? 3 : 1) : (args.includes("--filter") ? 4 : 2);
      calls += 1;
      return { stdout: role === selectedRole ? existing : "" };
    }), /already has/u);
    assert.equal(calls, 5);
  }
  await assert.doesNotReject(assertUnusedStandaloneProject(project,
    async (_program, args) => ({ stdout: args[0] === "volume" && !args.includes("--filter")
      ? "other-project_node-data\n" : "" })));
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
  await approveCommitteeDeployment(f);
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
    "deployment-bound-roster-signature-verified-transition-pending");
  assert.equal((await standaloneSetupStatus(f.directory)).releaseQualified, false);
  const changed = { ...f.request, sourceRevision: "f".repeat(40) };
  await writeFile(f.requestPath, JSON.stringify(changed));
  await assert.rejects(prepareStandaloneCommitteeTransition(f.directory, f.requestPath, {
    verifyBundle: f.verifyBundle, prepareTransition: async () => assert.fail("changed request"),
  }), /invalid shape or source revision/u);
});

test("committee transition requires signed approval of this finalized deployment", async () => {
  const f = await committeeTransitionFixture();
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  record.verifierKeyInsertions = { nextKey: { state: "verified" }, laterKey: { state: "verified" } };
  const binding = record.committeeDeploymentApproval;
  delete record.committeeDeploymentApproval;
  await writeFile(recordPath, JSON.stringify(record));
  await assert.rejects(prepareStandaloneCommitteeTransition(f.directory, f.requestPath, {
    verifyBundle: f.verifyBundle, prepareTransition: async () => assert.fail("unapproved deployment"),
  }), /Approved committee and finalized staged deployment/u);

  record.committeeDeploymentApproval = binding;
  record.deployment.result.receipt = { ...stagedReceipt, contractAddress: `0x${"e".repeat(64)}` };
  await writeFile(recordPath, JSON.stringify(record));
  await assert.rejects(prepareStandaloneCommitteeTransition(f.directory, f.requestPath, {
    verifyBundle: f.verifyBundle, prepareTransition: async () => assert.fail("changed contract"),
  }), /Signed committee deployment binding disagrees/u);

  record.deployment.result.receipt = stagedReceipt;
  record.committeeDeploymentApproval.documentSha256 = "f".repeat(64);
  await writeFile(recordPath, JSON.stringify(record));
  await assert.rejects(prepareStandaloneCommitteeTransition(f.directory, f.requestPath, {
    verifyBundle: f.verifyBundle, prepareTransition: async () => assert.fail("changed approval"),
  }), /Signed committee deployment binding disagrees/u);
});

test("deployment binding rejects a wrong contract or governance reviewer before signature verification", async () => {
  const f = await committeeTransitionFixture();
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  delete record.committeeDeploymentApproval;
  await writeFile(recordPath, JSON.stringify(record));
  const input = await committeeDeploymentDocument(f, {
    deploymentReceipt: { ...stagedReceipt, contractAddress: `0x${"e".repeat(64)}` },
  });
  await assert.rejects(approveStandaloneCommitteeDeployment(
    f.directory, input.path, input.signature, f.keyring, governanceFingerprint,
    { verifyBundle: f.verifyBundle, verifySignature: async () => assert.fail("wrong contract") },
  ), /does not bind the finalized install and contract/u);
  await assert.rejects(approveStandaloneCommitteeDeployment(
    f.directory, input.path, input.signature, f.keyring, reviewerFingerprint,
    { verifySignature: async () => assert.fail("wrong reviewer") },
  ), /requires the pinned governance reviewer/u);
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceApproval,
    "roster-signature-verified-deployment-binding-pending");
});

test("deployment binding refuses pending readback and cannot be replaced after approval", async () => {
  const f = await committeeTransitionFixture();
  const input = await committeeDeploymentDocument(f);
  await assert.rejects(approveStandaloneCommitteeDeployment(
    f.directory, input.path, input.signature, f.keyring, governanceFingerprint,
    { verifySignature: async () => assert.fail("duplicate approval") },
  ), /already recorded/u);
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  delete record.committeeDeploymentApproval;
  record.deployment.result.readbackStatus = "pending";
  await writeFile(recordPath, JSON.stringify(record));
  await assert.rejects(approveStandaloneCommitteeDeployment(
    f.directory, input.path, input.signature, f.keyring, governanceFingerprint,
    { verifySignature: async () => assert.fail("pending readback") },
  ), /finalized staged deployment/u);
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceApproval,
    "roster-signature-verified-deployment-binding-pending");
});

test("deployment binding rejects changed pins, malformed shape, and a missing reservation time", async () => {
  const f = await committeeTransitionFixture();
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  delete record.committeeDeploymentApproval;
  await writeFile(recordPath, JSON.stringify(record));
  const changes = [
    { committeeApprovalSha256: "f".repeat(64) },
    { deploymentPlanSha256: "f".repeat(64) },
    { releaseManifestSha256: "f".repeat(64) },
    { deploymentReceipt: { ...stagedReceipt, extra: true } },
    { unexpectedField: true },
    { approvedAt: new Date(Date.parse(record.deployment.reservedAt) - 1_000).toISOString() },
    { approvedAt: new Date(Date.now() + 1_000).toUTCString() },
    { approvedAt: new Date(Date.now() + 10 * 60_000).toISOString() },
  ];
  for (const change of changes) {
    const input = await committeeDeploymentDocument(f, change);
    await assert.rejects(approveStandaloneCommitteeDeployment(
      f.directory, input.path, input.signature, f.keyring, governanceFingerprint,
      { verifyBundle: f.verifyBundle, verifySignature: async () => assert.fail("invalid binding") },
    ), /does not bind the finalized install and contract/u);
  }
  delete record.deployment.reservedAt;
  await writeFile(recordPath, JSON.stringify(record));
  const input = await committeeDeploymentDocument(f);
  await assert.rejects(approveStandaloneCommitteeDeployment(
    f.directory, input.path, input.signature, f.keyring, governanceFingerprint,
    { verifyBundle: f.verifyBundle, verifySignature: async () => assert.fail("missing reservation time") },
  ), /does not bind the finalized install and contract/u);
});

test("deployment binding verifies the installed bundle and release manifest before approval", async () => {
  const f = await committeeTransitionFixture();
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  delete record.committeeDeploymentApproval;
  await writeFile(recordPath, JSON.stringify(record));
  const input = await committeeDeploymentDocument(f);
  await assert.rejects(approveStandaloneCommitteeDeployment(
    f.directory, input.path, input.signature, f.keyring, governanceFingerprint,
    { verifyBundle: async () => ({ sourceRevision: "f".repeat(40) }),
      verifySignature: async () => assert.fail("changed bundle") },
  ), /source revision changed/u);
  const malformed = JSON.stringify({ ...f.manifest, format: "invalid" });
  await writeFile(join(record.install.bundle, "release-manifest.json"), malformed);
  await writeFile(f.releaseManifestPath, malformed);
  await assert.rejects(approveStandaloneCommitteeDeployment(
    f.directory, input.path, input.signature, f.keyring, governanceFingerprint,
    { verifyBundle: f.verifyBundle,
      verifySignature: async () => assert.fail("invalid manifest") },
  ), /invalid source or format/u);
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
  assert.equal(signingRequest.committeeDeploymentApprovalSha256,
    record.committeeDeploymentApproval.documentSha256);
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

async function recoveryRequiredFixture() {
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
  const updated = JSON.parse(await readFile(recordPath, "utf8"));
  const now = Date.parse(f.request.expiresAt) + 11 * 60_000;
  const decision = {
    format: "tr-local-maintenance-no-journal-recovery-v1",
    decision: "authorize-new-attempt-after-absent-journal",
    sourceRevision,
    requestSha256: updated.maintenanceAttempt.requestSha256,
    signingRequestSha256: updated.maintenanceAttempt.signingRequestSha256,
    updateSha256: updated.maintenanceAttempt.updateSha256,
    approvedFinalizedBlockHash: updated.maintenanceAttempt.finalizedBlockHash,
    recoveryFinalizedBlockHash: `0x${"f".repeat(64)}`,
    expiredAt: f.request.expiresAt,
    reviewerFingerprint: governanceFingerprint,
    reviewedReference: "independent-local-finalized-chain-scan:case-1",
    approvedAt: new Date(now).toISOString(),
  };
  const decisionPath = join(f.directory, "committee-recovery-decision.json");
  const decisionSignaturePath = join(f.directory, "committee-recovery-decision.sig");
  await writeFile(decisionPath, JSON.stringify(decision));
  await writeFile(decisionSignaturePath, "test-only-recovery-signature");
  const dependencies = {
    verifyBundle: f.verifyBundle,
    prepareTransition: async (approval) => ({ ...await f.dependencies.prepareTransition(approval),
      finalizedBlockHash: `0x${"f".repeat(64)}` }),
    now: () => now,
    verifySignature: async (_document, _signature, _keyring, fingerprint) => {
      assert.equal(fingerprint, governanceFingerprint);
    },
  };
  return { ...f, decision, decisionPath, decisionSignaturePath, now, dependencies };
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
  const reserved = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(reserved.maintenanceAttempt.committeeDeploymentApprovalSha256,
    f.signingRequest.committeeDeploymentApprovalSha256);
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

test("legacy maintenance attempts remain read-only reconcilable without retrospective approval", async () => {
  const f = await preparedCommitteeFixture();
  await submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, {
      ...f.dependencies,
      loadMaterial: async () => ({ material: { providers: {}, stop: async () => {} } }),
      submit: async () => "legacy-maintenance-tx",
    },
  );
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  delete record.committeeDeploymentApproval;
  delete record.maintenanceAttempt.committeeDeploymentApprovalSha256;
  const saved = JSON.parse(await readFile(f.signingRequestPath, "utf8"));
  delete saved.committeeDeploymentApprovalSha256;
  const bytes = JSON.stringify(saved);
  await writeFile(f.signingRequestPath, bytes);
  record.maintenanceAttempt.signingRequestSha256 = createHash("sha256").update(bytes).digest("hex");
  await writeFile(recordPath, JSON.stringify(record));
  const input = await committeeDeploymentDocument(f);
  await assert.rejects(approveStandaloneCommitteeDeployment(
    f.directory, input.path, input.signature, f.keyring, governanceFingerprint,
    { verifySignature: async () => assert.fail("retrospective approval") },
  ), /maintenance attempt already exists/u);
  const result = await reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, {
      verifyBundle: f.verifyBundle,
      reconcile: async () => ({ status: "observed", txId: "legacy-maintenance-tx",
        finalizedBlockHash: `0x${"f".repeat(64)}` }),
    },
  );
  assert.equal(result.status, "observed");
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceApproval,
    "roster-signature-verified-deployment-binding-pending");
  await assert.rejects(prepareStandaloneCommitteeTransition(f.directory, f.requestPath, {
    verifyBundle: f.verifyBundle,
    prepareTransition: async () => assert.fail("legacy prepare"),
  }), /Approved committee and finalized staged deployment/u);
});

test("reconciliation rejects a partial deployment binding on an existing attempt", async () => {
  const f = await preparedCommitteeFixture();
  await submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, {
      ...f.dependencies,
      loadMaterial: async () => ({ material: { providers: {}, stop: async () => {} } }),
      submit: async () => "maintenance-tx",
    },
  );
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  const binding = record.committeeDeploymentApproval;
  delete record.committeeDeploymentApproval;
  await writeFile(recordPath, JSON.stringify(record));
  await assert.rejects(reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, {
      verifyBundle: f.verifyBundle, reconcile: async () => assert.fail("partial binding"),
    },
  ), /Approved committee and finalized staged deployment/u);
  record.committeeDeploymentApproval = binding;
  delete record.maintenanceAttempt.committeeDeploymentApprovalSha256;
  await writeFile(recordPath, JSON.stringify(record));
  await assert.rejects(reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, {
      verifyBundle: f.verifyBundle, reconcile: async () => assert.fail("partial attempt pin"),
    },
  ), /disagrees with the reserved signing request/u);
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

test("signed governance recovery unlocks only a fresh maintenance signing window", async () => {
  const f = await recoveryRequiredFixture();
  await writeFile(f.decisionPath, JSON.stringify({ ...f.decision,
    recoveryFinalizedBlockHash: `0x${"d".repeat(64)}` }));
  const result = await approveStandaloneCommitteeRecovery(
    f.directory, f.requestPath, f.signingRequestPath, f.decisionPath,
    f.decisionSignaturePath, f.keyring, governanceFingerprint, f.dependencies,
  );
  assert.equal(result.state, "recovered-no-journal-approved");
  assert.equal(result.recoveryFinalizedBlockHash, `0x${"f".repeat(64)}`);
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(record.maintenanceAttempt.recoveryApproval.reviewerFingerprint, governanceFingerprint);
  assert.equal(record.maintenanceAttempt.recoveryApproval.reviewerFinalizedBlockHash,
    `0x${"d".repeat(64)}`);
  assert.equal((await standaloneSetupStatus(f.directory)).releaseQualified, false);
  await assert.rejects(submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, f.dependencies,
  ), /fresh request and signing window/u);
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition,
    "recovered-no-journal-approved");
});

test("recovery refuses an attempt whose deployment approval pin changed", async () => {
  const f = await recoveryRequiredFixture();
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  record.maintenanceAttempt.committeeDeploymentApprovalSha256 = "f".repeat(64);
  await writeFile(recordPath, JSON.stringify(record));
  await assert.rejects(approveStandaloneCommitteeRecovery(
    f.directory, f.requestPath, f.signingRequestPath, f.decisionPath,
    f.decisionSignaturePath, f.keyring, governanceFingerprint, f.dependencies,
  ), /Recovery evidence disagrees/u);
});

test("legacy no-journal recovery requires an explicit migration decision", async () => {
  const f = await recoveryRequiredFixture();
  const recordPath = join(f.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  delete record.committeeDeploymentApproval;
  delete record.maintenanceAttempt.committeeDeploymentApprovalSha256;
  await writeFile(recordPath, JSON.stringify(record));
  await assert.rejects(approveStandaloneCommitteeRecovery(
    f.directory, f.requestPath, f.signingRequestPath, f.decisionPath,
    f.decisionSignaturePath, f.keyring, governanceFingerprint, f.dependencies,
  ), /operator-reviewed migration decision/u);
});

test("recovery permits one new signed request and retains the recovered attempt", async () => {
  const f = await recoveryRequiredFixture();
  await approveStandaloneCommitteeRecovery(
    f.directory, f.requestPath, f.signingRequestPath, f.decisionPath,
    f.decisionSignaturePath, f.keyring, governanceFingerprint, f.dependencies,
  );
  const newRequest = { ...f.request, expiresAt: new Date(f.now + 15 * 60_000).toISOString() };
  await writeFile(f.requestPath, JSON.stringify(newRequest));
  const newDependencies = {
    ...f.dependencies,
    prepareTransition: async (approval) => ({
      ...await f.dependencies.prepareTransition(approval),
      finalizedBlockHash: `0x${"f".repeat(64)}`,
    }),
    loadMaterial: async () => ({ material: { providers: {} } }),
    submit: async () => "fresh-recovery-transaction",
  };
  const signingRequest = await prepareStandaloneCommitteeTransition(
    f.directory, f.requestPath, newDependencies,
  );
  assert.equal(signingRequest.updateSha256, f.signingRequest.updateSha256);
  await writeFile(f.signingRequestPath, JSON.stringify(signingRequest));
  await writeFile(f.signaturePath, JSON.stringify({
    format: "tr-local-committee-signature-v1",
    updateSha256: signingRequest.updateSha256,
    signature: `0x${"a".repeat(128)}`,
  }));
  const result = await submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, newDependencies,
  );
  assert.equal(result.txId, "fresh-recovery-transaction");
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(record.maintenanceHistory.at(-1).state, "recovered-no-journal-approved");
  assert.equal(record.maintenanceAttempt.state, "submitted");
});

test("reconciliation preserves recovery approval only while journal absence remains confirmed", async () => {
  const f = await recoveryRequiredFixture();
  await approveStandaloneCommitteeRecovery(
    f.directory, f.requestPath, f.signingRequestPath, f.decisionPath,
    f.decisionSignaturePath, f.keyring, governanceFingerprint, f.dependencies,
  );
  await reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath,
    { verifyBundle: f.verifyBundle, reconcile: async () => ({ status: "not-reserved" }) },
  );
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition,
    "recovered-no-journal-approved");
  await reconcileStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath,
    { verifyBundle: f.verifyBundle, reconcile: async () => ({ status: "unresolved" }) },
  );
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(record.maintenanceAttempt.state, "conflict");
  assert.equal(record.maintenanceAttempt.alert, "post-recovery-evidence-contradiction");
});

test("recovered submission rejects the abandoned saved checkpoint", async () => {
  const f = await recoveryRequiredFixture();
  await approveStandaloneCommitteeRecovery(
    f.directory, f.requestPath, f.signingRequestPath, f.decisionPath,
    f.decisionSignaturePath, f.keyring, governanceFingerprint, f.dependencies,
  );
  await writeFile(f.requestPath, JSON.stringify({
    ...f.request, expiresAt: new Date(f.now + 15 * 60_000).toISOString(),
  }));
  const dependencies = {
    ...f.dependencies,
    prepareTransition: async (approval) => ({
      ...await f.dependencies.prepareTransition(approval),
      finalizedBlockHash: `0x${"f".repeat(64)}`,
    }),
  };
  const signingRequest = await prepareStandaloneCommitteeTransition(
    f.directory, f.requestPath, dependencies,
  );
  await writeFile(f.signingRequestPath, JSON.stringify({ ...signingRequest,
    finalizedBlockHash: f.signingRequest.finalizedBlockHash }));
  await assert.rejects(submitStandaloneCommitteeTransition(
    f.directory, f.requestPath, f.signingRequestPath, f.signaturePath, dependencies,
  ), /cannot reuse the abandoned finalized checkpoint/u);
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition,
    "recovered-no-journal-approved");
});

test("recovery rejects early, changed-image, and changed-decision evidence", async () => {
  const f = await recoveryRequiredFixture();
  const args = [f.directory, f.requestPath, f.signingRequestPath, f.decisionPath,
    f.decisionSignaturePath, f.keyring, governanceFingerprint];
  await assert.rejects(approveStandaloneCommitteeRecovery(...args, {
    ...f.dependencies, now: () => Date.parse(f.request.expiresAt) + 5 * 60_000,
  }), /must expire/u);
  await assert.rejects(approveStandaloneCommitteeRecovery(...args, {
    ...f.dependencies,
    prepareTransition: async (approval) => ({ ...await f.dependencies.prepareTransition(approval),
      dataToSign: Uint8Array.from([9, 9, 9]) }),
  }), /Finalized registry image changed/u);
  await writeFile(f.decisionPath, JSON.stringify({ ...f.decision, updateSha256: "0".repeat(64) }));
  await assert.rejects(approveStandaloneCommitteeRecovery(...args, f.dependencies),
    /does not bind the expired attempt/u);
  await writeFile(f.decisionPath, JSON.stringify({ ...f.decision,
    recoveryFinalizedBlockHash: f.signingRequest.finalizedBlockHash }));
  await assert.rejects(approveStandaloneCommitteeRecovery(...args, f.dependencies),
    /does not bind the expired attempt/u);
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition,
    "recovery-required-no-journal");
});

test("failed governance signature leaves maintenance recovery blocked", async () => {
  const f = await recoveryRequiredFixture();
  await assert.rejects(approveStandaloneCommitteeRecovery(
    f.directory, f.requestPath, f.signingRequestPath, f.decisionPath,
    f.decisionSignaturePath, f.keyring, governanceFingerprint, {
      ...f.dependencies,
      verifySignature: async () => { throw new Error("invalid detached signature"); },
    },
  ), /invalid detached signature/u);
  const record = JSON.parse(await readFile(join(f.directory, "setup-record.json"), "utf8"));
  assert.equal(record.maintenanceAttempt.state, "recovery-required-no-journal");
  assert.equal(record.maintenanceAttempt.recoveryApproval, undefined);
});

test("recovery refuses a present journal, attributed transaction, or unchanged finalized head", async () => {
  const journalFixture = await recoveryRequiredFixture();
  await writeFile(join(journalFixture.directory, "committee-transition.json"), "{}");
  await assert.rejects(approveStandaloneCommitteeRecovery(
    journalFixture.directory, journalFixture.requestPath, journalFixture.signingRequestPath,
    journalFixture.decisionPath, journalFixture.decisionSignaturePath,
    journalFixture.keyring, governanceFingerprint, journalFixture.dependencies,
  ));

  const attributedFixture = await recoveryRequiredFixture();
  const recordPath = join(attributedFixture.directory, "setup-record.json");
  const record = JSON.parse(await readFile(recordPath, "utf8"));
  record.maintenanceAttempt.reportedTxId = "possibly-broadcast";
  await writeFile(recordPath, JSON.stringify(record));
  await assert.rejects(approveStandaloneCommitteeRecovery(
    attributedFixture.directory, attributedFixture.requestPath,
    attributedFixture.signingRequestPath, attributedFixture.decisionPath,
    attributedFixture.decisionSignaturePath, attributedFixture.keyring,
    governanceFingerprint, attributedFixture.dependencies,
  ), /Only an unresolved pre-journal crash window/u);

  const staleFixture = await recoveryRequiredFixture();
  await assert.rejects(approveStandaloneCommitteeRecovery(
    staleFixture.directory, staleFixture.requestPath, staleFixture.signingRequestPath,
    staleFixture.decisionPath, staleFixture.decisionSignaturePath, staleFixture.keyring,
    governanceFingerprint, { ...staleFixture.dependencies,
      prepareTransition: async (approval) => ({
        ...await staleFixture.dependencies.prepareTransition(approval),
        finalizedBlockHash: staleFixture.signingRequest.finalizedBlockHash,
      }) },
  ), /Finalized registry image changed/u);
});

test("recovery refuses a reviewer fingerprint different from the approved roster", async () => {
  const f = await recoveryRequiredFixture();
  await assert.rejects(approveStandaloneCommitteeRecovery(
    f.directory, f.requestPath, f.signingRequestPath, f.decisionPath,
    f.decisionSignaturePath, f.keyring, reviewerFingerprint, f.dependencies,
  ), /does not bind the expired attempt/u);
  assert.equal((await standaloneSetupStatus(f.directory)).maintenanceTransition,
    "recovery-required-no-journal");
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

test("genesis approval cannot be replayed across setup directories", async () => {
  const first = await fixture();
  const second = await fixture();
  await observeStandaloneLedger(first.directory, first.pinPath,
    { preflight: async () => ({ kind: "local-node-observation-only" }) });
  await observeStandaloneLedger(second.directory, second.pinPath,
    { preflight: async () => ({ kind: "local-node-observation-only" }) });
  await assert.rejects(approveStandaloneGenesis(second.directory, first.approvalPath,
    first.signaturePath, second.keyring, reviewerFingerprint,
    { verifySignature: async () => { throw new Error("signature should not be checked"); } }), /does not bind/u);
  const secondRecord = JSON.parse(await readFile(join(second.directory, "setup-record.json"), "utf8"));
  assert.equal(secondRecord.genesisApproval, undefined);
});

test("signed release committee roster binds three distinct custodians but not a transition", async () => {
  const f = await fixture();
  await observeStandaloneLedger(f.directory, f.pinPath, { preflight: async () => ({ kind: "local-node-observation-only" }) });
  await approve(f);
  const result = await approveCommittee(f);
  assert.equal(result.threshold, 2);
  assert.equal(result.committeeSize, 3);
  const status = await standaloneSetupStatus(f.directory);
  assert.equal(status.maintenanceApproval, "roster-signature-verified-deployment-binding-pending");
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

test("synthetic demo reference cannot enter a signed genesis approval", async () => {
  const f = await fixture();
  await observeStandaloneLedger(f.directory, f.pinPath, {
    preflight: async () => ({ kind: "local-node-observation-only" }),
  });
  const document = JSON.parse(await readFile(f.approvalPath, "utf8"));
  document.reviewedReference = demoGenesisReference("preview").exampleReference;
  await writeFile(f.approvalPath, JSON.stringify(document));
  await assert.rejects(approve(f), /does not bind the current install and observed genesis/u);
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
  const armoredPublicKey = execFileSync("gpg", ["--homedir", signer, "--batch", "--armor",
    "--export", fingerprint]);
  execFileSync("gpg", ["--homedir", verifier, "--batch", "--import"], { input: publicKey, stdio: ["pipe", "pipe", "pipe"] });
  const document = join(root, "approval.json");
  const signature = join(root, "approval.sig");
  await writeFile(document, '{"format":"tr-local-genesis-approval-v1"}\n');
  execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--detach-sign", "--output", signature, document]);
  await verifyDetachedReviewerSignature(document, signature, verifier, fingerprint);
  const publicExport = join(root, "reviewer-public.asc");
  await writeFile(publicExport, armoredPublicKey, { mode: 0o600 });
  await verifyDetachedReviewerSignature(document, signature, publicExport, fingerprint);
  await assert.rejects(verifyDetachedReviewerSignature(document, signature, publicExport, "B".repeat(40)),
    /does not match/u);
  const invalidExport = join(root, "invalid-public.asc");
  await writeFile(invalidExport, "-----BEGIN PGP PRIVATE KEY BLOCK-----\n", { mode: 0o600 });
  await assert.rejects(verifyDetachedReviewerSignature(document, signature, invalidExport, fingerprint),
    /armored public-key export/u);
  const longKeyring = join(root, "nested-".repeat(10), "reviewer-".repeat(8));
  await mkdir(longKeyring, { recursive: true, mode: 0o700 });
  await writeFile(join(longKeyring, "pubring.kbx"), await readFile(join(verifier, "pubring.kbx")),
    { mode: 0o600 });
  await verifyDetachedReviewerSignature(document, signature, longKeyring, fingerprint);
  const unsupportedKeyring = join(root, "unsupported-keyring");
  await mkdir(unsupportedKeyring, { mode: 0o700 });
  await assert.rejects(verifyDetachedReviewerSignature(document, signature, unsupportedKeyring, fingerprint),
    /needs pubring\.kbx/u);
  const linkedKeyring = join(root, "linked-keyring");
  await mkdir(linkedKeyring, { mode: 0o700 });
  await symlink(join(verifier, "pubring.kbx"), join(linkedKeyring, "pubring.kbx"));
  await assert.rejects(verifyDetachedReviewerSignature(document, signature, linkedKeyring, fingerprint));
  await assert.rejects(verifyDetachedReviewerSignature(document, signature, verifier, "B".repeat(40)), /does not match/u);
  const attachedSignature = join(root, "attached.sig");
  execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--sign", "--output",
    attachedSignature, document]);
  const clearSignature = join(root, "clear.asc");
  execFileSync("gpg", ["--homedir", signer, "--batch", "--yes", "--clearsign", "--output",
    clearSignature, document]);
  const unrelatedDocument = join(root, "unrelated.json");
  await writeFile(unrelatedDocument, '{"format":"different"}\n');
  await assert.rejects(verifyDetachedReviewerSignature(unrelatedDocument, attachedSignature,
    verifier, fingerprint), /detached signature|not verified/u);
  await assert.rejects(verifyDetachedReviewerSignature(unrelatedDocument, clearSignature,
    verifier, fingerprint), /detached signature|not verified/u);
  await writeFile(document, '{"format":"tampered"}\n');
  await assert.rejects(verifyDetachedReviewerSignature(document, signature, verifier, fingerprint));
});
