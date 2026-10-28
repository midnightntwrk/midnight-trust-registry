#!/usr/bin/env node

import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFile } from "node:child_process";
import { constants, existsSync } from "node:fs";
import { link, open, lstat, mkdir, mkdtemp, realpath, rename, rm, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";
import { createInterface } from "node:readline/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import {
  FileMaintenanceTransitionJournal, prepareLocalNetworkCommitteeTransition,
  reconcileLocalNetworkCommitteeTransition, submitLocalNetworkCommitteeTransition,
  getLocalNetworkProfile,
  VerifierKeyInsertionOutcomeUnknownError,
} from "@midnight-ntwrk/trust-registry-integration";
import { assertStrictDetachedSignatureStatus } from "@midnight-ntwrk/trust-registry-integration/reviewer-signature-status";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { regularBytes } from "./standalone-private-file-bytes.mjs";
export { regularBytes } from "./standalone-private-file-bytes.mjs";
import { checkHelmImageMapping } from "./check-helm-image-mapping.mjs";
import { pinnedStandaloneImages } from "./build-standalone-install.mjs";
import { observeStandaloneEgress } from "./check-standalone-egress.mjs";
import { observeStandaloneLocalEgress } from "./check-standalone-local-egress.mjs";
import { observeStandaloneInstallRelay } from "./check-standalone-install-relay.mjs";
import { observeStandaloneTopology, standaloneStackConfig } from "./check-standalone-topology.mjs";
import {
  canonicalReviewerMetadata, reviewerProposal, validateReleaseCommittee,
} from "./standalone-approval-policy.mjs";
import { buildStandaloneApiApprovalChain } from "./standalone-api-approval-chain.mjs";
export { buildStandaloneApiApprovalChain } from "./standalone-api-approval-chain.mjs";
import { observeStandaloneRestartSnapshot, readStandaloneRestartEvidence } from "./check-standalone-restart.mjs";
import { checkLocalLedgerPreflight, validateStandaloneGenesisPin } from "./local-ledger-preflight.mjs";
import {
  loadApprovedMaintenanceMaterial, reconcileLocalDeployment, runLocalDeployment,
  validateLocalDeploymentPlan,
} from "./local-ledger-deploy.mjs";
import {
  runLocalVerifierKeyInsertion, validateLocalVerifierKeyInsertionPlan,
} from "./local-ledger-insert-verifier-key.mjs";

const FORMAT = "tr-standalone-setup-v1";
const STANDALONE_PROFILE = getLocalNetworkProfile();
const RECORD = "setup-record.json";
const FINGERPRINT = /^[A-F0-9]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;
/** @param {string | Buffer} bytes */
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
/** @param {Buffer} bytes */
const parseJsonBytes = (bytes) => JSON.parse(bytes.toString("utf8"));
const execFileAsync = promisify(execFile);
const composePath = resolve(dirname(fileURLToPath(import.meta.url)), "../deploy/standalone/compose.yml");
const offlineComposePath = resolve(dirname(fileURLToPath(import.meta.url)), "../deploy/standalone/compose.offline.yml");
const validLocalDeploymentReceipt = (receipt) => receipt?.networkId === STANDALONE_PROFILE.networkId
  && HASH.test(receipt.contractAddress) && !/^0x0{64}$/u.test(receipt.contractAddress)
  && HASH.test(receipt.blockHash) && !/^0x0{64}$/u.test(receipt.blockHash)
  && typeof receipt.txId === "string" && receipt.txId.length > 0
  && Number.isSafeInteger(receipt.blockHeight) && receipt.blockHeight >= 0;

function requireVerifiedInventoryBytes(verified, bytes, expectedSha256, message) {
  const hash = sha256(bytes);
  if (!SHA256.test(verified?.inventorySha256 ?? "")
    || verified.inventorySha256 !== hash
    || (expectedSha256 !== undefined && expectedSha256 !== hash)) {
    throw new Error(message);
  }
  return hash;
}

async function verifiedPackageManifestBytes(bundle, inventory, verified) {
  const pin = parseJsonBytes(inventory);
  const manifestBytes = await regularBytes(join(bundle, pin.packageManifest));
  if (!SHA256.test(pin.packageManifestSha256 ?? "")
    || !SHA256.test(verified?.packageManifestSha256 ?? "")
    || pin.packageManifestSha256 !== verified.packageManifestSha256
    || sha256(manifestBytes) !== verified.packageManifestSha256) {
    throw new Error("Installed release manifest changed since its inventory pin or bundle verification");
  }
  return manifestBytes;
}

function parseCanonicalSignedJson(bytes, label) {
  const raw = bytes.toString("utf8");
  const value = JSON.parse(raw);
  if (!Buffer.from(raw, "utf8").equals(bytes)
    || (raw !== JSON.stringify(value) && raw !== `${JSON.stringify(value, null, 2)}\n`)) {
    throw new Error(`${label} must use canonical signed JSON without duplicate keys`);
  }
  return value;
}

async function privateDirectory(path) {
  const stat = await lstat(path);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Setup directory must be owned by this user and accessible only to them");
  }
  return realpath(path);
}

async function readRecord(directory) {
  const root = await privateDirectory(resolve(directory));
  const record = JSON.parse((await regularBytes(join(root, RECORD), { privateFile: true })).toString("utf8"));
  if (record?.format !== FORMAT || typeof record?.sourceRevision !== "string") {
    throw new Error("Invalid standalone setup record");
  }
  if (record.networkProfile !== undefined
    && JSON.stringify(record.networkProfile) !== JSON.stringify(STANDALONE_PROFILE)) {
    throw new Error("Standalone network profile changed since setup initialization");
  }
  return { root, record };
}

async function writeRecord(root, record) {
  const temp = join(root, `.setup-record.${process.pid}.${Date.now()}.tmp`);
  const file = await open(temp, "wx", 0o600);
  try {
    await file.writeFile(`${JSON.stringify(record, null, 2)}\n`);
    await file.sync();
  } finally {
    await file.close();
  }
  await rename(temp, join(root, RECORD));
  const directory = await open(root, "r");
  try {
    await directory.sync();
  } finally {
    await directory.close();
  }
}

async function writePrivateSnapshot(path, bytes) {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`;
  const file = await open(temporary, "wx", 0o600);
  try {
    await file.writeFile(bytes);
    await file.sync();
  } finally {
    await file.close();
  }
  try {
    await link(temporary, path);
  } catch (error) {
    await unlink(temporary);
    throw error;
  }
  await unlink(temporary);
}

async function withLock(directory, action) {
  const root = await privateDirectory(resolve(directory));
  const lockPath = join(root, ".setup.lock");
  const lock = await open(lockPath, "wx", 0o600);
  try {
    await lock.close();
    return await action(root);
  } finally {
    await unlink(lockPath);
  }
}

export async function initializeStandaloneSetup(directory, bundleDirectory, dependencies = {}) {
  const bundle = await realpath(resolve(bundleDirectory));
  const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(bundle);
  const inventory = await regularBytes(join(bundle, "install-inventory.json"));
  const inventoryDocument = parseJsonBytes(inventory);
  requireVerifiedInventoryBytes(verified, inventory, undefined,
    "Verified install inventory changed during setup");
  await verifiedPackageManifestBytes(bundle, inventory, verified);
  if (inventoryDocument.sourceRevision !== verified.sourceRevision) {
    throw new Error("Verified install inventory changed during setup");
  }
  if (!SHA256.test(verified.runtimeComposeSha256 ?? "")
    || !SHA256.test(verified.runtimeOfflineComposeSha256 ?? "")
    || inventoryDocument.runtimeCompose?.sha256 !== verified.runtimeComposeSha256
    || inventoryDocument.runtimeCompose?.offlineSha256 !== verified.runtimeOfflineComposeSha256) {
    throw new Error("New standalone setup requires a verified runtime Compose pin");
  }
  const root = resolve(directory);
  await mkdir(root, { mode: 0o700 });
  const record = {
    format: FORMAT,
    setupId: randomUUID(),
    networkProfile: STANDALONE_PROFILE,
    sourceRevision: verified.sourceRevision,
    createdAt: new Date().toISOString(),
    install: { bundle, inventorySha256: verified.inventorySha256, verified },
  };
  await writeRecord(root, record);
  return record;
}

export async function checkStandaloneHelmBootstrapHandoff(directory, paths, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (record.stack || record.ledgerObservation || record.genesisApproval
      || record.deployment || record.committeeApproval || record.maintenanceAttempt) {
      throw new Error("Helm bootstrap requires a fresh setup; Compose ledger evidence cannot qualify a Helm target");
    }
    const inventoryBytes = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    const inventory = parseJsonBytes(inventoryBytes);
    if (sha256(inventoryBytes) !== record.install.inventorySha256
      || inventory.sourceRevision !== record.sourceRevision) {
      throw new Error("Helm bootstrap install inventory changed since wizard initialization");
    }
    if (inventory.format !== "tr-standalone-install-v6") {
      throw new Error("Helm bootstrap requires a v6 install bundle");
    }
    const mapping = await (dependencies.checkMapping ?? checkHelmImageMapping)({
      bundleRoot: record.install.bundle,
      valuesPath: paths.valuesPath,
      receiptPath: paths.receiptPath,
      signaturePath: paths.signaturePath,
      keyringPath: paths.keyringPath,
      signerFingerprint: paths.signerFingerprint,
    });
    if (mapping.sourceRevision !== record.sourceRevision
      || mapping.inventorySha256 !== record.install.inventorySha256
      || !SHA256.test(mapping.mappingSha256 ?? "")
      || mapping.deploymentPhase !== "bootstrap") {
      throw new Error("Signed Helm bootstrap mapping does not match this setup and its approved phase");
    }
    return {
      format: "tr-helm-bootstrap-handoff-v1",
      sourceRevision: record.sourceRevision,
      inventorySha256: record.install.inventorySha256,
      mappingSha256: mapping.mappingSha256,
      deploymentPhase: "bootstrap",
      targetGenesisApproval: "pending",
      releaseQualified: false,
    };
  });
}

export async function assertUnusedStandaloneProject(project, command = execFileAsync) {
  const options = { timeout: 10_000, maxBuffer: 1024 * 1024 };
  const [containers, networks, volumes, labeledNetworks, labeledVolumes] = await Promise.all([
    command("docker", ["ps", "-aq", "--filter", `label=com.docker.compose.project=${project}`], options),
    command("docker", ["network", "ls", "--format", "{{.Name}}"], options),
    command("docker", ["volume", "ls", "--format", "{{.Name}}"], options),
    command("docker", ["network", "ls", "--filter", `label=com.docker.compose.project=${project}`,
      "--format", "{{.Name}}"], options),
    command("docker", ["volume", "ls", "--filter", `label=com.docker.compose.project=${project}`,
      "--format", "{{.Name}}"], options),
  ]);
  const names = (result) => result.stdout.trim().split("\n").filter(Boolean);
  if (names(containers).length > 0 || names(networks).includes(`${project}_ledger`)
    || names(volumes).includes(`${project}_node-data`)
    || names(volumes).includes(`${project}_indexer-data`)
    || names(labeledNetworks).length > 0 || names(labeledVolumes).length > 0) {
    throw new Error("Selected local Compose project already has containers, a network, or persistent volumes");
  }
}

export async function prepareStandaloneStack(directory, requested, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (record.stack || record.ledgerObservation || record.deployment) {
      throw new Error("Stack configuration is already prepared or local-ledger observation has started");
    }
    if (!requested || typeof requested.project !== "string"
      || typeof requested.nodePort !== "string"
      || typeof requested.indexerPort !== "string"
      || typeof requested.proofPort !== "string") {
      throw new Error("An explicit local stack project and three loopback ports are required");
    }
    const config = standaloneStackConfig({
      TR_STACK_NAME: requested.project,
      COMPOSE_PROJECT_NAME: requested.project,
      TR_NODE_PORT: requested.nodePort,
      TR_INDEXER_PORT: requested.indexerPort,
      TR_PROOF_PORT: requested.proofPort,
    });
    const inventoryBytes = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    if (sha256(inventoryBytes) !== record.install.inventorySha256) {
      throw new Error("Installed inventory changed since setup verification");
    }
    const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(record.install.bundle);
    requireVerifiedInventoryBytes(verified, inventoryBytes, record.install.inventorySha256,
      "Verified install inventory changed since setup verification");
    if (verified.sourceRevision !== record.sourceRevision) {
      throw new Error("Verified install source revision changed");
    }
    if (!SHA256.test(verified.runtimeComposeSha256 ?? "")
      || !SHA256.test(verified.runtimeOfflineComposeSha256 ?? "")
      || parseJsonBytes(inventoryBytes).runtimeCompose?.sha256 !== verified.runtimeComposeSha256
      || parseJsonBytes(inventoryBytes).runtimeCompose?.offlineSha256 !== verified.runtimeOfflineComposeSha256) {
      throw new Error("New standalone setup requires a verified v3/v4/v5 runtime Compose pin");
    }
    const composeBytes = await regularBytes(composePath);
    if (sha256(composeBytes) !== verified.runtimeComposeSha256
      || sha256(await regularBytes(offlineComposePath)) !== verified.runtimeOfflineComposeSha256) {
      throw new Error("Current runtime Compose differs from the verified install bundle");
    }
    const installedImages = parseJsonBytes(inventoryBytes).images;
    const pinnedImages = pinnedStandaloneImages(composeBytes.toString("utf8"));
    if (!Array.isArray(installedImages) || installedImages.length !== pinnedImages.length
      || pinnedImages.some(({ role, reference }) => !installedImages.some((image) =>
        image.role === role && image.reference === reference))) {
      throw new Error("Current Compose images differ from the verified install bundle");
    }
    await (dependencies.assertProjectUnused ?? assertUnusedStandaloneProject)(config.project);
    const proofDirectory = join(record.install.bundle, "proof-params");
    if (!(await lstat(proofDirectory)).isDirectory()
      || !/^[A-Za-z0-9_./ -]+$/u.test(proofDirectory)) {
      throw new Error("Pinned proof-parameter path is not safe for a Compose environment file");
    }
    const envFile = join(root, "stack.env");
    const envBytes = Buffer.from([
      `TR_STACK_NAME=${config.project}`,
      `COMPOSE_PROJECT_NAME=${config.project}`,
      `TR_NODE_PORT=${config.ports.node}`,
      `TR_INDEXER_PORT=${config.ports.indexer}`,
      `TR_PROOF_PORT=${config.ports["proof-server"]}`,
      `TR_NETWORK_ID=${STANDALONE_PROFILE.networkId}`,
      `TR_PROOF_PARAMS_DIR=${JSON.stringify(proofDirectory)}`,
      `TR_INDEXER_PASSWORD=${randomBytes(24).toString("hex")}`,
      `TR_INDEXER_SECRET=${randomBytes(32).toString("hex")}`,
      "",
    ].join("\n"));
    await writePrivateSnapshot(envFile, envBytes);
    record.stack = {
      project: config.project,
      ports: config.ports,
      envFileSha256: sha256(envBytes),
      composeSha256: verified.runtimeComposeSha256,
      offlineComposeSha256: verified.runtimeOfflineComposeSha256,
      preparedAt: new Date().toISOString(),
      state: "prepared-runtime-unobserved",
    };
    await writeRecord(root, record);
    return { project: config.project, ports: config.ports, envFile, state: record.stack.state };
  });
}

async function preparedStandaloneTopology(root, record) {
    if (!record.stack) throw new Error("Prepare an isolated stack before observing it");
    if (record.install.verified?.runtimeComposeSha256
      && !Array.isArray(record.install.verified.images)) {
      throw new Error("Verified install image identities are missing from setup");
    }
    const envBytes = await regularBytes(join(root, "stack.env"));
    if (sha256(envBytes) !== record.stack.envFileSha256) {
      throw new Error("Prepared stack environment changed since setup");
    }
    if (record.stack.composeSha256
      && sha256(await regularBytes(join(record.install.bundle, "compose.yml")))
        !== record.stack.composeSha256) {
      throw new Error("Runtime Compose changed since stack preparation");
    }
    if (record.stack.offlineComposeSha256
      && sha256(await regularBytes(join(record.install.bundle, "compose.offline.yml")))
        !== record.stack.offlineComposeSha256) {
      throw new Error("Offline Compose changed since stack preparation");
    }
    const config = standaloneStackConfig({
      TR_STACK_NAME: record.stack.project,
      COMPOSE_PROJECT_NAME: record.stack.project,
      TR_NODE_PORT: record.stack.ports.node,
      TR_INDEXER_PORT: record.stack.ports.indexer,
      TR_PROOF_PORT: record.stack.ports["proof-server"],
    });
    const lines = envBytes.toString("utf8").trimEnd().split("\n");
    const entries = lines.map((line) => line.split("=", 2));
    const selected = Object.fromEntries(entries);
    const expectedEnvCount = record.networkProfile ? 9 : 8;
    if (entries.length !== expectedEnvCount || Object.keys(selected).length !== expectedEnvCount
      || selected.TR_STACK_NAME !== config.project
      || selected.COMPOSE_PROJECT_NAME !== config.project
      || selected.TR_NODE_PORT !== config.ports.node
      || selected.TR_INDEXER_PORT !== config.ports.indexer
      || selected.TR_PROOF_PORT !== config.ports["proof-server"]
      || (record.networkProfile && selected.TR_NETWORK_ID !== STANDALONE_PROFILE.networkId)) {
      throw new Error("Prepared stack environment disagrees with the setup record");
    }
    let proofParamsDir;
    try {
      proofParamsDir = JSON.parse(selected.TR_PROOF_PARAMS_DIR);
    } catch {
      throw new Error("Prepared proof-parameter path is malformed");
    }
    if (proofParamsDir !== join(record.install.bundle, "proof-params")
      || !/^[0-9a-f]{48}$/u.test(selected.TR_INDEXER_PASSWORD ?? "")
      || !/^[0-9a-f]{64}$/u.test(selected.TR_INDEXER_SECRET ?? "")) {
      throw new Error("Prepared private stack inputs disagree with the install bundle");
    }
    const expectedTopology = {
      requirePrivateInputs: true,
      allowUnpublishedHostPorts: true,
      proofParamsDir,
      indexerPassword: selected.TR_INDEXER_PASSWORD,
      indexerSecret: selected.TR_INDEXER_SECRET,
      ...(record.install.verified?.runtimeComposeSha256 ? {
        sourceRevision: record.install.verified.sourceRevision,
        images: record.install.verified.images,
        apiRuntime: record.install.verified.apiRuntime,
        installRelay: record.install.verified.installRelay,
        allowOffline: true,
        composeFiles: [join(record.install.bundle, "compose.yml"),
          join(record.install.bundle, "compose.offline.yml")],
      } : {}),
    };
    return { config, expectedTopology };
}

function requireVerifiedStandaloneStack(record) {
  const access = record.ledgerObservation?.installAccess;
  if (!SHA256.test(record.install?.verified?.runtimeComposeSha256 ?? "")
    || !SHA256.test(record.install?.verified?.runtimeOfflineComposeSha256 ?? "")
    || !record.stack?.observation
    || typeof record.stack.project !== "string"
    || !["effective-direct-loopback", "standalone-install-relay-observation"].includes(access?.kind)
    || access.networkId !== record.stack.observation.topology?.networkId) {
    throw new Error("A verified observed standalone stack is required before approval or deployment");
  }
}

export async function observeStandaloneStack(directory, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (!record.stack) throw new Error("Prepare an isolated stack before observing it");
    if (record.ledgerObservation || record.deployment) {
      throw new Error("Stack observations cannot change after local-ledger observation begins");
    }
    const observations = record.stack.observations ?? (record.stack.observation
      ? [record.stack.observation] : []);
    if (!Array.isArray(observations) || observations.length >= 20) {
      throw new Error("Stack observation history is full or malformed");
    }
    const { config, expectedTopology } = await preparedStandaloneTopology(root, record);
    const controlSubnet = dependencies.egressControlSubnet ?? process.env.TR_EGRESS_CONTROL_SUBNET;
    const topology = await (dependencies.observeTopology ?? observeStandaloneTopology)(config,
      expectedTopology);
    const egress = await (dependencies.observeEgress ?? (expectedTopology.installRelay
      ? observeStandaloneLocalEgress : observeStandaloneEgress))({
      env: {
        TR_STACK_NAME: config.project,
        COMPOSE_PROJECT_NAME: config.project,
        TR_NODE_PORT: config.ports.node,
        TR_INDEXER_PORT: config.ports.indexer,
        TR_PROOF_PORT: config.ports["proof-server"],
        ...(controlSubnet === undefined ? {} : { TR_EGRESS_CONTROL_SUBNET: controlSubnet }),
      },
      expectedTopology,
    });
    if (topology.project !== config.project || egress.project !== config.project
      || typeof topology.networkId !== "string" || topology.networkId.length === 0
      || egress.networkId !== topology.networkId) {
      throw new Error("Stack observations disagree with the selected project");
    }
    record.stack.observation = { observedAt: new Date().toISOString(), topology, egress };
    record.stack.observations = [...observations, record.stack.observation];
    record.stack.state = "observed-ledger-bridge-only";
    await writeRecord(root, record);
    return { project: config.project, state: record.stack.state,
      observation: record.stack.observation };
  });
}

export async function collectStandaloneGenesisCandidate(directory, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (!record.install.verified?.runtimeComposeSha256 || !record.stack?.observation
      || record.ledgerObservation || record.genesisApproval || record.deployment) {
      throw new Error("Collect a candidate only from an observed stack before recording a genesis pin");
    }
    let snapshot;
    try {
      snapshot = await (dependencies.observeSnapshot ?? observeStandaloneRestartSnapshot)(root,
        { allowUnpublishedHostPorts: true });
    } catch (error) {
      if (error instanceof Error
        && error.message === "Dedicated ledger network has a missing or extra container attachment") {
        throw new Error("Genesis collection requires only the three ledger containers; inspect attachments and remove any verified temporary install relay before retrying", { cause: error });
      }
      throw error;
    }
    if (snapshot.project !== record.stack.project
      || snapshot.sourceRevision !== record.sourceRevision
      || snapshot.installInventorySha256 !== record.install.inventorySha256
      || !SHA256.test(snapshot.observerSha256 ?? "")
      || !HASH.test(snapshot.genesisHash ?? "")
      || /^0x0{64}$/u.test(snapshot.genesisHash)
      || !HASH.test(snapshot.finalizedHash ?? "")
      || !Number.isSafeInteger(snapshot.finalizedHeight) || snapshot.finalizedHeight < 1
      || !Number.isFinite(Date.parse(snapshot.observedAt ?? ""))
      || new Date(Date.parse(snapshot.observedAt)).toISOString() !== snapshot.observedAt) {
      throw new Error("Untrusted node candidate disagrees with the observed install");
    }
    const candidate = {
      format: "tr-local-genesis-candidate-v1",
      sourceRevision: record.sourceRevision,
      installInventorySha256: record.install.inventorySha256,
      project: record.stack.project,
      networkId: STANDALONE_PROFILE.networkId,
      nodeReportedGenesisHash: snapshot.genesisHash,
      nodeReportedFinalizedBlockHash: snapshot.finalizedHash,
      nodeReportedFinalizedHeight: snapshot.finalizedHeight,
      observerSha256: snapshot.observerSha256,
      observedAt: snapshot.observedAt,
      status: "untrusted-node-observation-independent-review-required",
    };
    const path = join(root, "genesis-candidate.untrusted.json");
    const bytes = Buffer.from(`${JSON.stringify(candidate, null, 2)}\n`);
    await writePrivateSnapshot(path, bytes);
    return { path, candidateSha256: sha256(bytes), status: candidate.status };
  });
}

/** Drafts an untrusted pin from the current installation access path; never approves it. */
export async function draftStandaloneGenesisPin(directory, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (!record.install.verified?.runtimeComposeSha256 || !record.stack?.observation
      || record.ledgerObservation || record.genesisApproval || record.deployment) {
      throw new Error("Draft a genesis pin only from an observed, pre-approval standalone stack");
    }
    const candidateBytes = await regularBytes(join(root, "genesis-candidate.untrusted.json"));
    const candidate = parseJsonBytes(candidateBytes);
    if (!Buffer.from(`${JSON.stringify(candidate, null, 2)}\n`).equals(candidateBytes)
      || candidate?.format !== "tr-local-genesis-candidate-v1"
      || Object.keys(candidate).sort().join("\0") !== [
        "format", "installInventorySha256", "networkId", "nodeReportedFinalizedBlockHash",
        "nodeReportedFinalizedHeight", "nodeReportedGenesisHash", "observedAt",
        "observerSha256", "project", "sourceRevision", "status",
      ].sort().join("\0")
      || candidate.status !== "untrusted-node-observation-independent-review-required"
      || candidate.sourceRevision !== record.sourceRevision
      || candidate.installInventorySha256 !== record.install.inventorySha256
      || candidate.project !== record.stack.project || candidate.networkId !== STANDALONE_PROFILE.networkId
      || !HASH.test(candidate.nodeReportedGenesisHash)
      || /^0x0{64}$/u.test(candidate.nodeReportedGenesisHash)
      || !HASH.test(candidate.nodeReportedFinalizedBlockHash)
      || /^0x0{64}$/u.test(candidate.nodeReportedFinalizedBlockHash)
      || !Number.isSafeInteger(candidate.nodeReportedFinalizedHeight)
      || candidate.nodeReportedFinalizedHeight < 1
      || !SHA256.test(candidate.observerSha256)
      || !Number.isFinite(Date.parse(candidate.observedAt ?? ""))
      || new Date(Date.parse(candidate.observedAt)).toISOString() !== candidate.observedAt) {
      throw new Error("Untrusted genesis candidate is malformed or disagrees with the observed install");
    }
    const { config, expectedTopology } = await preparedStandaloneTopology(root, record);
    const observedNetworkId = record.stack.observation.topology?.networkId;
    let rpcPort;
    let accessKind;
    let accessObservation;
    if (record.stack.observation.topology?.hostPortAccess === "effective-loopback") {
      const current = await (dependencies.observeTopology ?? observeStandaloneTopology)(config,
        { ...expectedTopology, allowUnpublishedHostPorts: false });
      if (current.project !== config.project || current.networkId !== observedNetworkId
        || current.internalNetworkOnly !== true || current.hostPortAccess !== "effective-loopback") {
        throw new Error("Direct loopback access changed since the stack observation");
      }
      rpcPort = config.ports.node;
      accessKind = "effective-direct-loopback";
      accessObservation = current;
    } else if (record.stack.observation.topology?.hostPortAccess
      === "unpublished-install-access-required" && record.install.verified.installRelay) {
      const current = await (dependencies.observeInstallRelay ?? observeStandaloneInstallRelay)(
        config, record.install.verified, expectedTopology);
      if (current.kind !== "standalone-install-relay-observation"
        || current.project !== config.project || current.networkId !== observedNetworkId
        || current.topology?.internalNetworkOnly !== true
        || current.topology?.hostPortAccess !== "unpublished-install-access-required") {
        throw new Error("Verified installation relay disagrees with the observed stack");
      }
      rpcPort = current.ports.node;
      accessKind = current.kind;
      accessObservation = current;
    } else {
      throw new Error("A verified loopback or installation relay path is required to draft a genesis pin");
    }
    if (typeof rpcPort !== "string" || !/^[1-9][0-9]*$/u.test(rpcPort)
      || Number(rpcPort) < 1024 || Number(rpcPort) > 65535) {
      throw new Error("Verified installation access has no valid loopback RPC port");
    }
    const pin = {
      format: "tr-local-ledger-pin-v1",
      networkId: STANDALONE_PROFILE.networkId,
      sourceRevision: record.sourceRevision,
      rpcUrl: `http://127.0.0.1:${rpcPort}`,
      expectedGenesisHash: candidate.nodeReportedGenesisHash,
      allowedHosts: ["127.0.0.1"],
    };
    await (dependencies.preflight ?? checkLocalLedgerPreflight)(pin);
    if (accessKind === "effective-direct-loopback") {
      const current = await (dependencies.observeTopology ?? observeStandaloneTopology)(config,
        { ...expectedTopology, allowUnpublishedHostPorts: false });
      if (current.project !== accessObservation.project
        || current.networkId !== accessObservation.networkId
        || current.internalNetworkOnly !== true
        || current.hostPortAccess !== "effective-loopback") {
        throw new Error("Direct loopback access changed during genesis pin draft");
      }
    } else {
      const current = await (dependencies.observeInstallRelay ?? observeStandaloneInstallRelay)(
        config, record.install.verified, expectedTopology);
      if (current.relayId !== accessObservation.relayId
        || current.networkId !== accessObservation.networkId
        || JSON.stringify(current.ports) !== JSON.stringify(accessObservation.ports)
        || current.relayScriptSha256 !== accessObservation.relayScriptSha256) {
        throw new Error("Installation relay changed during genesis pin draft");
      }
    }
    const bytes = Buffer.from(`${JSON.stringify(pin, null, 2)}\n`);
    const path = join(root, "genesis-pin.proposed.json");
    await writePrivateSnapshot(path, bytes);
    return { path, pinSha256: sha256(bytes), candidateSha256: sha256(candidateBytes),
      accessKind, status: "untrusted-proposal-independent-review-required" };
  });
}

export async function observeStandaloneLedger(directory, pinPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (record.deployment) throw new Error("Cannot replace the genesis pin after deployment was reserved");
    if (record.genesisApproval) throw new Error("Cannot replace the genesis observation after reviewer approval");
    if (record.install.verified?.runtimeComposeSha256 && !record.stack?.observation) {
      throw new Error("Observe the prepared local stack before recording its genesis pin");
    }
    const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    requireVerifiedInventoryBytes(record.install.verified, inventory, record.install.inventorySha256,
      "Installed inventory changed since setup verification");
    const pinBytes = await regularBytes(resolve(pinPath));
    const pin = validateStandaloneGenesisPin(parseJsonBytes(pinBytes), record.sourceRevision);
    let installAccess;
    if (record.install.verified?.runtimeComposeSha256) {
      const { config, expectedTopology } = await preparedStandaloneTopology(root, record);
      const directUrl = `http://127.0.0.1:${record.stack.ports.node}`;
      if (pin.rpcUrl === directUrl) {
        const current = await (dependencies.observeTopology ?? observeStandaloneTopology)(config,
          { ...expectedTopology, allowUnpublishedHostPorts: false });
        if (current.project !== record.stack.project
          || current.networkId !== record.stack.observation.topology.networkId
          || current.internalNetworkOnly !== true) {
          throw new Error("Current ledger topology disagrees with the recorded stack observation");
        }
        installAccess = { kind: "effective-direct-loopback", networkId: current.networkId };
      } else {
        if (!record.install.verified.installRelay) {
          throw new Error("Genesis pin must target the prepared stack's exact loopback RPC endpoint");
        }
        const current = await (dependencies.observeInstallRelay ?? observeStandaloneInstallRelay)(
          config, record.install.verified, expectedTopology);
        if (current.project !== record.stack.project
          || current.networkId !== record.stack.observation.topology.networkId
          || current.topology?.internalNetworkOnly !== true
          || current.topology?.hostPortAccess !== "unpublished-install-access-required"
          || pin.rpcUrl !== `http://127.0.0.1:${current.ports?.node}`) {
          throw new Error("Genesis pin does not match the verified installation relay");
        }
        installAccess = { kind: current.kind, networkId: current.networkId,
          relayId: current.relayId, ports: current.ports,
          relayScriptSha256: current.relayScriptSha256, installationOnly: true };
      }
    }
    const observation = await (dependencies.preflight ?? checkLocalLedgerPreflight)(pin);
    if (installAccess?.kind === "effective-direct-loopback") {
      const { config, expectedTopology } = await preparedStandaloneTopology(root, record);
      const current = await (dependencies.observeTopology ?? observeStandaloneTopology)(config,
        { ...expectedTopology, allowUnpublishedHostPorts: false });
      if (current.project !== record.stack.project
        || current.networkId !== installAccess.networkId
        || current.internalNetworkOnly !== true) {
        throw new Error("Direct-loopback topology changed during genesis observation");
      }
    } else if (installAccess?.kind === "standalone-install-relay-observation") {
      const { config, expectedTopology } = await preparedStandaloneTopology(root, record);
      const current = await (dependencies.observeInstallRelay ?? observeStandaloneInstallRelay)(
        config, record.install.verified, expectedTopology);
      if (current.relayId !== installAccess.relayId
        || current.networkId !== installAccess.networkId
        || JSON.stringify(current.ports) !== JSON.stringify(installAccess.ports)
        || current.relayScriptSha256 !== installAccess.relayScriptSha256) {
        throw new Error("Installation relay changed during genesis observation");
      }
    }
    record.ledgerObservation = {
      pinSha256: sha256(pinBytes),
      expectedGenesisHash: pin.expectedGenesisHash,
      rpcUrl: pin.rpcUrl,
      allowedHosts: pin.allowedHosts,
      observation,
      ...(installAccess ? { installAccess } : {}),
    };
    await writeRecord(root, record);
    return record.ledgerObservation;
  });
}

export function assertDetachedReviewerSignatureStatus(
  output, expectedFingerprint, approvedAt, now = Date.now(),
) {
  try {
    if (typeof approvedAt !== "string") throw new Error("Approval timestamp is required");
    assertStrictDetachedSignatureStatus({ output, exitStatus: 0,
      expectedPrimaryFingerprint: expectedFingerprint, approvedAt, now });
  } catch {
    throw new Error("Detached approval signature does not match the pinned reviewer key");
  }
}

export async function verifyDetachedReviewerSignature(
  documentPath, signaturePath, keyringDirectory, expectedFingerprint, approvedAt,
) {
  if (!FINGERPRINT.test(expectedFingerprint)) throw new Error("Reviewer signing-key fingerprint must be canonical");
  const publicKeySource = resolve(keyringDirectory);
  const sourceStat = await lstat(publicKeySource);
  const armoredExport = sourceStat.isFile();
  const keyboxPath = armoredExport ? publicKeySource
    : join(await privateDirectory(publicKeySource), "pubring.kbx");
  let keybox;
  try {
    keybox = await open(keyboxPath,
      constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      throw new Error("Reviewer keyring needs pubring.kbx; export and import the public key into a pre-created private directory");
    }
    throw error;
  }
  let publicKeys;
  try {
    const stat = await keybox.stat();
    if (!stat.isFile() || stat.size === 0 || stat.size > 8 * 1024 * 1024
      || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
      throw new Error("Reviewer public keyring must be an owned bounded regular file");
    }
    publicKeys = await keybox.readFile();
    if (publicKeys.length !== stat.size) throw new Error("Reviewer public keyring changed during read");
  } finally {
    await keybox.close();
  }
  if (armoredExport && !publicKeys.toString("utf8").startsWith("-----BEGIN PGP PUBLIC KEY BLOCK-----\n")) {
    throw new Error("Reviewer key file must be an armored public-key export");
  }
  const shortTempRoot = tmpdir().length > 55 ? "/tmp" : tmpdir();
  const temporary = await mkdtemp(join(shortTempRoot, "tr-reviewer-keyring-"));
  try {
    const gpg = ["/usr/bin/gpg", "/opt/homebrew/bin/gpg", "/usr/local/bin/gpg"].find(existsSync);
    if (!gpg) throw new Error("A trusted GPG executable is required for reviewer approval");
    const verificationEnv = { PATH: "/usr/bin:/bin", HOME: temporary, LC_ALL: "C" };
    const keyring = join(temporary, "pubring.kbx");
    if (armoredExport) {
      const exportPath = join(temporary, "reviewer-public.asc");
      await writeFile(exportPath, publicKeys, { flag: "wx", mode: 0o600 });
      await execFileAsync(gpg, ["--batch", "--no-options", "--homedir", temporary,
        "--import", exportPath], { timeout: 30_000, maxBuffer: 1024 * 1024, env: verificationEnv });
    } else {
      await writeFile(keyring, publicKeys, { flag: "wx", mode: 0o600 });
    }
    const { stdout } = await execFileAsync(gpg, [
      "--batch", "--no-options", "--no-auto-key-retrieve", "--trust-model", "always",
      "--no-default-keyring", "--homedir", temporary, "--keyring", keyring,
      "--status-fd=1", "--verify", signaturePath, documentPath,
    ], { timeout: 30_000, maxBuffer: 1024 * 1024, env: verificationEnv });
    assertDetachedReviewerSignatureStatus(stdout, expectedFingerprint, approvedAt);
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

export async function draftStandaloneGenesisApproval(directory, proposal) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (!record.ledgerObservation || record.genesisApproval || record.deployment) {
      throw new Error("Observe genesis before drafting its approval; do not replace an approved or reserved decision");
    }
    requireVerifiedStandaloneStack(record);
    if (record.install.verified?.runtimeComposeSha256 && !record.stack?.observation) {
      throw new Error("Observe the prepared local stack before drafting its genesis approval");
    }
    reviewerProposal(proposal, ["reviewerFingerprint", "reviewedReference", "approvedAt"]);
    if (Date.parse(proposal.approvedAt) < Date.parse(record.createdAt)) {
      throw new Error("Genesis review time predates setup initialization");
    }
    const document = {
      format: "tr-local-genesis-approval-v1",
      setupId: record.setupId,
      stackProject: record.stack?.project ?? null,
      sourceRevision: record.sourceRevision,
      installInventorySha256: record.install.inventorySha256,
      networkId: STANDALONE_PROFILE.networkId,
      pinSha256: record.ledgerObservation.pinSha256,
      expectedGenesisHash: record.ledgerObservation.expectedGenesisHash,
      rpcUrl: record.ledgerObservation.rpcUrl,
      reviewerFingerprint: proposal.reviewerFingerprint,
      reviewedReference: proposal.reviewedReference,
      approvedAt: proposal.approvedAt,
    };
    const path = join(root, "genesis-approval.unsigned.json");
    const bytes = Buffer.from(`${JSON.stringify(document, null, 2)}\n`);
    await writePrivateSnapshot(path, bytes);
    return { path, documentSha256: sha256(bytes), state: "unsigned-human-review-required" };
  });
}

export async function draftStandaloneCommitteeApproval(directory, proposal) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (!record.genesisApproval || record.committeeApproval || record.deployment) {
      throw new Error("Approve genesis before drafting a committee; do not replace an approved or reserved roster");
    }
    reviewerProposal(proposal, ["reviewerFingerprint", "reviewedReference",
      "maintenancePolicy", "custodians", "approvedAt", "deploymentPlanPath"]);
    if (Date.parse(proposal.approvedAt) < Date.parse(record.genesisApproval.approvedAt)) {
      throw new Error("Committee review time predates genesis approval");
    }
    validateReleaseCommittee(proposal.maintenancePolicy, proposal.custodians);
    if (typeof proposal.deploymentPlanPath !== "string"
      || !isAbsolute(proposal.deploymentPlanPath)) {
      throw new Error("Committee review requires an absolute deployment plan path");
    }
    const planBytes = await regularBytes(resolve(proposal.deploymentPlanPath));
    const plan = validateLocalDeploymentPlan(parseJsonBytes(planBytes));
    if (plan.sourceRevision !== record.sourceRevision
      || plan.network.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
      || plan.network.rpcUrl !== record.ledgerObservation.rpcUrl
      || JSON.stringify(plan.network.allowedHosts) !== JSON.stringify(record.ledgerObservation.allowedHosts)) {
      throw new Error("Committee deployment plan disagrees with the approved install or genesis");
    }
    const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    if (sha256(inventory) !== record.install.inventorySha256) {
      throw new Error("Installed inventory changed since genesis approval");
    }
    const bundleManifest = await verifiedPackageManifestBytes(
      record.install.bundle, inventory, record.install.verified,
    );
    if (sha256(await regularBytes(plan.releaseManifestPath)) !== sha256(bundleManifest)) {
      throw new Error("Committee deployment manifest disagrees with the approved install");
    }
    const document = {
      format: "tr-local-committee-approval-v2",
      sourceRevision: record.sourceRevision,
      installInventorySha256: record.install.inventorySha256,
      genesisApprovalSha256: record.genesisApproval.documentSha256,
      deploymentPlanSha256: sha256(planBytes),
      providerModuleSha256: plan.providerModuleSha256,
      networkId: STANDALONE_PROFILE.networkId,
      expectedGenesisHash: record.ledgerObservation.expectedGenesisHash,
      reviewerFingerprint: proposal.reviewerFingerprint,
      reviewedReference: proposal.reviewedReference,
      approvedAt: proposal.approvedAt,
      maintenancePolicy: proposal.maintenancePolicy,
      custodians: proposal.custodians,
    };
    const path = join(root, "committee-approval.unsigned.json");
    const bytes = Buffer.from(`${JSON.stringify(document, null, 2)}\n`);
    await writePrivateSnapshot(path, bytes);
    return { path, documentSha256: sha256(bytes), state: "unsigned-human-review-required" };
  });
}

async function verifiedApprovalEvidence(
  root, label, document, signature, keyringDirectory, expectedFingerprint, dependencies, approvedAt,
) {
  if (document.length > 32 * 1024 || signature.length > 64 * 1024) {
    throw new Error(`${label} approval document or signature exceeds the bounded evidence size`);
  }
  const snapshot = join(root, `.${label}-approval-${randomUUID()}`);
  const documentSnapshot = `${snapshot}.json`;
  const signatureSnapshot = `${snapshot}.sig`;
  try {
    await writePrivateSnapshot(documentSnapshot, document);
    await writePrivateSnapshot(signatureSnapshot, signature);
    await (dependencies.verifySignature ?? verifyDetachedReviewerSignature)(
      documentSnapshot, signatureSnapshot, resolve(keyringDirectory), expectedFingerprint, approvedAt,
    );
  } finally {
    await unlink(documentSnapshot).catch(() => {});
    await unlink(signatureSnapshot).catch(() => {});
  }
  return {
    reviewerFingerprint: expectedFingerprint,
    documentSha256: sha256(document),
    signatureSha256: sha256(signature),
    documentBase64: document.toString("base64"),
    signatureBase64: signature.toString("base64"),
    verification: "detached-signature-verified-against-operator-pinned-key",
  };
}

export async function approveStandaloneGenesis(
  directory, documentPath, signaturePath, keyringDirectory, expectedFingerprint, dependencies = {},
) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (!record.ledgerObservation) throw new Error("Observe the local ledger before requesting genesis approval");
    if (record.genesisApproval || record.deployment) throw new Error("Genesis approval is already recorded or deployment reserved");
    requireVerifiedStandaloneStack(record);
    if (!FINGERPRINT.test(expectedFingerprint)) throw new Error("Reviewer signing-key fingerprint must be canonical");
    const document = await regularBytes(resolve(documentPath));
    const signature = await regularBytes(resolve(signaturePath));
    if (document.length > 32 * 1024 || signature.length > 64 * 1024) {
      throw new Error("Genesis approval document or signature exceeds the bounded evidence size");
    }
    const approval = parseCanonicalSignedJson(document, "Genesis approval");
    const expectedFields = ["approvedAt", "expectedGenesisHash", "format", "installInventorySha256",
      "networkId", "pinSha256", "reviewedReference", "reviewerFingerprint", "rpcUrl", "setupId",
      "sourceRevision", "stackProject"];
    if (approval === null || typeof approval !== "object" || Array.isArray(approval)
      || Object.keys(approval).sort().join("\0") !== expectedFields.join("\0")
      || approval.format !== "tr-local-genesis-approval-v1"
      || approval.sourceRevision !== record.sourceRevision
      || !record.setupId || approval.setupId !== record.setupId
      || approval.stackProject !== (record.stack?.project ?? null)
      || approval.installInventorySha256 !== record.install.inventorySha256
      || approval.networkId !== STANDALONE_PROFILE.networkId
      || approval.pinSha256 !== record.ledgerObservation.pinSha256
      || approval.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
      || !HASH.test(approval.expectedGenesisHash)
      || approval.rpcUrl !== record.ledgerObservation.rpcUrl
      || approval.reviewerFingerprint !== expectedFingerprint
      || !canonicalReviewerMetadata(approval, Date.parse(record.createdAt), Date.now() + 5 * 60_000)) {
      throw new Error("Reviewer approval does not bind the current install and observed genesis");
    }
    const evidence = await verifiedApprovalEvidence(
      root, "genesis", document, signature, keyringDirectory, expectedFingerprint, dependencies,
      approval.approvedAt,
    );
    record.genesisApproval = {
      ...evidence,
      approvedAt: approval.approvedAt,
      reviewedReference: approval.reviewedReference,
    };
    await writeRecord(root, record);
    return {
      reviewerFingerprint: expectedFingerprint,
      documentSha256: record.genesisApproval.documentSha256,
      signatureSha256: record.genesisApproval.signatureSha256,
    };
  });
}

export async function approveStandaloneCommittee(
  directory, documentPath, signaturePath, keyringDirectory, expectedFingerprint, dependencies = {},
) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (!record.genesisApproval) throw new Error("Approve the local genesis before proposing a release committee");
    if (record.setupId) readStoredGenesisApproval(record);
    if (record.committeeApproval || record.deployment) {
      throw new Error("Committee roster approval is already recorded or deployment reserved");
    }
    if (!FINGERPRINT.test(expectedFingerprint)) throw new Error("Governance reviewer fingerprint must be canonical");
    const document = await regularBytes(resolve(documentPath));
    const signature = await regularBytes(resolve(signaturePath));
    if (document.length > 32 * 1024 || signature.length > 64 * 1024) {
      throw new Error("Committee approval document or signature exceeds the bounded evidence size");
    }
    const approval = parseCanonicalSignedJson(document, "Committee approval");
    const expectedFields = ["approvedAt", "custodians", "deploymentPlanSha256",
      "expectedGenesisHash", "format", "genesisApprovalSha256", "installInventorySha256",
      "maintenancePolicy", "networkId", "providerModuleSha256", "reviewedReference",
      "reviewerFingerprint", "sourceRevision"];
    if (approval === null || typeof approval !== "object" || Array.isArray(approval)
      || Object.keys(approval).sort().join("\0") !== expectedFields.join("\0")
      || approval.format !== "tr-local-committee-approval-v2"
      || !SHA256.test(approval.deploymentPlanSha256)
      || !SHA256.test(approval.providerModuleSha256)
      || approval.sourceRevision !== record.sourceRevision
      || approval.installInventorySha256 !== record.install.inventorySha256
      || approval.genesisApprovalSha256 !== record.genesisApproval.documentSha256
      || approval.networkId !== STANDALONE_PROFILE.networkId
      || approval.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
      || approval.reviewerFingerprint !== expectedFingerprint
      || !canonicalReviewerMetadata(approval,
        Date.parse(record.genesisApproval.approvedAt), Date.now() + 5 * 60_000)) {
      throw new Error("Committee approval does not bind the approved install and genesis");
    }
    validateReleaseCommittee(approval.maintenancePolicy, approval.custodians);
    const evidence = await verifiedApprovalEvidence(
      root, "committee", document, signature, keyringDirectory, expectedFingerprint, dependencies,
      approval.approvedAt,
    );
    record.committeeApproval = {
      ...evidence,
      approvedAt: approval.approvedAt,
      reviewedReference: approval.reviewedReference,
      maintenancePolicy: approval.maintenancePolicy,
      custodians: approval.custodians,
      deploymentPlanSha256: approval.deploymentPlanSha256,
      providerModuleSha256: approval.providerModuleSha256,
    };
    await writeRecord(root, record);
    return {
      reviewerFingerprint: expectedFingerprint,
      documentSha256: evidence.documentSha256,
      signatureSha256: evidence.signatureSha256,
      threshold: approval.maintenancePolicy.threshold,
      committeeSize: approval.maintenancePolicy.verifyingKeys.length,
    };
  });
}

export async function approveStandaloneCommitteeDeployment(
  directory, documentPath, signaturePath, keyringDirectory, expectedFingerprint, dependencies = {},
) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const deployment = record.deployment;
    const receipt = deployment?.result?.receipt;
    if (!record.committeeApproval || deployment?.state !== "observed"
      || deployment.result?.readbackStatus !== "staged-bootstrap-pending"
      || !deployment.stagedPlan || !validLocalDeploymentReceipt(receipt)) {
      throw new Error("A signed roster and finalized staged deployment are required for committee binding");
    }
    if (record.committeeDeploymentApproval) {
      throw new Error("Committee deployment binding is already recorded");
    }
    if (record.maintenanceAttempt || (record.maintenanceHistory?.length ?? 0) > 0) {
      throw new Error("A maintenance attempt already exists; reconcile it without retrospective approval");
    }
    if (expectedFingerprint !== record.committeeApproval.reviewerFingerprint) {
      throw new Error("Committee deployment binding requires the pinned governance reviewer");
    }
    readStoredCommitteeApproval(record);
    const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    if (sha256(inventory) !== record.install.inventorySha256) {
      throw new Error("Installed inventory changed since committee approval");
    }
    const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(record.install.bundle);
    if (verified.sourceRevision !== record.sourceRevision) {
      throw new Error("Installed bundle source revision changed since committee approval");
    }
    requireVerifiedInventoryBytes(verified, inventory, record.install.inventorySha256,
      "Installed inventory changed since committee approval");
    const manifestBytes = await verifiedPackageManifestBytes(record.install.bundle, inventory, verified);
    const stagedManifestBytes = await regularBytes(deployment.stagedPlan.releaseManifestPath);
    if (sha256(manifestBytes) !== sha256(stagedManifestBytes)) {
      throw new Error("Staged deployment manifest disagrees with approved install bytes");
    }
    const manifest = parseJsonBytes(manifestBytes);
    if (manifest.format !== "tr-release-candidate-manifest-v2"
      || manifest.sourceRevision !== record.sourceRevision) {
      throw new Error("Staged deployment manifest has an invalid source or format");
    }
    const document = await regularBytes(resolve(documentPath));
    const signature = await regularBytes(resolve(signaturePath));
    if (document.length > 32 * 1024 || signature.length > 64 * 1024) {
      throw new Error("Committee deployment approval document or signature exceeds the bounded evidence size");
    }
    const approval = parseCanonicalSignedJson(document, "Committee deployment approval");
    const reservedAt = Date.parse(deployment.reservedAt);
    const receiptFields = ["blockHash", "blockHeight", "contractAddress", "networkId", "txId"];
    const expectedFields = ["approvedAt", "committeeApprovalSha256", "deploymentPlanSha256",
      "deploymentReceipt", "expectedGenesisHash", "format", "releaseManifestSha256",
      "reviewedReference", "reviewerFingerprint", "sourceRevision"];
    if (!exactFields(approval, expectedFields)
      || approval.format !== "tr-local-committee-deployment-approval-v1"
      || approval.sourceRevision !== record.sourceRevision
      || approval.committeeApprovalSha256 !== record.committeeApproval.documentSha256
      || !SHA256.test(approval.committeeApprovalSha256)
      || approval.deploymentPlanSha256 !== deployment.planSha256
      || !SHA256.test(approval.deploymentPlanSha256)
      || approval.releaseManifestSha256 !== sha256(manifestBytes)
      || approval.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
      || !exactFields(approval.deploymentReceipt, receiptFields)
      || receiptFields.some((field) => approval.deploymentReceipt[field] !== receipt[field])
      || approval.reviewerFingerprint !== expectedFingerprint
      || !Number.isFinite(reservedAt)
      || !canonicalReviewerMetadata(approval, reservedAt, Date.now() + 5 * 60_000)) {
      throw new Error("Committee deployment approval does not bind the finalized install and contract");
    }
    const evidence = await verifiedApprovalEvidence(
      root, "committee-deployment", document, signature, keyringDirectory,
      expectedFingerprint, dependencies, approval.approvedAt,
    );
    record.committeeDeploymentApproval = {
      ...evidence,
      approvedAt: approval.approvedAt,
      reviewedReference: approval.reviewedReference,
    };
    await writeRecord(root, record);
    return {
      reviewerFingerprint: expectedFingerprint,
      documentSha256: evidence.documentSha256,
      signatureSha256: evidence.signatureSha256,
      contractAddress: receipt.contractAddress,
    };
  });
}

async function requireCurrentInstallRelay(root, record, verified, plan, dependencies) {
  const approved = record.ledgerObservation.installAccess;
  const { config, expectedTopology } = await preparedStandaloneTopology(root, record);
  const live = await (dependencies.observeInstallRelay ?? observeStandaloneInstallRelay)(
    config, verified, expectedTopology);
  const indexerHttp = `http://127.0.0.1:${live.ports?.indexer}/api/v4/graphql`;
  const indexerWs = `ws://127.0.0.1:${live.ports?.indexer}/api/v4/graphql/ws`;
  if (live.relayId !== approved.relayId
    || live.networkId !== approved.networkId
    || live.relayScriptSha256 !== approved.relayScriptSha256
    || JSON.stringify(live.ports) !== JSON.stringify(approved.ports)) {
    throw new Error("Verified installation relay changed");
  }
  if (plan.network.rpcUrl !== `http://127.0.0.1:${live.ports?.node}`
    || plan.network.indexerHttpUrl !== indexerHttp
    || plan.network.indexerWsUrl !== indexerWs) {
    throw new Error("Deployment plan endpoints diverged from the verified installation relay");
  }
}

async function requireCurrentDirectTopology(root, record, plan, dependencies) {
  const approved = record.ledgerObservation.installAccess;
  const { config, expectedTopology } = await preparedStandaloneTopology(root, record);
  const live = await (dependencies.observeTopology ?? observeStandaloneTopology)(config,
    { ...expectedTopology, allowUnpublishedHostPorts: false });
  if (live.project !== record.stack.project
    || live.networkId !== approved.networkId
    || live.networkId !== record.stack.observation.topology.networkId
    || live.internalNetworkOnly !== true) {
    throw new Error("Verified direct-loopback topology changed");
  }
  const indexerHttp = `http://127.0.0.1:${record.stack.ports.indexer}/api/v4/graphql`;
  const indexerWs = `ws://127.0.0.1:${record.stack.ports.indexer}/api/v4/graphql/ws`;
  if (plan.network.rpcUrl !== `http://127.0.0.1:${record.stack.ports.node}`
    || plan.network.indexerHttpUrl !== indexerHttp
    || plan.network.indexerWsUrl !== indexerWs) {
    throw new Error("Deployment plan endpoints diverged from the verified direct-loopback stack");
  }
}

async function requireCurrentApprovedAccess(root, record, verified, plan, dependencies) {
  requireVerifiedStandaloneStack(record);
  if (verified.sourceRevision !== record.sourceRevision
    || verified.runtimeComposeSha256 !== record.install.verified.runtimeComposeSha256
    || verified.runtimeOfflineComposeSha256 !== record.install.verified.runtimeOfflineComposeSha256
    || JSON.stringify(verified.images) !== JSON.stringify(record.install.verified.images)) {
    throw new Error("Verified install runtime identities changed since stack approval");
  }
  if (record.ledgerObservation.installAccess.kind === "standalone-install-relay-observation") {
    await requireCurrentInstallRelay(root, record, verified, plan, dependencies);
  } else {
    await requireCurrentDirectTopology(root, record, plan, dependencies);
  }
}

export async function attemptStandaloneDeployment(directory, planPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (record.deployment) {
      throw new Error("Deployment already reserved; reconcile the journal and finalized chain before any new action");
    }
    if (!record.ledgerObservation || !record.genesisApproval) {
      throw new Error("Observe the local ledger and record detached reviewer approval before deployment");
    }
    requireVerifiedStandaloneStack(record);
    if (!record.setupId) {
      throw new Error("Legacy setup cannot submit a deployment without a setup-bound approval");
    }
    readStoredGenesisApproval(record);
    if (!record.committeeApproval) {
      throw new Error("Approve the release maintenance committee before reserving deployment");
    }
    const committee = readStoredCommitteeApproval(record);
    const planBytes = await regularBytes(resolve(planPath));
    const plan = validateLocalDeploymentPlan(parseJsonBytes(planBytes));
    if (sha256(planBytes) !== committee.deploymentPlanSha256
      || plan.providerModuleSha256 !== committee.providerModuleSha256
      || plan.sourceRevision !== record.sourceRevision
      || plan.network.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
      || plan.network.rpcUrl !== record.ledgerObservation.rpcUrl
      || JSON.stringify(plan.network.allowedHosts) !== JSON.stringify(record.ledgerObservation.allowedHosts)) {
      throw new Error("Deployment plan disagrees with the verified install or observed local ledger");
    }
    const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(record.install.bundle);
    const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    if (verified.sourceRevision !== record.sourceRevision) {
      throw new Error("Installed bundle changed since setup verification");
    }
    requireVerifiedInventoryBytes(verified, inventory, record.install.inventorySha256,
      "Installed bundle changed since setup verification");
    await requireCurrentApprovedAccess(root, record, verified, plan, dependencies);
    const bundleManifestBytes = await verifiedPackageManifestBytes(record.install.bundle, inventory, verified);
    const planManifestBytes = await regularBytes(plan.releaseManifestPath);
    if (sha256(bundleManifestBytes) !== sha256(planManifestBytes)) {
      throw new Error("Deployment release manifest disagrees with the verified install bundle");
    }
    record.deployment = {
      state: "reserved",
      planSha256: sha256(planBytes),
      journalPath: plan.journalPath,
      stagedPlan: plan.format === "tr-local-staged-deployment-plan-v1" ? {
        initialVerifierKeyName: plan.initialVerifierKeyName,
        network: plan.network,
        providerModulePath: plan.providerModulePath,
        providerModuleSha256: plan.providerModuleSha256,
        releaseManifestPath: plan.releaseManifestPath,
      } : null,
      reservedAt: new Date().toISOString(),
    };
    await writeRecord(root, record);
    try {
      const result = await (dependencies.deploy ?? runLocalDeployment)(plan, {}, {
        expectedReleaseManifestSha256: sha256(planManifestBytes),
      });
      await requireCurrentApprovedAccess(root, record, verified, plan, dependencies);
      record.deployment = { ...record.deployment, state: "observed", result };
      await writeRecord(root, record);
      return result;
    } catch {
      record.deployment = { ...record.deployment, state: "unknown" };
      await writeRecord(root, record);
      throw new Error("Deployment outcome is unknown; inspect the journal and finalized chain, never retry blindly");
    }
  });
}

export async function reconcileStandaloneDeployment(directory, planPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    if (!record.deployment || !record.genesisApproval) {
      throw new Error("A reserved deployment and approved genesis are required for reconciliation");
    }
    if (record.deployment.result?.readbackStatus === "staged-bootstrap-pending"
      || Object.keys(record.verifierKeyInsertions ?? {}).length > 0) {
      throw new Error("Staged bootstrap already advanced; reconcile verifier keys instead of downgrading deployment state");
    }
    const planBytes = await regularBytes(resolve(planPath));
    const plan = validateLocalDeploymentPlan(parseJsonBytes(planBytes));
    if (plan.format !== "tr-local-staged-deployment-plan-v1"
      || sha256(planBytes) !== record.deployment.planSha256
      || plan.journalPath !== record.deployment.journalPath
      || plan.sourceRevision !== record.sourceRevision
      || plan.network.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
      || plan.network.rpcUrl !== record.ledgerObservation.rpcUrl
      || JSON.stringify(plan.network.allowedHosts) !== JSON.stringify(record.ledgerObservation.allowedHosts)) {
      throw new Error("Reconciliation plan disagrees with the reserved staged deployment");
    }
    const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(record.install.bundle);
    const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    if (verified.sourceRevision !== record.sourceRevision) {
      throw new Error("Installed bundle changed since setup verification");
    }
    requireVerifiedInventoryBytes(verified, inventory, record.install.inventorySha256,
      "Installed bundle changed since setup verification");
    const bundleManifest = await verifiedPackageManifestBytes(record.install.bundle, inventory, verified);
    const planManifest = await regularBytes(plan.releaseManifestPath);
    if (sha256(bundleManifest) !== sha256(planManifest)) {
      throw new Error("Deployment release manifest disagrees with the verified install bundle");
    }
    await requireCurrentApprovedAccess(root, record, verified, plan, dependencies);
    const approval = {
      expectedReleaseManifestSha256: sha256(planManifest),
      ...(record.deployment.result?.receipt
        ? { expectedDeploymentReceipt: record.deployment.result.receipt } : {}),
    };
    const result = await (dependencies.reconcileDeployment ?? ((approvedPlan, expected) =>
      reconcileLocalDeployment(approvedPlan, {}, expected)))(plan, approval);
    await requireCurrentApprovedAccess(root, record, verified, plan, dependencies);
    if (!["staged-bootstrap-pending", "pending", "invalid-image", "unavailable", "mismatch", "unknown-no-receipt"]
      .includes(result?.readbackStatus)
      || (result.readbackStatus === "unknown-no-receipt"
        && (result.receipt !== undefined || approval.expectedDeploymentReceipt))
      || (result.readbackStatus !== "unknown-no-receipt"
        && (!validLocalDeploymentReceipt(result.receipt)
          || result.receiptAttribution !== "journal-recorded-not-independently-inclusion-verified"))
      || (result.finalizedBlockHash !== undefined
        && !HASH.test(result.finalizedBlockHash))) {
      throw new Error("Deployment reconciliation returned an invalid observation");
    }
    if (approval.expectedDeploymentReceipt
      && ["networkId", "contractAddress", "txId", "blockHash", "blockHeight"]
        .some((field) => result.receipt?.[field] !== approval.expectedDeploymentReceipt[field])) {
      throw new Error("Deployment reconciliation changed the setup-recorded receipt");
    }
    if (result.receipt) {
      const readbackHistory = [...(record.deployment.readbackHistory ?? [])];
      if (readbackHistory.length >= 256) {
        throw new Error("Deployment reconciliation history is full; preserve the setup record for operator review");
      }
      if (record.deployment.result) readbackHistory.push(record.deployment.result);
      record.deployment = {
        ...record.deployment, state: "observed",
        readbackHistory,
        stagedPlan: record.deployment.stagedPlan ?? {
          initialVerifierKeyName: plan.initialVerifierKeyName,
          network: plan.network,
          providerModulePath: plan.providerModulePath,
          providerModuleSha256: plan.providerModuleSha256,
          releaseManifestPath: plan.releaseManifestPath,
        },
        result: {
          kind: "local-deployment-submission-observation",
          sourceRevision: plan.sourceRevision,
          receipt: result.receipt,
          readbackStatus: result.readbackStatus,
          receiptAttribution: result.receiptAttribution,
          ...(result.finalizedBlockHash
            ? { finalizedBlockHash: result.finalizedBlockHash } : {}),
        },
      };
      await writeRecord(root, record);
    }
    return result;
  });
}

async function approvedInsertionPlan(root, record, planPath, dependencies) {
  if (record.deployment?.state !== "observed"
    || record.deployment.result?.readbackStatus !== "staged-bootstrap-pending"
    || !validLocalDeploymentReceipt(record.deployment.result?.receipt)
    || !record.deployment.stagedPlan || !record.genesisApproval) {
    throw new Error("A finalized staged bootstrap and approved genesis are required before key insertion");
  }
  const planBytes = await regularBytes(resolve(planPath));
  const plan = validateLocalVerifierKeyInsertionPlan(parseJsonBytes(planBytes));
  const staged = record.deployment.stagedPlan;
  if (plan.sourceRevision !== record.sourceRevision
    || plan.network.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
    || plan.network.rpcUrl !== record.ledgerObservation.rpcUrl
    || JSON.stringify(plan.network.allowedHosts) !== JSON.stringify(record.ledgerObservation.allowedHosts)
    || plan.network.indexerHttpUrl !== staged.network.indexerHttpUrl
    || plan.network.indexerWsUrl !== staged.network.indexerWsUrl
    || plan.deploymentJournalPath !== record.deployment.journalPath
    || plan.initialVerifierKeyName !== staged.initialVerifierKeyName
    || plan.providerModulePath !== staged.providerModulePath
    || plan.providerModuleSha256 !== staged.providerModuleSha256
    || plan.releaseManifestPath !== staged.releaseManifestPath) {
    throw new Error("Insertion plan disagrees with the approved staged deployment");
  }
  const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(record.install.bundle);
  const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
  if (verified.sourceRevision !== record.sourceRevision) {
    throw new Error("Installed bundle changed since setup verification");
  }
  requireVerifiedInventoryBytes(verified, inventory, record.install.inventorySha256,
    "Installed bundle changed since setup verification");
  const bundleManifest = await verifiedPackageManifestBytes(record.install.bundle, inventory, verified);
  const planManifest = await regularBytes(plan.releaseManifestPath);
  if (sha256(bundleManifest) !== sha256(planManifest)) {
    throw new Error("Insertion release manifest disagrees with the verified install bundle");
  }
  await requireCurrentApprovedAccess(root, record, verified, plan, dependencies);
  return { plan, verified, planSha256: sha256(planBytes), releaseManifestSha256: sha256(planManifest) };
}

export async function attemptStandaloneVerifierKeyInsertion(directory, planPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const { plan, verified, planSha256, releaseManifestSha256 } = await approvedInsertionPlan(root, record, planPath, dependencies);
    const attempts = record.verifierKeyInsertions ?? {};
    if (Object.hasOwn(attempts, plan.circuitName)
      || Object.values(attempts).some((entry) => entry.state !== "verified")) {
      throw new Error("Prior verifier-key insertion is reserved or unresolved; reconcile without resubmitting");
    }
    record.verifierKeyInsertions = attempts;
    attempts[plan.circuitName] = {
      state: "reserved", planSha256, journalPath: plan.journalPath,
      reservedAt: new Date().toISOString(),
    };
    await writeRecord(root, record);
    try {
      const approval = {
        expectedDeploymentReceipt: record.deployment.result.receipt,
        expectedReleaseManifestSha256: releaseManifestSha256,
      };
      const result = await (dependencies.insert ?? ((approvedPlan, expected) =>
        runLocalVerifierKeyInsertion(approvedPlan, {}, "submit", expected)))(plan, approval);
      await requireCurrentApprovedAccess(root, record, verified, plan, dependencies);
      if (!["verified", "pending", "absent", "mismatch"].includes(result?.readbackStatus)) {
        throw new Error("Insertion did not return a recognized finalized-readback status");
      }
      const state = result.readbackStatus;
      attempts[plan.circuitName] = { ...attempts[plan.circuitName], state, result };
      await writeRecord(root, record);
      return result;
    } catch (error) {
      attempts[plan.circuitName] = {
        ...attempts[plan.circuitName], state: "unknown",
        ...(error instanceof VerifierKeyInsertionOutcomeUnknownError && error.receipt
          ? { receipt: error.receipt } : {}),
      };
      await writeRecord(root, record);
      throw new Error("Verifier-key insertion outcome is unknown; reconcile the journal and finalized chain, never retry blindly");
    }
  });
}

export async function reconcileStandaloneVerifierKeyInsertion(directory, planPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const { plan, verified, planSha256, releaseManifestSha256 } = await approvedInsertionPlan(root, record, planPath, dependencies);
    const attempt = record.verifierKeyInsertions?.[plan.circuitName];
    if (!attempt || attempt.planSha256 !== planSha256 || attempt.journalPath !== plan.journalPath) {
      throw new Error("No matching reserved verifier-key insertion exists");
    }
    const approval = {
      expectedDeploymentReceipt: record.deployment.result.receipt,
      expectedReleaseManifestSha256: releaseManifestSha256,
    };
    const result = await (dependencies.reconcile ?? ((approvedPlan, expected) =>
      runLocalVerifierKeyInsertion(approvedPlan, {}, "reconcile", expected)))(plan, approval);
    await requireCurrentApprovedAccess(root, record, verified, plan, dependencies);
    if (!["verified", "failed-on-chain", "observed-without-receipt", "pending", "absent", "mismatch"]
      .includes(result?.readback?.status)) {
      throw new Error("Reconciliation did not return a recognized finalized-readback status");
    }
    attempt.state = result.readback.status;
    attempt.result = result;
    await writeRecord(root, record);
    return result;
  });
}

const exactFields = (value, fields) => value !== null && typeof value === "object"
  && !Array.isArray(value)
  && Object.keys(value).sort().join("\0") === [...fields].sort().join("\0");

function readStoredGenesisApproval(record) {
  const stored = record.genesisApproval;
  const document = Buffer.from(stored?.documentBase64 ?? "", "base64");
  const signature = Buffer.from(stored?.signatureBase64 ?? "", "base64");
  if (document.length === 0 || document.length > 32 * 1024
    || signature.length === 0 || signature.length > 64 * 1024
    || sha256(document) !== stored?.documentSha256
    || sha256(signature) !== stored?.signatureSha256
    || stored?.verification !== "detached-signature-verified-against-operator-pinned-key"
    || !FINGERPRINT.test(stored?.reviewerFingerprint ?? "")) {
    throw new Error("Stored genesis approval evidence is incomplete or changed");
  }
  const approval = parseCanonicalSignedJson(document, "Stored genesis approval");
  if (!exactFields(approval, ["approvedAt", "expectedGenesisHash", "format", "installInventorySha256",
    "networkId", "pinSha256", "reviewedReference", "reviewerFingerprint", "rpcUrl", "setupId",
    "sourceRevision", "stackProject"])
    || approval.format !== "tr-local-genesis-approval-v1"
    || approval.sourceRevision !== record.sourceRevision
    || approval.setupId !== record.setupId
    || approval.stackProject !== record.stack?.project
    || approval.installInventorySha256 !== record.install?.inventorySha256
    || approval.networkId !== STANDALONE_PROFILE.networkId
    || approval.pinSha256 !== record.ledgerObservation?.pinSha256
    || approval.expectedGenesisHash !== record.ledgerObservation?.expectedGenesisHash
    || approval.rpcUrl !== record.ledgerObservation?.rpcUrl
    || approval.reviewerFingerprint !== stored.reviewerFingerprint
    || approval.approvedAt !== stored.approvedAt
    || approval.reviewedReference !== stored.reviewedReference) {
    throw new Error("Stored genesis approval disagrees with the setup and observed ledger");
  }
  return approval;
}

function readStoredCommitteeApproval(record, legacyReadOnly = false) {
  if (!legacyReadOnly && record.setupId) readStoredGenesisApproval(record);
  const approvalBytes = Buffer.from(record.committeeApproval.documentBase64 ?? "", "base64");
  const signatureBytes = Buffer.from(record.committeeApproval.signatureBase64 ?? "", "base64");
  if (!legacyReadOnly && (signatureBytes.length === 0 || signatureBytes.length > 64 * 1024
    || sha256(signatureBytes) !== record.committeeApproval.signatureSha256
    || record.committeeApproval.verification !== "detached-signature-verified-against-operator-pinned-key"
    || !FINGERPRINT.test(record.committeeApproval.reviewerFingerprint ?? ""))) {
    throw new Error("Stored committee approval signature evidence is incomplete or changed");
  }
  // Historical attempts may be reconciled forensically, but never prepared or submitted again.
  const signedApproval = legacyReadOnly
    ? JSON.parse(approvalBytes.toString("utf8"))
    : parseCanonicalSignedJson(approvalBytes, "Stored committee approval");
  const legacy = signedApproval?.format === "tr-local-committee-approval-v1";
  const fields = ["approvedAt", "custodians", "expectedGenesisHash", "format",
    "genesisApprovalSha256", "installInventorySha256", "maintenancePolicy", "networkId",
    "reviewedReference", "reviewerFingerprint", "sourceRevision",
    ...(legacy ? [] : ["deploymentPlanSha256", "providerModuleSha256"])];
  if (sha256(approvalBytes) !== record.committeeApproval.documentSha256
    || !exactFields(signedApproval, fields)
    || (legacy ? !legacyReadOnly : signedApproval.format !== "tr-local-committee-approval-v2")
    || (!legacy && (!SHA256.test(signedApproval.deploymentPlanSha256)
      || !SHA256.test(signedApproval.providerModuleSha256)
      || signedApproval.deploymentPlanSha256 !== record.committeeApproval.deploymentPlanSha256
      || signedApproval.providerModuleSha256 !== record.committeeApproval.providerModuleSha256))
    || signedApproval.networkId !== STANDALONE_PROFILE.networkId
    || signedApproval.sourceRevision !== record.sourceRevision
    || signedApproval.installInventorySha256 !== record.install.inventorySha256
    || signedApproval.genesisApprovalSha256 !== record.genesisApproval.documentSha256
    || signedApproval.expectedGenesisHash !== record.ledgerObservation.expectedGenesisHash
    || signedApproval.reviewerFingerprint !== record.committeeApproval.reviewerFingerprint
    || signedApproval.approvedAt !== record.committeeApproval.approvedAt
    || signedApproval.reviewedReference !== record.committeeApproval.reviewedReference
    || JSON.stringify(signedApproval.custodians)
      !== JSON.stringify(record.committeeApproval.custodians)
    || JSON.stringify(signedApproval.maintenancePolicy)
      !== JSON.stringify(record.committeeApproval.maintenancePolicy)) {
    throw new Error("Stored committee approval disagrees with signed approval bytes");
  }
  return signedApproval;
}
function readStoredCommitteeDeploymentApproval(record, releaseManifestSha256) {
  const stored = record.committeeDeploymentApproval;
  const receipt = record.deployment?.result?.receipt;
  const document = Buffer.from(stored?.documentBase64 ?? "", "base64");
  const signature = Buffer.from(stored?.signatureBase64 ?? "", "base64");
  if (document.length === 0 || document.length > 32 * 1024
    || signature.length === 0 || signature.length > 64 * 1024
    || sha256(document) !== stored?.documentSha256
    || sha256(signature) !== stored?.signatureSha256
    || stored?.verification !== "detached-signature-verified-against-operator-pinned-key"
    || !FINGERPRINT.test(stored?.reviewerFingerprint ?? "")
    || !validLocalDeploymentReceipt(receipt)) {
    throw new Error("Stored committee deployment approval evidence is incomplete or changed");
  }
  const binding = parseCanonicalSignedJson(document, "Stored committee deployment approval");
  const receiptFields = ["blockHash", "blockHeight", "contractAddress", "networkId", "txId"];
  if (!exactFields(binding, ["approvedAt", "committeeApprovalSha256", "deploymentPlanSha256",
    "deploymentReceipt", "expectedGenesisHash", "format", "releaseManifestSha256",
    "reviewedReference", "reviewerFingerprint", "sourceRevision"])
    || binding.format !== "tr-local-committee-deployment-approval-v1"
    || binding.sourceRevision !== record.sourceRevision
    || binding.committeeApprovalSha256 !== record.committeeApproval?.documentSha256
    || binding.deploymentPlanSha256 !== record.deployment?.planSha256
    || !SHA256.test(binding.releaseManifestSha256)
    || binding.releaseManifestSha256 !== releaseManifestSha256
    || binding.expectedGenesisHash !== record.ledgerObservation?.expectedGenesisHash
    || binding.reviewerFingerprint !== record.committeeApproval?.reviewerFingerprint
    || binding.reviewerFingerprint !== stored.reviewerFingerprint
    || binding.approvedAt !== stored.approvedAt
    || binding.reviewedReference !== stored.reviewedReference
    || !exactFields(binding.deploymentReceipt, receiptFields)
    || receiptFields.some((field) => binding.deploymentReceipt[field] !== receipt[field])) {
    throw new Error("Signed committee deployment binding disagrees with current setup state");
  }
  return binding;
}
const bytes32 = (value) => {
  if (!HASH.test(value) || /^0x0{64}$/u.test(value)) {
    throw new Error("Committee transition request contains an invalid public commitment");
  }
  return Buffer.from(value.slice(2), "hex");
};
const integer = (value) => {
  if (typeof value !== "string" || !DECIMAL.test(value)) {
    throw new Error("Committee transition request contains an invalid decimal counter");
  }
  return BigInt(value);
};

async function readApprovedCommitteeTransition(record, requestPath, dependencies = {}, legacyReadOnly = false) {
    const staged = record.deployment?.stagedPlan;
    const receipt = record.deployment?.result?.receipt;
    if (!record.genesisApproval || !record.committeeApproval
      || (!record.committeeDeploymentApproval && !legacyReadOnly) || !staged
      || record.deployment?.state !== "observed"
      || record.deployment.result?.readbackStatus !== "staged-bootstrap-pending"
      || !validLocalDeploymentReceipt(receipt)) {
      throw new Error("Approved committee and finalized staged deployment are required");
    }
    readStoredCommitteeApproval(record, legacyReadOnly);
    const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    if (sha256(inventory) !== record.install.inventorySha256) {
      throw new Error("Installed inventory changed since committee approval");
    }
    const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(record.install.bundle);
    requireVerifiedInventoryBytes(verified, inventory, record.install.inventorySha256,
      "Installed bundle inventory changed since committee approval");
    if (verified.sourceRevision !== record.sourceRevision) {
      throw new Error("Installed bundle source revision changed since committee approval");
    }
    const manifestBytes = await verifiedPackageManifestBytes(record.install.bundle, inventory, verified);
    const deployedManifestBytes = await regularBytes(staged.releaseManifestPath);
    if (sha256(manifestBytes) !== sha256(deployedManifestBytes)) {
      throw new Error("Staged deployment manifest disagrees with approved install bytes");
    }
    const manifest = parseJsonBytes(manifestBytes);
    if (manifest.format !== "tr-release-candidate-manifest-v2"
      || manifest.sourceRevision !== record.sourceRevision) {
      throw new Error("Staged deployment manifest has an invalid source or format");
    }
    if (record.committeeDeploymentApproval) {
      readStoredCommitteeDeploymentApproval(record, sha256(manifestBytes));
    }
    const catalog = Object.keys(manifest.verifierKeySha256 ?? {});
    const expectedInsertions = catalog.filter((name) => name !== staged.initialVerifierKeyName).sort();
    const insertions = record.verifierKeyInsertions ?? {};
    if (catalog.length < 2 || !catalog.includes(staged.initialVerifierKeyName)
      || Object.keys(insertions).sort().join("\0") !== expectedInsertions.join("\0")
      || expectedInsertions.some((name) => insertions[name].state !== "verified")) {
      throw new Error("Every staged verifier key must have verified finalized readback");
    }
    const requestBytes = await regularBytes(resolve(requestPath));
    const request = parseJsonBytes(requestBytes);
    if (!exactFields(request, ["bootstrap", "bootstrapMaintenanceVerifyingKey", "expiresAt",
      "format", "governance", "sourceRevision"])
      || request.format !== "tr-local-committee-transition-request-v1"
      || request.sourceRevision !== record.sourceRevision
      || !HASH.test(request.bootstrapMaintenanceVerifyingKey)
      || !exactFields(request.bootstrap, ["governancePolicyCommitment", "maintainerDidCommitment",
        "maintainerId", "maintainerKeyId", "maintainerPublicKey", "maintainerThreshold",
        "registryDidCommitment", "registryId"])
      || !exactFields(request.bootstrap.maintainerPublicKey, ["x", "y"])
      || typeof request.bootstrap.registryId !== "string"
      || !exactFields(request.governance, ["actionSequence", "activeMaintainerCount",
        "maintainerThreshold", "policyCommitment", "policyVersion"])) {
      throw new Error("Committee transition request has an invalid shape or source revision");
    }
    const approval = {
      network: staged.network,
      receipt,
      bootstrap: {
        registryId: request.bootstrap.registryId,
        registryDidCommitment: bytes32(request.bootstrap.registryDidCommitment),
        governancePolicyCommitment: bytes32(request.bootstrap.governancePolicyCommitment),
        maintainerId: bytes32(request.bootstrap.maintainerId),
        maintainerDidCommitment: bytes32(request.bootstrap.maintainerDidCommitment),
        maintainerKeyId: bytes32(request.bootstrap.maintainerKeyId),
        maintainerPublicKey: {
          x: integer(request.bootstrap.maintainerPublicKey.x),
          y: integer(request.bootstrap.maintainerPublicKey.y),
        },
        maintainerThreshold: integer(request.bootstrap.maintainerThreshold),
      },
      releaseManifest: manifest,
      governance: {
        policyCommitment: bytes32(request.governance.policyCommitment),
        policyVersion: integer(request.governance.policyVersion),
        actionSequence: integer(request.governance.actionSequence),
        maintainerThreshold: integer(request.governance.maintainerThreshold),
        activeMaintainerCount: integer(request.governance.activeMaintainerCount),
      },
      maintenancePolicy: record.committeeApproval.maintenancePolicy,
      bootstrapMaintenanceVerifyingKey: request.bootstrapMaintenanceVerifyingKey,
      stagedVerifierKeyInstallation: true,
      expiresAt: new Date(request.expiresAt),
    };
    return { approval, requestBytes, manifestBytes, catalog, verified };
}

async function approvedStandaloneCommitteeTransition(root, record, requestPath, dependencies = {}) {
    const { approval, requestBytes, manifestBytes, catalog, verified } = await readApprovedCommitteeTransition(
      record, requestPath, dependencies,
    );
    await requireCurrentApprovedAccess(root, record, verified,
      { network: approval.network }, dependencies);
    setNetworkId(STANDALONE_PROFILE.networkId);
    const prepared = await (dependencies.prepareTransition ?? prepareLocalNetworkCommitteeTransition)(approval);
    await requireCurrentApprovedAccess(root, record, verified,
      { network: approval.network }, dependencies);
    if (prepared.networkId !== STANDALONE_PROFILE.networkId || prepared.contractAddress !== approval.receipt.contractAddress
      || !HASH.test(prepared.finalizedBlockHash) || /^0x0{64}$/u.test(prepared.finalizedBlockHash)
      || prepared.currentAuthorityCounter !== BigInt(catalog.length - 1)
      || prepared.nextAuthorityCounter !== BigInt(catalog.length)
      || prepared.threshold !== record.committeeApproval.maintenancePolicy.threshold
      || JSON.stringify(prepared.committeeVerifyingKeys)
        !== JSON.stringify(record.committeeApproval.maintenancePolicy.verifyingKeys)
      || prepared.expiresAt !== approval.expiresAt.toISOString()
      || !(prepared.dataToSign instanceof Uint8Array) || prepared.dataToSign.length === 0) {
      throw new Error("Finalized committee transition plan disagrees with approved setup state");
    }
    const signingRequest = {
      kind: "local-committee-transition-signing-request",
      sourceRevision: record.sourceRevision,
      committeeApprovalSha256: record.committeeApproval.documentSha256,
      committeeDeploymentApprovalSha256: record.committeeDeploymentApproval.documentSha256,
      requestSha256: sha256(requestBytes),
      releaseManifestSha256: sha256(manifestBytes),
      contractAddress: prepared.contractAddress,
      finalizedBlockHash: prepared.finalizedBlockHash,
      currentAuthorityCounter: prepared.currentAuthorityCounter.toString(),
      nextAuthorityCounter: prepared.nextAuthorityCounter.toString(),
      committeeVerifyingKeys: prepared.committeeVerifyingKeys,
      threshold: prepared.threshold,
      expiresAt: prepared.expiresAt,
      dataToSignHex: `0x${Buffer.from(prepared.dataToSign).toString("hex")}`,
      updateSha256: sha256(prepared.dataToSign),
      submission: "not-attempted",
    };
    return { approval, signingRequest, requestBytes, prepared, verified };
}

export async function prepareStandaloneCommitteeTransition(directory, requestPath, dependencies = {}) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const { signingRequest } = await approvedStandaloneCommitteeTransition(
      root, record, requestPath, dependencies,
    );
    return signingRequest;
  });
}

const SIGNATURE = /^0x[0-9a-f]{128}$/u;
const signingRequestMatches = (saved, fresh) => exactFields(saved, Object.keys(fresh))
  && HASH.test(saved.finalizedBlockHash) && !/^0x0{64}$/u.test(saved.finalizedBlockHash)
  && Object.keys(fresh).filter((field) => field !== "finalizedBlockHash")
    .every((field) => JSON.stringify(saved[field]) === JSON.stringify(fresh[field]));

export async function submitStandaloneCommitteeTransition(
  directory, requestPath, signingRequestPath, signaturePath, dependencies = {},
) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const priorRecoveredAttempt = record.maintenanceAttempt?.state === "recovered-no-journal-approved"
      ? record.maintenanceAttempt : null;
    if (["aborted-before-journal", "recovered-no-journal-approved"]
      .includes(record.maintenanceAttempt?.state)) {
      if (record.maintenanceAttempt.state === "recovered-no-journal-approved"
        && !record.maintenanceAttempt.recoveryApproval) {
        throw new Error("Maintenance recovery approval evidence is missing");
      }
      const priorJournal = new FileMaintenanceTransitionJournal(record.maintenanceAttempt.journalPath);
      if (await priorJournal.inspect() !== null) {
        throw new Error("Aborted maintenance attempt has a journal; preserve it for recovery");
      }
      const history = record.maintenanceHistory ?? [];
      if (history.length >= 32) throw new Error("Maintenance attempt history is full; preserve it for review");
      history.push(record.maintenanceAttempt);
      record.maintenanceHistory = history;
      delete record.maintenanceAttempt;
    } else if (record.maintenanceAttempt) {
      if (record.maintenanceAttempt.state === "recovery-required-no-journal") {
        throw new Error("Maintenance crash window requires independent human recovery approval before a new attempt");
      }
      throw new Error("Maintenance transition already reserved; reconcile without resubmitting");
    }
    const { approval, signingRequest, requestBytes, prepared, verified } = await approvedStandaloneCommitteeTransition(
      root, record, requestPath, dependencies,
    );
    if (priorRecoveredAttempt
      && (sha256(requestBytes) === priorRecoveredAttempt.requestSha256
        || signingRequest.finalizedBlockHash === priorRecoveredAttempt.finalizedBlockHash
        || Date.parse(signingRequest.expiresAt)
          <= Date.parse(priorRecoveredAttempt.recoveryApproval.approvedAt))) {
      throw new Error("Human-recovered maintenance requires a fresh request and signing window");
    }
    const signingRequestBytes = await regularBytes(resolve(signingRequestPath));
    const savedSigningRequest = parseJsonBytes(signingRequestBytes);
    if (!signingRequestMatches(savedSigningRequest, signingRequest)) {
      throw new Error("Saved signing request disagrees with fresh finalized maintenance evidence");
    }
    if (priorRecoveredAttempt
      && savedSigningRequest.finalizedBlockHash
        === priorRecoveredAttempt.finalizedBlockHash) {
      throw new Error("Recovered maintenance attempt cannot reuse the abandoned finalized checkpoint");
    }
    const signatureBytes = await regularBytes(resolve(signaturePath));
    const signed = parseJsonBytes(signatureBytes);
    if (!exactFields(signed, ["format", "signature", "updateSha256"])
      || signed.format !== "tr-local-committee-signature-v1"
      || signed.updateSha256 !== signingRequest.updateSha256
      || !SIGNATURE.test(signed.signature)) {
      throw new Error("External bootstrap signature does not match the approved signing request");
    }
    const signature = signed.signature.slice(2);
    prepared.authorize(signature);
    const journalPath = join(root, "committee-transition.json");
    const journal = new FileMaintenanceTransitionJournal(journalPath);
    if (await journal.inspect() !== null) {
      throw new Error("Maintenance journal already exists; reconcile the previous attempt");
    }
    record.maintenanceAttempt = {
      state: "reserved",
      requestSha256: sha256(requestBytes),
      signingRequestSha256: sha256(signingRequestBytes),
      signatureSha256: sha256(signatureBytes),
      committeeDeploymentApprovalSha256: signingRequest.committeeDeploymentApprovalSha256,
      updateSha256: signingRequest.updateSha256,
      finalizedBlockHash: savedSigningRequest.finalizedBlockHash,
      journalPath,
      reservedAt: new Date().toISOString(),
    };
    await writeRecord(root, record);
    let material;
    try {
      const staged = record.deployment.stagedPlan;
      const plan = validateLocalDeploymentPlan({
        format: "tr-local-staged-deployment-plan-v1",
        sourceRevision: record.sourceRevision,
        network: staged.network,
        providerModulePath: staged.providerModulePath,
        providerModuleSha256: staged.providerModuleSha256,
        releaseManifestPath: staged.releaseManifestPath,
        initialVerifierKeyName: staged.initialVerifierKeyName,
        journalPath: record.deployment.journalPath,
      });
      ({ material } = await (dependencies.loadMaterial ?? loadApprovedMaintenanceMaterial)(
        plan, dependencies, { expectedReleaseManifestSha256: signingRequest.releaseManifestSha256 },
      ));
      if (!material?.providers) throw new Error("Approved provider module did not return contract providers");
      const txId = await (dependencies.submit ?? submitLocalNetworkCommitteeTransition)({
        approval, signature, journal, providers: material.providers,
        approvedUpdateSha256: signingRequest.updateSha256,
        approvedFinalizedBlockHash: savedSigningRequest.finalizedBlockHash,
      });
      await requireCurrentApprovedAccess(root, record, verified,
        { network: approval.network }, dependencies);
      if (typeof txId !== "string" || txId.length === 0 || txId.length > 512) {
        throw new Error("Maintenance submission did not return a bounded transaction ID");
      }
      record.maintenanceAttempt = { ...record.maintenanceAttempt, state: "submitted", txId };
      await writeRecord(root, record);
      return { kind: "local-committee-transition-submission", txId, finalizedReadback: "pending" };
    } catch (error) {
      let journalReserved = true;
      try { journalReserved = await journal.inspect() !== null; } catch { /* An unreadable journal is unknown. */ }
      const reportedTxId = error && typeof error === "object" && "txId" in error
        && typeof error.txId === "string" ? error.txId : undefined;
      record.maintenanceAttempt = { ...record.maintenanceAttempt,
        state: journalReserved ? "unknown" : "aborted-before-journal",
        journalReserved,
        ...(journalReserved && reportedTxId && reportedTxId.length <= 512
          ? { reportedTxId } : {}) };
      await writeRecord(root, record);
      if (!journalReserved) {
        throw new Error("Maintenance preflight stopped before journal reservation; inspect setup and prepare again");
      }
      throw new Error("Maintenance outcome is unknown; preserve the journal and reconcile, never retry blindly");
    } finally {
      if (typeof material?.stop === "function") {
        try { await material.stop(); } catch {
          console.error("Provider cleanup failed; preserve the maintenance journal");
        }
      }
    }
  });
}

export async function reconcileStandaloneCommitteeTransition(
  directory, requestPath, signingRequestPath, dependencies = {},
) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const attempt = record.maintenanceAttempt;
    if (!attempt) throw new Error("A reserved committee transition is required for reconciliation");
    if (attempt.state === "aborted-before-journal") {
      throw new Error("No maintenance journal was reserved; prepare a new signing request instead");
    }
    const legacyReadOnly = !record.committeeDeploymentApproval
      && !attempt.committeeDeploymentApprovalSha256;
    const { approval, requestBytes, verified } = await readApprovedCommitteeTransition(
      record, requestPath, dependencies, legacyReadOnly,
    );
    const signingRequestBytes = await regularBytes(resolve(signingRequestPath));
    const signingRequest = parseJsonBytes(signingRequestBytes);
    if (sha256(requestBytes) !== attempt.requestSha256
      || sha256(signingRequestBytes) !== attempt.signingRequestSha256
      || signingRequest.updateSha256 !== attempt.updateSha256
      || signingRequest.finalizedBlockHash !== attempt.finalizedBlockHash
      || (record.committeeDeploymentApproval
        && (attempt.committeeDeploymentApprovalSha256
          !== record.committeeDeploymentApproval.documentSha256
          || signingRequest.committeeDeploymentApprovalSha256
            !== record.committeeDeploymentApproval.documentSha256))
      || attempt.journalPath !== join(root, "committee-transition.json")) {
      throw new Error("Maintenance reconciliation disagrees with the reserved signing request");
    }
    if (!legacyReadOnly) {
      await requireCurrentApprovedAccess(root, record, verified,
        { network: approval.network }, dependencies);
    }
    setNetworkId(STANDALONE_PROFILE.networkId);
    const result = await (dependencies.reconcile ?? reconcileLocalNetworkCommitteeTransition)({
      approval,
      journal: new FileMaintenanceTransitionJournal(attempt.journalPath),
      approvedUpdateSha256: attempt.updateSha256,
      approvedFinalizedBlockHash: attempt.finalizedBlockHash,
    });
    if (!legacyReadOnly) {
      await requireCurrentApprovedAccess(root, record, verified,
        { network: approval.network }, dependencies);
    }
    if (!["not-reserved", "unavailable", "pending", "invalid-image", "stale-checkpoint",
      "unresolved", "conflict", "observed"].includes(result?.status)) {
      throw new Error("Maintenance reconciliation returned an invalid status");
    }
    if ((result.txId !== null && result.txId !== undefined
        && (typeof result.txId !== "string" || result.txId.length === 0 || result.txId.length > 512))
      || (attempt.txId && result.txId && result.txId !== attempt.txId)
      || (result.status === "observed"
        && (!HASH.test(result.finalizedBlockHash) || /^0x0{64}$/u.test(result.finalizedBlockHash)))) {
      throw new Error("Maintenance reconciliation returned evidence inconsistent with the reserved attempt");
    }
    const history = attempt.reconciliationHistory ?? [];
    if (history.length >= 256) {
      throw new Error("Maintenance reconciliation history is full; preserve the setup record for review");
    }
    history.push(result);
    attempt.reconciliationHistory = history;
    if (attempt.state === "recovered-no-journal-approved") {
      if (result.status !== "not-reserved" || result.txId) {
        attempt.state = "conflict";
        attempt.alert = "post-recovery-evidence-contradiction";
      }
    } else if (result.status === "not-reserved") {
      if (attempt.txId || attempt.journalReserved
        || ["observed", "observed-without-receipt", "conflict"].includes(attempt.state)) {
        attempt.alert = "journal-missing-after-submission";
        if (!["observed", "observed-without-receipt"].includes(attempt.state)) attempt.state = "conflict";
      } else {
        attempt.state = "recovery-required-no-journal";
        attempt.alert = "independent-human-recovery-required";
      }
    } else if (attempt.txId && !result.txId) {
      attempt.alert = "journal-submitted-id-missing";
      if (attempt.state !== "observed") attempt.state = "conflict";
    } else if (result.status === "conflict") {
      attempt.alert = "conflict";
      if (attempt.state !== "observed") attempt.state = "conflict";
    } else if (result.status === "stale-checkpoint") {
      attempt.alert = "stale-checkpoint";
      if (!["observed", "conflict"].includes(attempt.state)) attempt.state = "stale-checkpoint";
    } else if (result.status === "observed") {
      if (attempt.state !== "conflict") {
        attempt.state = result.txId ? "observed" : "observed-without-receipt";
      }
    } else if (result.status === "unresolved") {
      if (!["observed", "conflict"].includes(attempt.state)) attempt.state = "unresolved";
    }
    if (result.txId) attempt.txId = result.txId;
    attempt.reconciliation = result;
    await writeRecord(root, record);
    return result;
  });
}

export async function approveStandaloneCommitteeRecovery(
  directory, requestPath, signingRequestPath, documentPath, signaturePath,
  keyringDirectory, expectedFingerprint, dependencies = {},
) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const attempt = record.maintenanceAttempt;
    if (!record.committeeDeploymentApproval && !attempt?.committeeDeploymentApprovalSha256) {
      throw new Error("Legacy maintenance recovery requires an operator-reviewed migration decision");
    }
    if (attempt?.state !== "recovery-required-no-journal"
      || attempt.txId || attempt.reportedTxId || attempt.journalReserved
      || attempt.journalPath !== join(root, "committee-transition.json")) {
      throw new Error("Only an unresolved pre-journal crash window can receive recovery approval");
    }
    const journal = new FileMaintenanceTransitionJournal(attempt.journalPath);
    if (await journal.inspect() !== null) {
      throw new Error("Maintenance journal exists; a no-journal recovery decision is forbidden");
    }
    const { approval, requestBytes, catalog, verified } = await readApprovedCommitteeTransition(
      record, requestPath, dependencies,
    );
    const signingRequestBytes = await regularBytes(resolve(signingRequestPath));
    const signingRequest = parseJsonBytes(signingRequestBytes);
    if (sha256(requestBytes) !== attempt.requestSha256
      || sha256(signingRequestBytes) !== attempt.signingRequestSha256
      || attempt.committeeDeploymentApprovalSha256
        !== record.committeeDeploymentApproval.documentSha256
      || signingRequest.committeeDeploymentApprovalSha256
        !== record.committeeDeploymentApproval.documentSha256
      || signingRequest.updateSha256 !== attempt.updateSha256
      || signingRequest.finalizedBlockHash !== attempt.finalizedBlockHash
      || signingRequest.expiresAt !== approval.expiresAt.toISOString()) {
      throw new Error("Recovery evidence disagrees with the original approved maintenance attempt");
    }
    const now = (dependencies.now ?? Date.now)();
    const expiredAt = approval.expiresAt.getTime();
    if (!Number.isSafeInteger(now) || !Number.isFinite(expiredAt)
      || now < expiredAt + 10 * 60_000) {
      throw new Error("Original maintenance signing window must expire before recovery approval");
    }
    await requireCurrentApprovedAccess(root, record, verified,
      { network: approval.network }, dependencies);
    setNetworkId(STANDALONE_PROFILE.networkId);
    const freshApproval = { ...approval, expiresAt: new Date(now + 5 * 60_000) };
    const fresh = await (dependencies.prepareTransition ?? prepareLocalNetworkCommitteeTransition)(freshApproval);
    await requireCurrentApprovedAccess(root, record, verified,
      { network: approval.network }, dependencies);
    if (fresh.networkId !== STANDALONE_PROFILE.networkId || fresh.contractAddress !== approval.receipt.contractAddress
      || !HASH.test(fresh.finalizedBlockHash) || /^0x0{64}$/u.test(fresh.finalizedBlockHash)
      || fresh.finalizedBlockHash === attempt.finalizedBlockHash
      || fresh.currentAuthorityCounter !== BigInt(catalog.length - 1)
      || fresh.nextAuthorityCounter !== BigInt(catalog.length)
      || fresh.threshold !== record.committeeApproval.maintenancePolicy.threshold
      || JSON.stringify(fresh.committeeVerifyingKeys)
        !== JSON.stringify(record.committeeApproval.maintenancePolicy.verifyingKeys)
      || fresh.expiresAt !== freshApproval.expiresAt.toISOString()
      || !(fresh.dataToSign instanceof Uint8Array)
      || sha256(fresh.dataToSign) !== attempt.updateSha256) {
      throw new Error("Finalized registry image changed or did not advance after the abandoned attempt");
    }
    const document = await regularBytes(resolve(documentPath));
    const signature = await regularBytes(resolve(signaturePath));
    if (document.length > 32 * 1024 || signature.length > 64 * 1024) {
      throw new Error("Maintenance recovery decision or signature exceeds the bounded evidence size");
    }
    const decision = parseCanonicalSignedJson(document, "Maintenance recovery decision");
    const reservedAt = Date.parse(attempt.reservedAt);
    if (!exactFields(decision, ["approvedAt", "approvedFinalizedBlockHash", "decision",
      "expiredAt", "format", "requestSha256", "reviewedReference", "reviewerFingerprint",
      "recoveryFinalizedBlockHash", "signingRequestSha256", "sourceRevision", "updateSha256"])
      || decision.format !== "tr-local-maintenance-no-journal-recovery-v1"
      || decision.decision !== "authorize-new-attempt-after-absent-journal"
      || decision.sourceRevision !== record.sourceRevision
      || decision.requestSha256 !== attempt.requestSha256
      || decision.signingRequestSha256 !== attempt.signingRequestSha256
      || decision.updateSha256 !== attempt.updateSha256
      || decision.approvedFinalizedBlockHash !== attempt.finalizedBlockHash
      || !HASH.test(decision.recoveryFinalizedBlockHash)
      || /^0x0{64}$/u.test(decision.recoveryFinalizedBlockHash)
      || decision.recoveryFinalizedBlockHash === attempt.finalizedBlockHash
      || decision.expiredAt !== approval.expiresAt.toISOString()
      || decision.reviewerFingerprint !== expectedFingerprint
      || expectedFingerprint !== record.committeeApproval.reviewerFingerprint
      || !Number.isFinite(reservedAt)
      || !canonicalReviewerMetadata(decision,
        Math.max(expiredAt + 10 * 60_000, reservedAt), now + 60_000)) {
      throw new Error("Signed maintenance recovery decision does not bind the expired attempt and approved reviewer");
    }
    const evidence = await verifiedApprovalEvidence(
      root, "maintenance-recovery", document, signature, keyringDirectory,
      expectedFingerprint, dependencies, decision.approvedAt,
    );
    attempt.recoveryApproval = {
      ...evidence, approvedAt: decision.approvedAt,
      reviewedReference: decision.reviewedReference,
      reviewerFinalizedBlockHash: decision.recoveryFinalizedBlockHash,
      recoveryFinalizedBlockHash: fresh.finalizedBlockHash,
    };
    attempt.state = "recovered-no-journal-approved";
    attempt.alert = "human-recovered-no-journal";
    await writeRecord(root, record);
    return {
      state: attempt.state,
      recoveryApprovalSha256: evidence.documentSha256,
      recoveryFinalizedBlockHash: fresh.finalizedBlockHash,
    };
  });
}

export async function exportStandaloneApiApprovalChain(directory) {
  return withLock(directory, async (root) => {
    const { record } = await readRecord(root);
    const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
    if (sha256(inventory) !== record.install.inventorySha256) {
      throw new Error("Installed inventory changed since reviewer approval");
    }
    const verified = await verifyStandaloneInstallBundle(record.install.bundle);
    requireVerifiedInventoryBytes(verified, inventory, record.install.inventorySha256,
      "Installed inventory changed since reviewer approval");
    const manifest = await verifiedPackageManifestBytes(record.install.bundle, inventory, verified);
    const chain = buildStandaloneApiApprovalChain(record, sha256(manifest));
    const output = join(root, "api-approval-chain.json");
    await writePrivateSnapshot(output, Buffer.from(`${JSON.stringify(chain, null, 2)}\n`));
    return { path: output, sha256: sha256(await regularBytes(output, { privateFile: true })) };
  });
}

export async function standaloneSetupStatus(directory) {
  const { root, record } = await readRecord(directory);
  let genesisApprovalConsistent = true;
  if (record.setupId && record.genesisApproval) {
    try {
      readStoredGenesisApproval(record);
    } catch {
      genesisApprovalConsistent = false;
    }
  }
  let committeeApprovalConsistent = true;
  if (record.setupId && record.committeeApproval) {
    try {
      readStoredCommitteeApproval(record);
    } catch {
      committeeApprovalConsistent = false;
    }
  }
  if (record.setupId && record.committeeDeploymentApproval && committeeApprovalConsistent) {
    try {
      const inventory = await regularBytes(join(record.install.bundle, "install-inventory.json"));
      if (sha256(inventory) !== record.install.inventorySha256) {
        throw new Error("Installed inventory changed since deployment approval");
      }
      const pin = parseJsonBytes(inventory);
      if (typeof pin.packageManifest !== "string" || pin.packageManifest.length === 0
        || isAbsolute(pin.packageManifest) || pin.packageManifest.includes("\\")
        || pin.packageManifest.split("/").some((part) => part === ".." || part === "." || part === "")) {
        throw new Error("Installed release manifest path is unsafe");
      }
      const bundleRoot = await realpath(record.install.bundle);
      const manifestPath = join(bundleRoot, pin.packageManifest);
      const resolvedManifest = await realpath(manifestPath);
      if (!resolvedManifest.startsWith(`${bundleRoot}${sep}`)) {
        throw new Error("Installed release manifest escaped the bundle");
      }
      const manifest = await regularBytes(manifestPath);
      if (!SHA256.test(pin.packageManifestSha256 ?? "")
        || sha256(manifest) !== pin.packageManifestSha256) {
        throw new Error("Installed release manifest changed since deployment approval");
      }
      readStoredCommitteeDeploymentApproval(record, sha256(manifest));
    } catch {
      committeeApprovalConsistent = false;
    }
  }
  let restartObservation;
  try {
    restartObservation = await readStandaloneRestartEvidence(root, {
      sourceRevision: record.sourceRevision,
      installInventorySha256: record.install?.inventorySha256,
      project: record.stack?.project,
    });
  } catch {
    restartObservation = { status: "invalid-evidence-investigate" };
  }
  let lockPresent = false;
  try {
    await lstat(join(root, ".setup.lock"));
    lockPresent = true;
  } catch (error) {
    if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error;
  }
  return {
    format: FORMAT,
    sourceRevision: record.sourceRevision,
    installInventorySha256: record.install.inventorySha256,
    stackProject: record.stack?.project ?? null,
    stackNetworkId: record.stack?.observation?.topology?.networkId ?? null,
    approvedGenesisHash: record.genesisApproval && genesisApprovalConsistent
      ? record.ledgerObservation?.expectedGenesisHash ?? null : null,
    deployedContractAddress: record.deployment?.state === "observed"
      ? record.deployment.result?.receipt?.contractAddress ?? null : null,
    install: "verified-staged-bytes-only",
    stackConfiguration: record.stack?.observation ? "observed-ledger-bridge-only"
      : record.stack ? "prepared-runtime-unobserved" : "pending",
    localLedger: record.genesisApproval ? genesisApprovalConsistent
      ? "operator-pinned-reviewer-signature-verified" : "invalid-approval-evidence-investigate"
      : record.ledgerObservation ? "node-observed-not-independently-approved" : "pending",
    deployment: record.deployment?.state ?? "pending",
    stagedVerifierKeys: Object.entries(record.verifierKeyInsertions ?? {})
      .map(([circuitName, entry]) => ({ circuitName, state: entry.state })),
    setupLock: lockPresent ? "present-inspect-before-removal" : "absent",
    maintenanceApproval: (record.committeeApproval || record.committeeDeploymentApproval)
      && !committeeApprovalConsistent
      ? "invalid-approval-evidence-investigate"
      : record.committeeDeploymentApproval
        ? "deployment-bound-roster-signature-verified-transition-pending"
        : record.committeeApproval ? "roster-signature-verified-deployment-binding-pending" : "pending",
    maintenanceTransition: record.maintenanceAttempt?.state ?? "pending",
    maintenanceTransitionAlert: record.maintenanceAttempt?.alert ?? null,
    maintenanceLastReadback: record.maintenanceAttempt?.reconciliation?.status ?? null,
    offlineJourneys: "pending",
    restartObservation,
    restartRestore: "pending",
    independentReview: "pending",
    releaseQualified: false,
  };
}

export async function runStandaloneSetupInteractive(
  directory, io = createInterface({ input: process.stdin, output: process.stdout }), dependencies = {},
) {
  try {
    let record;
    try {
      ({ record } = await readRecord(directory));
    } catch (error) {
      if (!(error && typeof error === "object" && "code" in error && error.code === "ENOENT")) throw error;
      const bundle = await io.question("Verified install bundle directory: ");
      record = await initializeStandaloneSetup(directory, bundle);
    }
    if (!record.ledgerObservation) {
      if (!record.stack) {
        const project = await io.question("New local Compose project (blank to defer): ");
        if (!project) {
          console.log(JSON.stringify(await standaloneSetupStatus(directory), null, 2));
          return;
        }
        const nodePort = await io.question("Unused node loopback port: ");
        const indexerPort = await io.question("Unused indexer loopback port: ");
        const proofPort = await io.question("Unused proof-server loopback port: ");
        await prepareStandaloneStack(directory, { project, nodePort, indexerPort, proofPort });
      }
      ({ record } = await readRecord(directory));
      if (!record.stack.observation) {
        const ready = await io.question("Start the reviewed stack, then type OBSERVE STACK (blank to stop): ");
        if (ready !== "OBSERVE STACK") {
          console.log(JSON.stringify(await standaloneSetupStatus(directory), null, 2));
          return;
        }
        await observeStandaloneStack(directory, dependencies.stackObservation);
      }
      const collect = await io.question(
        "Collect node-reported genesis candidate for independent review? Type COLLECT or leave blank: ",
      );
      if (collect === "COLLECT") {
        console.log(JSON.stringify(await collectStandaloneGenesisCandidate(
          directory, dependencies.candidateObservation,
        )));
      } else if (collect !== "") {
        throw new Error("Genesis candidate collection requires COLLECT or blank");
      }
      const pin = await io.question("Independently reviewed local genesis pin JSON (blank to stop): ");
      if (pin) await observeStandaloneLedger(directory, pin);
    }
    ({ record } = await readRecord(directory));
    if (record.ledgerObservation && !record.genesisApproval) {
      const document = await io.question("Reviewer-signed genesis approval JSON (blank to stop): ");
      if (document) {
        const signature = await io.question("Detached signature file: ");
        const keyring = await io.question("Private local GPG keyring with reviewer public key: ");
        const fingerprint = await io.question("Pinned reviewer primary-key fingerprint (40 uppercase hex): ");
        await approveStandaloneGenesis(directory, document, signature, keyring, fingerprint);
      }
    }
    ({ record } = await readRecord(directory));
    if (record.genesisApproval && !record.committeeApproval) {
      const document = await io.question("Reviewer-signed release committee roster JSON (blank to stop before deployment): ");
      if (document) {
        const signature = await io.question("Detached committee signature file: ");
        const keyring = await io.question("Private local GPG keyring with governance reviewer public key: ");
        const fingerprint = await io.question("Pinned governance primary-key fingerprint (40 uppercase hex): ");
        await approveStandaloneCommittee(directory, document, signature, keyring, fingerprint);
      }
    }
    ({ record } = await readRecord(directory));
    if (record.genesisApproval && record.committeeApproval && !record.deployment) {
      const plan = await io.question("Approved deployment plan JSON (blank to stop): ");
      if (plan && await io.question("Type DEPLOY ONCE to reserve one attempt: ") === "DEPLOY ONCE") {
        await attemptStandaloneDeployment(directory, plan);
      }
    }
    ({ record } = await readRecord(directory));
    if (record.committeeApproval && !record.committeeDeploymentApproval
      && record.deployment?.state === "observed"
      && record.deployment.result?.readbackStatus === "staged-bootstrap-pending") {
      const document = await io.question("Reviewer-signed deployment-bound committee approval JSON (blank to defer): ");
      if (document) {
        const signature = await io.question("Detached deployment approval signature file: ");
        const keyring = await io.question("Private governance reviewer public-key keyring: ");
        await approveStandaloneCommitteeDeployment(
          directory, document, signature, keyring, record.committeeApproval.reviewerFingerprint,
        );
      }
    }
    console.log(JSON.stringify(await standaloneSetupStatus(directory), null, 2));
  } finally {
    io.close();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, directory, input, signature, keyring, fingerprint, extra, more] = process.argv.slice(2);
  if (!directory || !["run", "init", "prepare-stack", "observe-stack", "collect-genesis-candidate", "draft-genesis-pin", "observe", "draft-genesis", "approve-genesis", "draft-committee", "approve-committee", "approve-committee-deployment", "deploy", "reconcile-deploy", "insert-key", "reconcile-key", "prepare-committee", "submit-committee", "reconcile-committee", "approve-committee-recovery", "check-helm-bootstrap", "export-api-approval-chain", "status"].includes(command)) {
    throw new Error("Usage: node scripts/standalone-setup-wizard.mjs <run|init|prepare-stack|observe-stack|collect-genesis-candidate|draft-genesis-pin|observe|draft-genesis|approve-genesis|draft-committee|approve-committee|approve-committee-deployment|deploy|reconcile-deploy|insert-key|reconcile-key|prepare-committee|submit-committee|reconcile-committee|approve-committee-recovery|check-helm-bootstrap|status> <private-setup-dir> [inputs]");
  }
  if (command === "run") await runStandaloneSetupInteractive(directory);
  else if (command === "init" && input) console.log(JSON.stringify(await initializeStandaloneSetup(directory, input)));
  else if (command === "prepare-stack" && input && signature && keyring && fingerprint) {
    console.log(JSON.stringify(await prepareStandaloneStack(directory, {
      project: input, nodePort: signature, indexerPort: keyring, proofPort: fingerprint,
    })));
  }
  else if (command === "observe-stack") console.log(JSON.stringify(await observeStandaloneStack(directory)));
  else if (command === "collect-genesis-candidate") {
    console.log(JSON.stringify(await collectStandaloneGenesisCandidate(directory)));
  }
  else if (command === "draft-genesis-pin") {
    console.log(JSON.stringify(await draftStandaloneGenesisPin(directory)));
  }
  else if (command === "observe" && input) console.log(JSON.stringify(await observeStandaloneLedger(directory, input)));
  else if (command === "draft-genesis" && input) {
    const proposal = parseJsonBytes(await regularBytes(resolve(input)));
    console.log(JSON.stringify(await draftStandaloneGenesisApproval(directory, proposal)));
  }
  else if (command === "approve-genesis" && input && signature && keyring && fingerprint) {
    console.log(JSON.stringify(await approveStandaloneGenesis(directory, input, signature, keyring, fingerprint)));
  }
  else if (command === "draft-committee" && input) {
    const proposal = parseJsonBytes(await regularBytes(resolve(input)));
    console.log(JSON.stringify(await draftStandaloneCommitteeApproval(directory, proposal)));
  }
  else if (command === "approve-committee" && input && signature && keyring && fingerprint) {
    console.log(JSON.stringify(await approveStandaloneCommittee(directory, input, signature, keyring, fingerprint)));
  }
  else if (command === "approve-committee-deployment" && input && signature && keyring && fingerprint) {
    console.log(JSON.stringify(await approveStandaloneCommitteeDeployment(
      directory, input, signature, keyring, fingerprint,
    )));
  }
  else if (command === "deploy" && input) console.log(JSON.stringify(await attemptStandaloneDeployment(directory, input)));
  else if (command === "reconcile-deploy" && input) {
    const result = await reconcileStandaloneDeployment(directory, input);
    console.log(JSON.stringify(result));
    if (result.readbackStatus !== "staged-bootstrap-pending") process.exitCode = 2;
  }
  else if (command === "insert-key" && input) {
    const result = await attemptStandaloneVerifierKeyInsertion(directory, input);
    console.log(JSON.stringify(result));
    if (result.readbackStatus !== "verified") process.exitCode = 2;
  }
  else if (command === "reconcile-key" && input) {
    const result = await reconcileStandaloneVerifierKeyInsertion(directory, input);
    console.log(JSON.stringify(result));
    if (result.readback.status !== "verified") process.exitCode = 2;
  }
  else if (command === "prepare-committee" && input) {
    console.log(JSON.stringify(await prepareStandaloneCommitteeTransition(directory, input), null, 2));
  }
  else if (command === "submit-committee" && input && signature && keyring) {
    console.log(JSON.stringify(await submitStandaloneCommitteeTransition(directory, input, signature, keyring)));
  }
  else if (command === "reconcile-committee" && input && signature) {
    const result = await reconcileStandaloneCommitteeTransition(directory, input, signature);
    console.log(JSON.stringify(result));
    if (result.status !== "observed" || !result.txId) process.exitCode = 2;
  }
  else if (command === "approve-committee-recovery" && input && signature && keyring
    && fingerprint && extra && more) {
    console.log(JSON.stringify(await approveStandaloneCommitteeRecovery(
      directory, input, signature, keyring, fingerprint, extra, more,
    )));
  }
  else if (command === "check-helm-bootstrap" && input && signature && keyring
    && fingerprint && extra) {
    console.log(JSON.stringify(await checkStandaloneHelmBootstrapHandoff(directory, {
      valuesPath: input, receiptPath: signature, signaturePath: keyring,
      keyringPath: fingerprint, signerFingerprint: extra,
    })));
  }
  else if (command === "status") console.log(JSON.stringify(await standaloneSetupStatus(directory), null, 2));
  else if (command === "export-api-approval-chain") {
    console.log(JSON.stringify(await exportStandaloneApiApprovalChain(directory)));
  }
  else throw new Error(`Missing input path for ${command}`);
}
