#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, open, readFile, realpath } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { observeStandaloneTopology, standaloneStackConfig } from "./check-standalone-topology.mjs";

const run = promisify(execFile);
const SHA256 = /^[0-9a-f]{64}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const SERVICES = ["node", "indexer", "proof-server"];
const BASELINE = "restart-baseline.json";
const VERIFICATION = "restart-verification.json";

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function privateDirectory(directory) {
  const root = await realpath(resolve(directory));
  const stat = await lstat(root);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Restart evidence requires an owned mode-0700 setup directory");
  }
  return root;
}

async function privateFile(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size === 0 || stat.size > 1024 * 1024 || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Restart evidence input must be an owned private regular file");
  }
  return readFile(path);
}

async function writeEvidence(path, value) {
  const file = await open(path, "wx", 0o600);
  try {
    await file.writeFile(`${JSON.stringify(value, null, 2)}\n`);
    await file.sync();
  } finally {
    await file.close();
  }
}

function parsePreparedEnv(bytes) {
  const lines = bytes.toString("utf8").trimEnd().split("\n");
  const entries = lines.map((line) => {
    const separator = line.indexOf("=");
    if (separator < 1) throw new Error("Prepared stack environment is malformed");
    return [line.slice(0, separator), line.slice(separator + 1)];
  });
  if (entries.length !== 8 || new Set(entries.map(([name]) => name)).size !== 8) {
    throw new Error("Prepared stack environment has unexpected entries");
  }
  return Object.fromEntries(entries);
}

async function readContext(root, dependencies) {
  const record = JSON.parse(await privateFile(join(root, "setup-record.json")));
  if (!record.stack?.observation || record.stack.state !== "observed-ledger-bridge-only"
    || !SHA256.test(record.install?.inventorySha256 ?? "")
    || !SHA256.test(record.stack.envFileSha256 ?? "")
    || !SHA256.test(record.stack.composeSha256 ?? "")
    || !SHA256.test(record.stack.offlineComposeSha256 ?? "")) {
    throw new Error("Restart observation requires a prepared and observed install stack");
  }
  const bundle = await realpath(record.install.bundle);
  const inventory = await readFile(join(bundle, "install-inventory.json"));
  const envBytes = await privateFile(join(root, "stack.env"));
  if (sha256(inventory) !== record.install.inventorySha256
    || sha256(envBytes) !== record.stack.envFileSha256) {
    throw new Error("Prepared install inventory or private environment changed");
  }
  const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(bundle);
  if (verified.sourceRevision !== record.sourceRevision
    || verified.runtimeComposeSha256 !== record.stack.composeSha256
    || verified.runtimeOfflineComposeSha256 !== record.stack.offlineComposeSha256
    || !Array.isArray(verified.images) || verified.images.length !== SERVICES.length) {
    throw new Error("Running stack no longer matches the verified install bundle");
  }
  const env = parsePreparedEnv(envBytes);
  const config = standaloneStackConfig(env);
  if (config.project !== record.stack.project
    || JSON.stringify(config.ports) !== JSON.stringify(record.stack.ports)
    || env.TR_PROOF_PARAMS_DIR !== JSON.stringify(join(bundle, "proof-params"))
    || !/^[0-9a-f]{48}$/u.test(env.TR_INDEXER_PASSWORD ?? "")
    || !/^[0-9a-f]{64}$/u.test(env.TR_INDEXER_SECRET ?? "")) {
    throw new Error("Prepared private inputs differ from the selected project");
  }
  return { record, bundle, verified, env, config };
}

async function docker(command, args) {
  const result = await command("docker", args, { timeout: 30_000, maxBuffer: 1024 * 1024 });
  return result.stdout.trim();
}

async function containerState(command, project, service) {
  const ids = (await docker(command, ["ps", "-aq", "--filter", `label=com.docker.compose.project=${project}`,
    "--filter", `label=com.docker.compose.service=${service}`])).split("\n").filter(Boolean);
  if (ids.length !== 1) throw new Error(`Expected one running ${service} container`);
  const state = JSON.parse(await docker(command, ["inspect", "--format", "{{json .State}}", ids[0]]));
  if (state.Running !== true || state.Paused === true || !Number.isFinite(Date.parse(state.StartedAt))) {
    throw new Error(`Invalid running ${service} state`);
  }
  return { id: ids[0], startedAt: state.StartedAt };
}

async function volumeCreatedAt(command, name) {
  const value = await docker(command, ["volume", "inspect", "--format", "{{.CreatedAt}}", name]);
  if (!Number.isFinite(Date.parse(value))) throw new Error(`Invalid volume creation time: ${name}`);
  return value;
}

async function nodeRpc(command, containerId, method, params) {
  const request = JSON.stringify({ jsonrpc: "2.0", id: 1, method, params });
  const response = JSON.parse(await docker(command, ["exec", containerId, "curl", "-sf",
    "-H", "Content-Type: application/json", "-d", request, "http://localhost:9944"]));
  if (response?.jsonrpc !== "2.0" || response.id !== 1 || response.error || response.result == null) {
    throw new Error(`Local node RPC failed: ${method}`);
  }
  return response.result;
}

export async function observeStandaloneRestartSnapshot(directory, options = {}, dependencies = {}) {
  const root = await privateDirectory(directory);
  const { record, bundle, verified, env, config } = await readContext(root, dependencies);
  const topology = await (dependencies.observeTopology ?? observeStandaloneTopology)(config, {
    requirePrivateInputs: true,
    proofParamsDir: join(bundle, "proof-params"),
    indexerPassword: env.TR_INDEXER_PASSWORD,
    indexerSecret: env.TR_INDEXER_SECRET,
    sourceRevision: record.sourceRevision,
    images: verified.images,
    allowOffline: true,
    allowUnpublishedHostPorts: options.allowUnpublishedHostPorts === true,
    composeFiles: [join(bundle, "compose.yml"), join(bundle, "compose.offline.yml")],
  });
  if (topology.project !== config.project || topology.preparedInputsMatched !== true
    || topology.verifiedImageIdsMatched !== true || topology.bundleComposeFilesMatched !== true
    || topology.internalNetworkOnly !== true || !topology.networkId) {
    throw new Error("Restart snapshot requires verified live standalone topology");
  }
  const command = dependencies.command ?? run;
  const containers = Object.fromEntries(await Promise.all(SERVICES.map(async (service) =>
    [service, await containerState(command, config.project, service)])));
  const volumes = {
    node: await volumeCreatedAt(command, `${config.project}_node-data`),
    indexer: await volumeCreatedAt(command, `${config.project}_indexer-data`),
  };
  const rpc = dependencies.rpc ?? ((method, params) => nodeRpc(command, containers.node.id, method, params));
  const observerSha256 = sha256(await readFile(fileURLToPath(import.meta.url)));
  const genesisHash = await rpc("chain_getBlockHash", [0]);
  const finalizedHash = await rpc("chain_getFinalizedHead", []);
  const header = await rpc("chain_getHeader", [finalizedHash]);
  const finalizedHeight = /^0x[0-9a-f]+$/u.test(header?.number ?? "")
    ? Number.parseInt(header.number.slice(2), 16) : NaN;
  if (!HASH.test(genesisHash) || !HASH.test(finalizedHash)
    || !Number.isSafeInteger(finalizedHeight) || finalizedHeight < 1
    || await rpc("chain_getBlockHash", [finalizedHeight]) !== finalizedHash) {
    throw new Error("Local finalized chain checkpoint is invalid or inconsistent");
  }
  let historicalHash;
  if (options.historicalHeight !== undefined) {
    if (!Number.isSafeInteger(options.historicalHeight) || options.historicalHeight < 1) {
      throw new Error("Historical checkpoint height is invalid");
    }
    historicalHash = await rpc("chain_getBlockHash", [options.historicalHeight]);
  }
  return {
    format: "tr-standalone-restart-snapshot-v1",
    observedAt: new Date().toISOString(),
    project: config.project,
    networkId: topology.networkId,
    hostPortAccess: topology.hostPortAccess ?? "effective-loopback",
    sourceRevision: record.sourceRevision,
    observerSha256,
    installInventorySha256: record.install.inventorySha256,
    stackEnvSha256: record.stack.envFileSha256,
    genesisHash, finalizedHeight, finalizedHash,
    ...(historicalHash === undefined ? {} : { historicalHash }),
    volumes, containers,
    scope: "ledger bridge only; contract, wallet, API, actor journeys, and restore not verified",
  };
}

export function compareStandaloneRestartSnapshots(before, after) {
  if (before?.format !== "tr-standalone-restart-snapshot-v1"
    || after?.format !== before.format || !HASH.test(before.genesisHash ?? "")
    || !HASH.test(before.finalizedHash ?? "")
    || typeof before.networkId !== "string" || before.networkId.length === 0
    || !["effective-loopback", "unpublished-install-access-required"].includes(before.hostPortAccess)
    || !Number.isSafeInteger(before.finalizedHeight) || before.finalizedHeight < 1) {
    throw new Error("Restart baseline is malformed");
  }
  for (const key of ["project", "sourceRevision", "observerSha256",
    "installInventorySha256", "stackEnvSha256", "networkId", "hostPortAccess",
    "genesisHash"]) {
    if (after[key] !== before[key]) throw new Error(`Restart evidence changed ${key}`);
  }
  for (const role of ["node", "indexer"]) {
    if (before.volumes?.[role] !== after.volumes?.[role]) {
      throw new Error(`Restart replaced ${role} persistent volume`);
    }
  }
  for (const service of SERVICES) {
    if (before.containers?.[service]?.id !== after.containers?.[service]?.id) {
      throw new Error(`Restart replaced ${service} container`);
    }
    const oldTime = Date.parse(before.containers?.[service]?.startedAt ?? "");
    const newTime = Date.parse(after.containers?.[service]?.startedAt ?? "");
    if (!Number.isFinite(oldTime) || !Number.isFinite(newTime) || newTime <= oldTime) {
      throw new Error(`Restart did not advance ${service} start time`);
    }
  }
  if (after.historicalHash !== before.finalizedHash
    || !Number.isSafeInteger(after.finalizedHeight)
    || after.finalizedHeight <= before.finalizedHeight) {
    throw new Error("Restart lost finalized history or finality did not progress");
  }
  return {
    kind: "standalone-ledger-bridge-restart-observation",
    project: before.project,
    sourceRevision: before.sourceRevision,
    beforeFinalizedHeight: before.finalizedHeight,
    afterFinalizedHeight: after.finalizedHeight,
    preservedCheckpointHash: before.finalizedHash,
    independentServiceRestarts: "operator-command-log-required",
    contractReadback: "not-verified",
    crossHostRestore: "not-run",
    releaseQualified: false,
  };
}

export async function captureStandaloneRestartBaseline(directory, dependencies = {}) {
  const root = await privateDirectory(directory);
  const snapshot = await observeStandaloneRestartSnapshot(root,
    { allowUnpublishedHostPorts: true }, dependencies);
  await writeEvidence(join(root, BASELINE), snapshot);
  return { baselinePath: join(root, BASELINE), project: snapshot.project,
    finalizedHeight: snapshot.finalizedHeight, finalizedHash: snapshot.finalizedHash };
}

export async function verifyStandaloneRestart(directory, dependencies = {}) {
  const root = await privateDirectory(directory);
  const baselineBytes = await privateFile(join(root, BASELINE));
  const baseline = JSON.parse(baselineBytes);
  const after = await observeStandaloneRestartSnapshot(root,
    { historicalHeight: baseline.finalizedHeight, allowUnpublishedHostPorts: true }, dependencies);
  const result = compareStandaloneRestartSnapshots(baseline, after);
  await writeEvidence(join(root, VERIFICATION), {
    ...result, observedAt: new Date().toISOString(), baselineSha256: sha256(baselineBytes), after,
  });
  return result;
}

export async function readStandaloneRestartEvidence(directory, expected) {
  const root = await privateDirectory(directory);
  let baselineBytes;
  let verificationBytes;
  try {
    baselineBytes = await privateFile(join(root, BASELINE));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  try {
    verificationBytes = await privateFile(join(root, VERIFICATION));
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
  if (!baselineBytes && !verificationBytes) return { status: "pending" };
  if (!baselineBytes) throw new Error("Restart verification exists without its baseline");
  const baseline = JSON.parse(baselineBytes);
  if (baseline.format !== "tr-standalone-restart-snapshot-v1"
    || baseline.sourceRevision !== expected.sourceRevision
    || baseline.installInventorySha256 !== expected.installInventorySha256
    || baseline.project !== expected.project) {
    throw new Error("Restart baseline is not bound to this setup");
  }
  if (!verificationBytes) return { status: "baseline-captured-verification-pending" };
  const verification = JSON.parse(verificationBytes);
  const comparison = compareStandaloneRestartSnapshots(baseline, verification.after);
  if (verification.baselineSha256 !== sha256(baselineBytes)
    || !Number.isFinite(Date.parse(verification.observedAt ?? ""))
    || Object.entries(comparison).some(([key, value]) => verification[key] !== value)) {
    throw new Error("Restart verification does not match its baseline and readback");
  }
  return {
    status: "verified-ledger-bridge-only",
    beforeFinalizedHeight: comparison.beforeFinalizedHeight,
    afterFinalizedHeight: comparison.afterFinalizedHeight,
  };
}

if (process.argv[1] && await realpath(resolve(process.argv[1])) === fileURLToPath(import.meta.url)) {
  const [action, directory] = process.argv.slice(2);
  if (process.argv.length !== 4 || !["capture", "verify"].includes(action)) {
    throw new Error("Usage: node scripts/check-standalone-restart.mjs <capture|verify> <private-setup-dir>");
  }
  const result = action === "capture"
    ? await captureStandaloneRestartBaseline(directory)
    : await verifyStandaloneRestart(directory);
  console.log(JSON.stringify(result));
}
