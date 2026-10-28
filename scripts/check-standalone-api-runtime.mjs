#!/usr/bin/env node

import { execFile } from "node:child_process";
import { lstat, realpath } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { standaloneStackConfig } from "./check-standalone-topology.mjs";

const run = promisify(execFile);
const services = ["api", "indexer", "node", "proof-server"];
const fingerprintPattern = /^[0-9A-F]{40}$/u;
const sha256Pattern = /^[0-9a-f]{64}$/u;
const apiHealthcheck = ["CMD", "node", "-e",
  "fetch('http://127.0.0.1:4400/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"];

function requireContainerImage(container, role, expected) {
  const verified = role === "api" ? expected.apiRuntime
    : expected.images.find((image) => image.role === role);
  const acceptedIds = role === "api"
    ? [verified?.imageId, verified?.configId]
    : verified?.acceptedIds;
  if (typeof container.Image !== "string"
    || !Array.isArray(acceptedIds) || !acceptedIds.includes(container.Image)
    || container.Config?.Image !== `tr-standalone/${role}:sha-${expected.sourceRevision}`) {
    throw new Error(`Running ${role} image differs from the verified install`);
  }
}

function normalizedEnvironment(entries) {
  if (!Array.isArray(entries) || entries.some((entry) =>
    typeof entry !== "string" || !/^[A-Za-z_][A-Za-z_0-9]*=/u.test(entry))) {
    throw new Error("API runtime process environment is invalid");
  }
  const names = entries.map((entry) => entry.slice(0, entry.indexOf("=")));
  if (new Set(names).size !== names.length) {
    throw new Error("API runtime process environment has duplicate variables");
  }
  return [...entries].sort();
}

/** A Docker topology observation only; it never approves a plan or proves finality. */
export function checkStandaloneApiRuntime(network, containers, expected) {
  const config = standaloneStackConfig({ TR_STACK_NAME: expected?.project });
  if (!expected || !/^[0-9a-f]{40}$/u.test(expected.sourceRevision)
    || !sha256Pattern.test(expected.inventorySha256 ?? "")
    || !/^[0-9]+$/u.test(expected.uid) || expected.uid === "0"
    || !/^[0-9]+$/u.test(expected.gid) || expected.gid === "0"
    || !fingerprintPattern.test(expected.reviewerFingerprint)
    || typeof expected.approvalDir !== "string" || !expected.approvalDir.startsWith("/")
    || expected.approvalDir === "/"
    || !Array.isArray(expected.composeFiles) || expected.composeFiles.length !== 3
    || !expected.composeFiles.every((file) => typeof file === "string" && file.startsWith("/"))
    || !expected.apiRuntime?.imageId || !expected.apiRuntime?.configId
    || !Array.isArray(expected.apiImageEnv) || !Array.isArray(expected.images)
    || expected.images.length !== 3
    || ["indexer", "node", "proof-server"].some((role) =>
      !expected.images.some((image) => image.role === role))) {
    throw new Error("Approved API runtime observation inputs are incomplete");
  }
  if (network?.Name !== config.network || !network.Id
    || network.Internal !== true || network.Driver !== "bridge"
    || network.EnableIPv6 !== false
    || network.Labels?.["com.docker.compose.project"] !== config.project) {
    throw new Error("API runtime is not on the dedicated internal ledger network");
  }
  if (!Array.isArray(containers) || containers.length !== services.length) {
    throw new Error("API runtime project must have exactly four services");
  }
  const byRole = new Map();
  for (const container of containers) {
    const labels = container.Config?.Labels;
    const role = labels?.["com.docker.compose.service"];
    if (!services.includes(role) || byRole.has(role)
      || labels?.["com.docker.compose.project"] !== config.project
      || container.State?.Running !== true || container.State?.Paused === true
      || (container.State?.Health && container.State.Health.Status !== "healthy")) {
      throw new Error("API runtime service is missing, duplicated, or unhealthy");
    }
    requireContainerImage(container, role, expected);
    const networks = container.NetworkSettings?.Networks;
    if (Object.keys(networks ?? {}).length !== 1
      || networks[config.network]?.NetworkID !== network.Id) {
      throw new Error("API runtime service has a non-internal network attachment");
    }
    byRole.set(role, container);
  }
  if (byRole.size !== services.length) {
    throw new Error("API runtime service set is incomplete");
  }
  const attached = Object.keys(network.Containers ?? {}).sort();
  const inspected = containers.map((container) => container.Id).sort();
  if (attached.length !== inspected.length
    || attached.some((id, index) => id !== inspected[index])) {
    throw new Error("API runtime ledger network has an extra or missing attachment");
  }
  const api = byRole.get("api");
  const labels = api.Config.Labels;
  if (typeof api.State?.StartedAt !== "string"
    || !Number.isFinite(Date.parse(api.State.StartedAt))
    || !Number.isSafeInteger(api.RestartCount) || api.RestartCount < 0) {
    throw new Error("API runtime start and restart evidence is unavailable");
  }
  if (JSON.stringify(normalizedEnvironment(api.Config.Env))
    !== JSON.stringify(normalizedEnvironment(expected.apiImageEnv))) {
    throw new Error("API runtime process environment differs from the verified image");
  }
  if (labels["com.docker.compose.project.config_files"] !== expected.composeFiles.join(",")
    || api.Config.User !== `${expected.uid}:${expected.gid}`
    || JSON.stringify(api.Config.Entrypoint) !== JSON.stringify(["node", "/app/bin/trust-registry-api.mjs"])
    || JSON.stringify(api.Config.Cmd) !== JSON.stringify([
      "serve", "--local-ledger-plan", "/run/trust-registry/api-plan.json",
      "--local-ledger-signature", "/run/trust-registry/api-plan.sig",
      "--local-ledger-keyring", "/run/trust-registry/reviewer-keyring",
      "--local-ledger-reviewer", expected.reviewerFingerprint,
      "--host", "0.0.0.0", "--cluster-bind", "--serve-portals",
    ])) {
    throw new Error("API runtime command or approved identity differs from the pinned overlay");
  }
  const host = api.HostConfig;
  if (host?.ReadonlyRootfs !== true || host.Privileged === true
    || !host.CapDrop?.includes("ALL")
    || host.SecurityOpt?.length !== 1 || host.SecurityOpt[0] !== "no-new-privileges:true"
    || host.PidsLimit !== 128 || host.Init !== true
    || [host.PidMode, host.IpcMode, host.UsernsMode, host.UTSMode,
      host.CgroupnsMode].includes("host")
    || (host.CapAdd?.length ?? 0) !== 0
    || (host.Devices?.length ?? 0) !== 0
    || (host.DeviceRequests?.length ?? 0) !== 0
    || Object.keys(host.Sysctls ?? {}).length !== 0
    || (host.ExtraHosts?.length ?? 0) !== 0
    || (host.PortBindings && Object.keys(host.PortBindings).length !== 0)
    || Object.values(api.NetworkSettings?.Ports ?? {}).some((bindings) => bindings !== null)) {
    throw new Error("API runtime privileges or host publishing differ from the pinned overlay");
  }
  if (JSON.stringify(api.Config.Healthcheck?.Test) !== JSON.stringify(apiHealthcheck)
    || api.State?.Health?.Status !== "healthy") {
    throw new Error("API runtime health check is absent or unhealthy");
  }
  const tmpfsOptions = host.Tmpfs?.["/tmp"]?.split(",");
  const allowedTmpfsOptions = new Set(["rw", "nosuid", "nodev", "noexec",
    "size=33554432", "size=32m"]);
  if (api.Mounts?.length !== 1 || api.Mounts[0].Type !== "bind"
    || api.Mounts[0].Source !== expected.approvalDir
    || api.Mounts[0].Destination !== "/run/trust-registry"
    || api.Mounts[0].RW !== false
    || Object.keys(host.Tmpfs ?? {}).length !== 1
    || !Array.isArray(tmpfsOptions) || tmpfsOptions.length !== 5
    || new Set(tmpfsOptions).size !== 5
    || !tmpfsOptions.every((option) => allowedTmpfsOptions.has(option))
    || !["rw", "nosuid", "nodev", "noexec"].every((option) =>
      tmpfsOptions.includes(option))) {
    throw new Error("API runtime approval mount or temporary filesystem differs from the pinned overlay");
  }
  return {
    kind: "standalone-api-runtime-topology-observation",
    project: config.project,
    networkId: network.Id,
    apiContainerId: api.Id,
    apiStartedAt: api.State.StartedAt,
    apiRestartCount: api.RestartCount,
    sourceRevision: expected.sourceRevision,
    installInventorySha256: expected.inventorySha256,
    imageIdsMatched: true,
    approvalMountReadOnly: true,
    internalNetworkOnly: true,
    hostPortPublished: false,
    finalizedReadback: "not-verified",
    egressDenied: "not-verified",
    actorJourneys: "not-run",
    releaseQualified: false,
  };
}

async function docker(args) {
  const { stdout } = await run("docker", args, { timeout: 20_000, maxBuffer: 8 * 1024 * 1024 });
  return stdout;
}

export async function observeStandaloneApiRuntime(bundle, env = process.env) {
  const root = await realpath(resolve(bundle));
  const verified = await verifyStandaloneInstallBundle(root);
  if (!verified.runtimeApiComposeSha256 || !verified.apiRuntime) {
    throw new Error("Verified bundle does not pin an API runtime overlay and image");
  }
  if (typeof env.TR_API_APPROVAL_DIR !== "string"
    || !env.TR_API_APPROVAL_DIR.startsWith("/")
    || env.TR_API_APPROVAL_DIR === "/") {
    throw new Error("Approved API runtime directory must be explicit and absolute");
  }
  const approvalPath = resolve(env.TR_API_APPROVAL_DIR);
  const approvalStat = await lstat(approvalPath);
  if (!approvalStat.isDirectory() || approvalStat.isSymbolicLink()
    || (approvalStat.uid !== 0 && approvalStat.uid !== Number(env.TR_API_UID))
    || (approvalStat.mode & 0o022) !== 0) {
    throw new Error("Approved API runtime directory must have a trusted owner and private permissions");
  }
  const config = standaloneStackConfig(env);
  const ids = (await docker(["ps", "-aq", "--filter",
    `label=com.docker.compose.project=${config.project}`])).trim().split("\n").filter(Boolean);
  if (ids.length !== services.length) {
    throw new Error("Dedicated API runtime project is absent or has unexpected containers");
  }
  const [network] = JSON.parse(await docker(["network", "inspect", config.network]));
  const containers = JSON.parse(await docker(["inspect", ...ids]));
  const [image] = JSON.parse(await docker(["image", "inspect", verified.apiRuntime.configId]));
  if (image?.Id !== verified.apiRuntime.configId) {
    throw new Error("Locally loaded API image config differs from the verified bundle");
  }
  return checkStandaloneApiRuntime(network, containers, {
    project: config.project,
    sourceRevision: verified.sourceRevision,
    inventorySha256: verified.inventorySha256,
    images: verified.images,
    apiRuntime: verified.apiRuntime,
    apiImageEnv: image.Config?.Env,
    composeFiles: ["compose.yml", "compose.offline.yml", "compose.api.yml"]
      .map((name) => `${root}/${name}`),
    approvalDir: approvalPath,
    uid: env.TR_API_UID,
    gid: env.TR_API_GID,
    reviewerFingerprint: env.TR_API_REVIEWER_FINGERPRINT,
  });
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) {
      throw new Error("Usage: check-standalone-api-runtime.mjs <verified-install-bundle>");
    }
    console.log(JSON.stringify(await observeStandaloneApiRuntime(process.argv[2])));
  } catch (error) {
    console.error(`Dedicated API runtime topology could not be verified: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
