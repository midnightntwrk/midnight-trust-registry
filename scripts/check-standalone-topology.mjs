#!/usr/bin/env node

import { execFile } from "node:child_process";
import { realpath } from "node:fs/promises";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { exactStringSet } from "./standalone-exact-fields-policy.mjs";

const run = promisify(execFile);
const DEFAULT_PROJECT = "tr-standalone-local-smoke";
const SERVICES = ["node", "indexer", "proof-server"];
const DIGEST_IMAGE = /^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$/u;
/** @type {Record<string, {variable: string, defaultPort: number, target: string}>} */
const PORTS = {
  node: { variable: "TR_NODE_PORT", defaultPort: 29944, target: "9944/tcp" },
  indexer: { variable: "TR_INDEXER_PORT", defaultPort: 28088, target: "8088/tcp" },
  "proof-server": { variable: "TR_PROOF_PORT", defaultPort: 26300, target: "6300/tcp" },
};

/**
 * These shapes describe Docker's untrusted inspect JSON. Runtime checks below
 * still decide whether any observed field is acceptable.
 * @typedef {{Name: string, Id: string, Internal: boolean, Driver: string,
 *   EnableIPv6: boolean, Labels?: Record<string, string>,
 *   Containers?: Record<string, unknown>}} DockerNetwork
 * @typedef {{Destination: string, Type: string, RW: boolean,
 *   Name?: string, Source?: string}} DockerMount
 * @typedef {{HostIp: string, HostPort: string}} DockerPort
 * @typedef {{Id: string, Image: string,
 *   Config: {Image: string, Labels: Record<string, string>, Env?: string[]},
 *   State?: {Running?: boolean, Paused?: boolean, Health?: {Status?: string}},
 *   HostConfig?: {PortBindings?: Record<string, DockerPort[]>, Privileged?: boolean,
 *     CapAdd?: string[], PidMode?: string, IpcMode?: string, UsernsMode?: string,
 *     Devices?: unknown[], DeviceRequests?: unknown[], CgroupnsMode?: string,
 *     SecurityOpt?: string[]},
 *   Mounts?: DockerMount[],
 *   NetworkSettings?: {Ports?: Record<string, DockerPort[] | null>,
 *     Networks?: Record<string, {NetworkID: string}>}}} DockerContainer
 * @typedef {{role: string, reference: string, acceptedIds: string[]}} VerifiedImage
 * @typedef {{sourceRevision?: string, images?: VerifiedImage[],
 *   requirePrivateInputs?: boolean, proofParamsDir?: string,
 *   indexerPassword?: string, indexerSecret?: string, installRelayId?: string,
 *   allowUnpublishedHostPorts?: boolean, allowOffline?: boolean,
 *   composeFiles?: string[]}} ExpectedTopology
 * @typedef {{project: string, network: string, ports: Record<string, string>}} StackConfig
 */

/** @param {NodeJS.ProcessEnv} env */
export function standaloneStackConfig(env = process.env) {
  const project = env.TR_STACK_NAME ?? DEFAULT_PROJECT;
  if (typeof project !== "string" || project.length > 63
    || !/^tr-standalone-local-[a-z0-9][a-z0-9-]*[a-z0-9]$/u.test(project)) {
    throw new Error("Local stack project name must use the tr-standalone-local-* namespace");
  }
  if (env.COMPOSE_PROJECT_NAME !== undefined && env.COMPOSE_PROJECT_NAME !== project) {
    throw new Error("COMPOSE_PROJECT_NAME must match TR_STACK_NAME");
  }
  /** @type {Record<string, string>} */
  const ports = {};
  for (const [service, definition] of Object.entries(PORTS)) {
    const value = env[definition.variable] ?? String(definition.defaultPort);
    if (typeof value !== "string" || !/^[1-9][0-9]*$/u.test(value)
      || Number(value) < 1024 || Number(value) > 65535) {
      throw new Error(`Invalid private loopback port for ${service}`);
    }
    ports[service] = value;
  }
  if (new Set(Object.values(ports)).size !== SERVICES.length) {
    throw new Error("Local stack loopback ports must be distinct");
  }
  return { project, network: `${project}_ledger`, ports };
}

/** @param {DockerContainer} container @param {string} destination
 * @param {string} type @param {boolean} expectedWritable @param {string} [expectedName] */
function requireMount(container, destination, type, expectedWritable = true, expectedName) {
  const mount = container.Mounts?.find((item) => item.Destination === destination);
  if (!mount || mount.Type !== type || mount.RW !== expectedWritable
    || (expectedName && mount.Name !== expectedName)) {
    throw new Error(`Required ${type} mount drifted: ${destination}`);
  }
}

/** @param {DockerContainer} container @param {string} name @param {string} value */
function requirePreparedInput(container, name, value) {
  const matches = container.Config?.Env?.filter((entry) => entry.startsWith(`${name}=`)) ?? [];
  if (matches.length !== 1 || matches[0] !== `${name}=${value}`) {
    throw new Error("Running service does not match the prepared private stack environment");
  }
}

/** @param {DockerContainer} container @param {string} service
 * @param {string} port @param {boolean} allowUnpublished */
function requireLoopbackBinding(container, service, port, allowUnpublished = false) {
  const bindings = container.HostConfig?.PortBindings;
  const effective = container.NetworkSettings?.Ports;
  const target = PORTS[service].target;
  if (!bindings || Object.keys(bindings).length !== 1
    || !Array.isArray(bindings[target]) || bindings[target].length !== 1
    || bindings[target][0]?.HostIp !== "127.0.0.1"
    || bindings[target][0]?.HostPort !== port
    || !effective || !Object.hasOwn(effective, target)
    || Object.entries(effective).some(([name, entries]) => name !== target
      && entries !== null && (!Array.isArray(entries) || entries.length !== 0))) {
    throw new Error(`Dedicated ${service} port is not bound only to approved loopback`);
  }
  if (allowUnpublished && (effective[target] === null
    || (Array.isArray(effective[target]) && effective[target].length === 0))) {
    return "unpublished";
  }
  if (!Array.isArray(effective[target]) || effective[target].length !== 1
    || effective[target][0]?.HostIp !== "127.0.0.1"
    || effective[target][0]?.HostPort !== port) {
    throw new Error(`Dedicated ${service} port is not bound only to approved loopback`);
  }
  return "effective-loopback";
}

/** A read-only topology observation, not a packet-level proof of denied egress.
 * @param {DockerNetwork | null} network @param {DockerContainer[]} containers
 * @param {StackConfig} config @param {ExpectedTopology} [expected] */
export function checkStandaloneTopology(network, containers, config = standaloneStackConfig({}), expected) {
  const privateInputs = expected?.requirePrivateInputs === true || (expected
    && [expected.proofParamsDir, expected.indexerPassword,
      expected.indexerSecret].some((value) => value !== undefined));
  if (privateInputs && (typeof expected.proofParamsDir !== "string" || !expected.proofParamsDir.startsWith("/")
    || typeof expected.indexerPassword !== "string" || expected.indexerPassword.length === 0
    || typeof expected.indexerSecret !== "string" || expected.indexerSecret.length === 0)) {
    throw new Error("Prepared private stack inputs are incomplete");
  }
  if (expected?.images && (expected.images.length !== SERVICES.length
    || typeof expected.sourceRevision !== "string"
    || !/^[0-9a-f]{40}$/u.test(expected.sourceRevision))) {
    throw new Error("Verified image identities are incomplete");
  }
  if (network?.Name !== config.network || typeof network.Id !== "string" || network.Id.length === 0
    || network.Internal !== true
    || network.Driver !== "bridge" || network.EnableIPv6 !== false
    || network.Labels?.["com.docker.compose.project"] !== config.project) {
    throw new Error("Dedicated ledger network is not an internal IPv4-only Compose bridge");
  }
  if (!Array.isArray(containers) || containers.length !== SERVICES.length) {
    throw new Error("Dedicated stack must contain exactly three services");
  }
  const attachedIds = Object.keys(network.Containers ?? {}).sort();
  const serviceIds = [...containers.map((container) => container.Id),
    ...(expected?.installRelayId ? [expected.installRelayId] : [])].sort();
  if (expected?.installRelayId && expected?.allowUnpublishedHostPorts !== true) {
    throw new Error("Installation relay requires explicit unpublished-host observation");
  }
  if (attachedIds.length !== serviceIds.length
    || attachedIds.some((id, index) => id !== serviceIds[index])) {
    throw new Error("Dedicated ledger network has a missing or extra container attachment");
  }
  /** @type {string[]} */
  const observed = [];
  const portAccess = new Set();
  let offlineImages = 0;
  for (const container of containers) {
    const labels = container.Config?.Labels;
    const service = labels?.["com.docker.compose.service"];
    if (labels?.["com.docker.compose.project"] !== config.project
      || !SERVICES.includes(service) || observed.includes(service)
      || container.State?.Running !== true || container.State?.Paused === true
      || (container.State?.Health && container.State.Health.Status !== "healthy")) {
      throw new Error("Dedicated service is missing or unhealthy");
    }
    const image = expected?.images?.find((entry) => entry.role === service);
    const offlineTag = `tr-standalone/${service}:sha-${expected?.sourceRevision}`;
    if (expected?.images) {
      if (!image || !DIGEST_IMAGE.test(image.reference)
        || !Array.isArray(image.acceptedIds) || !image.acceptedIds.includes(container.Image)
        || (container.Config.Image !== image.reference
          && !(expected.allowOffline === true && container.Config.Image === offlineTag))) {
        throw new Error("Dedicated service image differs from verified install bytes");
      }
      if (container.Config.Image === offlineTag) offlineImages += 1;
    } else if (!DIGEST_IMAGE.test(container.Config.Image)) {
      throw new Error("Dedicated service is not digest-pinned");
    }
    if (expected?.composeFiles) {
      const files = labels?.["com.docker.compose.project.config_files"]?.split(",").map((part) => part.trim());
      if (!Array.isArray(files) || files[0] !== expected.composeFiles[0]
        || files.length > 2 || (files.length === 2 && files[1] !== expected.composeFiles[1])) {
        throw new Error("Dedicated service was not started from verified bundle Compose files");
      }
    }
    const host = container.HostConfig;
    if (host?.Privileged === true || (host?.CapAdd?.length ?? 0) > 0
      || [host?.PidMode, host?.IpcMode, host?.UsernsMode].includes("host")
      || (host?.Devices?.length ?? 0) > 0 || (host?.DeviceRequests?.length ?? 0) > 0
      || host?.CgroupnsMode === "host"
      || (host?.SecurityOpt ?? []).some((option) =>
        /^(?:(?:seccomp|apparmor|systempaths)[=:]unconfined|label[=:]disable)$/u.test(option))) {
      throw new Error("Dedicated service has elevated container privileges");
    }
    if (container.Mounts?.length !== 1) {
      throw new Error("Dedicated service has an unexpected mount");
    }
    const networks = Object.keys(container.NetworkSettings?.Networks ?? {});
    if (networks.length !== 1 || networks[0] !== config.network
      || container.NetworkSettings?.Networks?.[config.network]?.NetworkID !== network.Id) {
      throw new Error("Dedicated service has a non-internal network attachment");
    }
    portAccess.add(requireLoopbackBinding(container, service, config.ports[service],
      expected?.allowUnpublishedHostPorts === true));
    if (service === "node") requireMount(container, "/node/chain", "volume", true,
      `${config.project}_node-data`);
    if (service === "indexer") {
      requireMount(container, "/data", "volume", true, `${config.project}_indexer-data`);
      if (privateInputs && expected
        && typeof expected.indexerPassword === "string"
        && typeof expected.indexerSecret === "string") {
        for (const name of ["APP__INFRA__STORAGE__PASSWORD", "APP__INFRA__PUB_SUB__PASSWORD",
          "APP__INFRA__LEDGER_STATE_STORAGE__PASSWORD"]) {
          requirePreparedInput(container, name, expected.indexerPassword);
        }
        requirePreparedInput(container, "APP__INFRA__SECRET", expected.indexerSecret);
      }
    }
    if (service === "proof-server") {
      requireMount(container, "/.cache/midnight/zk-params", "bind", false);
      if (privateInputs && expected && container.Mounts[0].Source !== expected.proofParamsDir) {
        throw new Error("Running proof cache differs from the prepared install path");
      }
      if (!container.Config.Env?.includes("MIDNIGHT_PROOF_SERVER_NO_FETCH_PARAMS=true")) {
        throw new Error("Proof server is not in no-fetch mode");
      }
    }
    observed.push(service);
  }
  if (!exactStringSet(observed, SERVICES)) {
    throw new Error("Dedicated service set is incomplete");
  }
  observed.sort();
  if (portAccess.size !== 1) {
    throw new Error("Dedicated service host access mode is inconsistent");
  }
  if (offlineImages > 0 && (offlineImages !== SERVICES.length
    || !expected?.composeFiles || containers.some((container) =>
      container.Config.Labels["com.docker.compose.project.config_files"].split(",").length !== 2))) {
    throw new Error("Offline image tags require the verified two-file Compose overlay");
  }
  return {
    kind: "standalone-runtime-topology-observation",
    project: config.project,
    network: config.network,
    networkId: network.Id,
    services: observed,
    internalNetworkOnly: true,
    ...(portAccess.has("unpublished") ? { hostPortAccess: "unpublished-install-access-required" } : {}),
    proofParameterCacheReadOnly: true,
    ...(privateInputs ? { preparedInputsMatched: true } : {}),
    ...(expected?.images ? { verifiedImageIdsMatched: true } : {}),
    ...(expected?.composeFiles ? { bundleComposeFilesMatched: true } : {}),
    egressDenied: "not-verified",
    actorJourneys: "not-run",
  };
}

/** @param {string[]} args */
async function docker(args) {
  const { stdout } = await run("docker", args, { timeout: 20_000, maxBuffer: 8 * 1024 * 1024 });
  return stdout;
}

/** @param {StackConfig} config @param {ExpectedTopology} [expected] */
export async function observeStandaloneTopology(config = standaloneStackConfig(), expected) {
  const ids = (await docker(["ps", "-aq", "--filter", `label=com.docker.compose.project=${config.project}`]))
    .trim().split("\n").filter(Boolean);
  if (ids.length !== SERVICES.length) {
    throw new Error("Dedicated Compose project is absent or has an unexpected service count");
  }
  /** @type {DockerNetwork[]} */
  const [network] = JSON.parse(await docker(["network", "inspect", config.network]));
  /** @type {DockerContainer[]} */
  const containers = JSON.parse(await docker(["inspect", ...ids]));
  return checkStandaloneTopology(network, containers, config, expected);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const bundle = process.argv[2];
    if (process.argv.length > 3) throw new Error("Usage: check-standalone-topology.mjs [verified-bundle]");
    let expected;
    if (bundle) {
      const root = await realpath(resolve(bundle));
      const verified = await verifyStandaloneInstallBundle(root);
      expected = { sourceRevision: verified.sourceRevision, images: verified.images,
        allowOffline: verified.runtimeComposeSha256 !== null,
        ...(verified.runtimeComposeSha256 ? { composeFiles: [
          join(root, "compose.yml"), join(root, "compose.offline.yml"),
        ] } : {}) };
    }
    console.log(JSON.stringify(await observeStandaloneTopology(standaloneStackConfig(), expected)));
  } catch {
    console.error("Dedicated local stack topology could not be verified; inspect Docker before qualification");
    process.exitCode = 1;
  }
}
