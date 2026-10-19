#!/usr/bin/env node

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const run = promisify(execFile);
const DEFAULT_PROJECT = "tr-standalone-local-smoke";
const SERVICES = ["node", "indexer", "proof-server"];
const DIGEST_IMAGE = /^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$/u;
const PORTS = {
  node: { variable: "TR_NODE_PORT", defaultPort: 29944, target: "9944/tcp" },
  indexer: { variable: "TR_INDEXER_PORT", defaultPort: 28088, target: "8088/tcp" },
  "proof-server": { variable: "TR_PROOF_PORT", defaultPort: 26300, target: "6300/tcp" },
};

export function standaloneStackConfig(env = process.env) {
  const project = env.TR_STACK_NAME ?? DEFAULT_PROJECT;
  if (typeof project !== "string" || project.length > 63
    || !/^tr-standalone-local-[a-z0-9][a-z0-9-]*[a-z0-9]$/u.test(project)) {
    throw new Error("Local stack project name must use the tr-standalone-local-* namespace");
  }
  if (env.COMPOSE_PROJECT_NAME !== undefined && env.COMPOSE_PROJECT_NAME !== project) {
    throw new Error("COMPOSE_PROJECT_NAME must match TR_STACK_NAME");
  }
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

function requireMount(container, destination, type, expectedWritable = true, expectedName) {
  const mount = container.Mounts?.find((item) => item.Destination === destination);
  if (!mount || mount.Type !== type || mount.RW !== expectedWritable
    || (expectedName && mount.Name !== expectedName)) {
    throw new Error(`Required ${type} mount drifted: ${destination}`);
  }
}

function requireLoopbackBinding(container, service, port) {
  const bindings = container.HostConfig?.PortBindings;
  const target = PORTS[service].target;
  if (!bindings || Object.keys(bindings).length !== 1
    || !Array.isArray(bindings[target]) || bindings[target].length !== 1
    || bindings[target][0].HostIp !== "127.0.0.1"
    || bindings[target][0].HostPort !== port) {
    throw new Error(`Dedicated ${service} port is not bound only to approved loopback`);
  }
}

/** A read-only topology observation, not a packet-level proof of denied egress. */
export function checkStandaloneTopology(network, containers, config = standaloneStackConfig({})) {
  if (network?.Name !== config.network || network.Internal !== true
    || network.Driver !== "bridge" || network.EnableIPv6 !== false
    || network.Labels?.["com.docker.compose.project"] !== config.project) {
    throw new Error("Dedicated ledger network is not an internal IPv4-only Compose bridge");
  }
  if (!Array.isArray(containers) || containers.length !== SERVICES.length) {
    throw new Error("Dedicated stack must contain exactly three services");
  }
  const attachedIds = Object.keys(network.Containers ?? {}).sort();
  const serviceIds = containers.map((container) => container.Id).sort();
  if (attachedIds.length !== SERVICES.length
    || attachedIds.some((id, index) => id !== serviceIds[index])) {
    throw new Error("Dedicated ledger network has a missing or extra container attachment");
  }
  const observed = [];
  for (const container of containers) {
    const labels = container.Config?.Labels;
    const service = labels?.["com.docker.compose.service"];
    if (labels?.["com.docker.compose.project"] !== config.project
      || !SERVICES.includes(service) || observed.includes(service)
      || container.State?.Running !== true || container.State?.Paused === true
      || (container.State?.Health && container.State.Health.Status !== "healthy")
      || !DIGEST_IMAGE.test(container.Config.Image)) {
      throw new Error("Dedicated service is missing, unhealthy, or not digest-pinned");
    }
    const networks = Object.keys(container.NetworkSettings?.Networks ?? {});
    if (networks.length !== 1 || networks[0] !== config.network
      || container.NetworkSettings.Networks[config.network].NetworkID !== network.Id) {
      throw new Error("Dedicated service has a non-internal network attachment");
    }
    requireLoopbackBinding(container, service, config.ports[service]);
    if (service === "node") requireMount(container, "/node/chain", "volume", true,
      `${config.project}_node-data`);
    if (service === "indexer") requireMount(container, "/data", "volume", true,
      `${config.project}_indexer-data`);
    if (service === "proof-server") {
      requireMount(container, "/.cache/midnight/zk-params", "bind", false);
      if (!container.Config.Env?.includes("MIDNIGHT_PROOF_SERVER_NO_FETCH_PARAMS=true")) {
        throw new Error("Proof server is not in no-fetch mode");
      }
    }
    observed.push(service);
  }
  if (observed.sort().join("\0") !== SERVICES.sort().join("\0")) {
    throw new Error("Dedicated service set is incomplete");
  }
  return {
    kind: "standalone-runtime-topology-observation",
    project: config.project,
    network: config.network,
    services: observed,
    internalNetworkOnly: true,
    proofParameterCacheReadOnly: true,
    egressDenied: "not-verified",
    actorJourneys: "not-run",
  };
}

async function docker(args) {
  const { stdout } = await run("docker", args, { timeout: 20_000, maxBuffer: 8 * 1024 * 1024 });
  return stdout;
}

export async function observeStandaloneTopology(config = standaloneStackConfig()) {
  const ids = (await docker(["ps", "-aq", "--filter", `label=com.docker.compose.project=${config.project}`]))
    .trim().split("\n").filter(Boolean);
  if (ids.length !== SERVICES.length) {
    throw new Error("Dedicated Compose project is absent or has an unexpected service count");
  }
  const [network] = JSON.parse(await docker(["network", "inspect", config.network]));
  const containers = JSON.parse(await docker(["inspect", ...ids]));
  return checkStandaloneTopology(network, containers, config);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    console.log(JSON.stringify(await observeStandaloneTopology()));
  } catch {
    console.error("Dedicated local stack topology could not be verified; inspect Docker before qualification");
    process.exitCode = 1;
  }
}
