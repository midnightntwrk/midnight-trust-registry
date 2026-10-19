#!/usr/bin/env node

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

const run = promisify(execFile);
const PROJECT = "tr-standalone-local-smoke";
const NETWORK = `${PROJECT}_ledger`;
const SERVICES = ["node", "indexer", "proof-server"];
const DIGEST_IMAGE = /^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$/u;

function requireMount(container, destination, type, expectedWritable = true) {
  const mount = container.Mounts?.find((item) => item.Destination === destination);
  if (!mount || mount.Type !== type || mount.RW !== expectedWritable) {
    throw new Error(`Required ${type} mount drifted: ${destination}`);
  }
}

/** A read-only topology observation, not a packet-level proof of denied egress. */
export function checkStandaloneTopology(network, containers) {
  if (network?.Name !== NETWORK || network.Internal !== true
    || network.Driver !== "bridge" || network.EnableIPv6 !== false
    || network.Labels?.["com.docker.compose.project"] !== PROJECT) {
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
    if (labels?.["com.docker.compose.project"] !== PROJECT
      || !SERVICES.includes(service) || observed.includes(service)
      || container.State?.Running !== true || container.State?.Paused === true
      || (container.State?.Health && container.State.Health.Status !== "healthy")
      || !DIGEST_IMAGE.test(container.Config.Image)) {
      throw new Error("Dedicated service is missing, unhealthy, or not digest-pinned");
    }
    const networks = Object.keys(container.NetworkSettings?.Networks ?? {});
    if (networks.length !== 1 || networks[0] !== NETWORK
      || container.NetworkSettings.Networks[NETWORK].NetworkID !== network.Id) {
      throw new Error("Dedicated service has a non-internal network attachment");
    }
    if (service === "node") requireMount(container, "/node/chain", "volume");
    if (service === "indexer") requireMount(container, "/data", "volume");
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
    project: PROJECT,
    network: NETWORK,
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

export async function observeStandaloneTopology() {
  const ids = (await docker(["ps", "-aq", "--filter", `label=com.docker.compose.project=${PROJECT}`]))
    .trim().split("\n").filter(Boolean);
  if (ids.length !== SERVICES.length) {
    throw new Error("Dedicated Compose project is absent or has an unexpected service count");
  }
  const [network] = JSON.parse(await docker(["network", "inspect", NETWORK]));
  const containers = JSON.parse(await docker(["inspect", ...ids]));
  return checkStandaloneTopology(network, containers);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    console.log(JSON.stringify(await observeStandaloneTopology()));
  } catch {
    console.error("Dedicated local stack topology could not be verified; inspect Docker before qualification");
    process.exitCode = 1;
  }
}
