#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, lstat } from "node:fs/promises";
import { promisify } from "node:util";

import { checkStandaloneTopology } from "./check-standalone-topology.mjs";

const run = promisify(execFile);
const ROUTES = { node: "30944/tcp", indexer: "38088/tcp", "proof-server": "36300/tcp" };

function hostPort(binding) {
  if (!Array.isArray(binding) || binding.length !== 1
    || binding[0]?.HostIp !== "127.0.0.1"
    || !/^[1-9][0-9]*$/u.test(binding[0]?.HostPort ?? "")
    || Number(binding[0].HostPort) < 1024 || Number(binding[0].HostPort) > 65535) {
    throw new Error("Installation relay port is not effectively loopback-bound");
  }
  return binding[0].HostPort;
}

/** Installation-only access. This must never be reported as offline egress denial. */
export function checkStandaloneInstallRelay(network, ledgerContainers, relay, config, verified,
  expectedTopology, baseImage) {
  const pin = verified?.installRelay;
  const node = verified?.images?.find((image) => image.role === "node");
  if (!pin || !node || !node.acceptedIds?.includes(baseImage?.Id)
    || JSON.stringify(relay?.Config?.Env ?? []) !== JSON.stringify(baseImage?.Config?.Env ?? [])
    || relay?.Config?.User !== baseImage?.Config?.User
    || relay?.Name !== `/${config.project}-install-relay`
    || relay.State?.Running !== true || relay.State?.Paused === true
    || relay.Config?.Image !== node.reference || !node.acceptedIds?.includes(relay.Image)
    || JSON.stringify(relay.Config?.Entrypoint) !== JSON.stringify(["/usr/bin/python3"])
    || JSON.stringify(relay.Config?.Cmd) !== JSON.stringify(["/relay.py"])
    || JSON.stringify(relay.Config?.Healthcheck ?? null)
      !== JSON.stringify(baseImage?.Config?.Healthcheck ?? null)
    || (relay.Config?.Env ?? []).some((entry) =>
      /^(?:PYTHON[A-Z_]*|LD_PRELOAD|LD_LIBRARY_PATH)=/u.test(entry))
    || relay.Config?.Labels?.["com.docker.compose.project"] !== undefined) {
    throw new Error("Installation relay identity or entrypoint differs from the verified bundle");
  }
  const host = relay.HostConfig;
  if (host?.Privileged === true || (host?.CapAdd?.length ?? 0) > 0
    || [host?.PidMode, host?.IpcMode, host?.UsernsMode].includes("host")
    || (host?.Devices?.length ?? 0) > 0 || (host?.DeviceRequests?.length ?? 0) > 0
    || (host?.SecurityOpt ?? []).some((option) => /unconfined|disable/u.test(option))) {
    throw new Error("Installation relay has elevated privileges");
  }
  if (relay.Mounts?.length !== 1 || relay.Mounts[0].Type !== "bind"
    || relay.Mounts[0].Destination !== "/relay.py" || relay.Mounts[0].RW !== false
    || relay.Mounts[0].Source !== pin.path) {
    throw new Error("Installation relay script mount differs from the verified bundle");
  }
  const networks = relay.NetworkSettings?.Networks;
  if (Object.keys(networks ?? {}).sort().join("\0") !== ["bridge", config.network].sort().join("\0")
    || networks[config.network]?.NetworkID !== network.Id) {
    throw new Error("Installation relay network attachments differ from the selected bridge");
  }
  const bindings = host?.PortBindings;
  const effective = relay.NetworkSettings?.Ports;
  if (Object.keys(bindings ?? {}).sort().join("\0") !== Object.values(ROUTES).sort().join("\0")
    || !effective || Object.entries(effective).some(([target, value]) =>
      !Object.values(ROUTES).includes(target) && value !== null
      && (!Array.isArray(value) || value.length !== 0))) {
    throw new Error("Installation relay has an unexpected published port");
  }
  const ports = {};
  for (const [service, target] of Object.entries(ROUTES)) {
    const requested = hostPort(bindings[target]);
    const actual = hostPort(effective[target]);
    if (requested !== actual) throw new Error("Installation relay effective port differs from its request");
    ports[service] = actual;
  }
  if (new Set(Object.values(ports)).size !== Object.keys(ROUTES).length) {
    throw new Error("Installation relay host ports must be distinct");
  }
  const topology = checkStandaloneTopology(network, ledgerContainers, config, {
    ...expectedTopology, allowUnpublishedHostPorts: true, installRelayId: relay.Id,
  });
  if (topology.hostPortAccess !== "unpublished-install-access-required") {
    throw new Error("Installation relay is not paired with an unpublished ledger bridge");
  }
  return { kind: "standalone-install-relay-observation", project: config.project,
    networkId: network.Id, relayId: relay.Id, ports,
    relayScriptSha256: pin.sha256, installationOnly: true,
    offlineEgressDenied: "not-verified", topology };
}

async function docker(args) {
  const { stdout } = await run("docker", args, { timeout: 20_000, maxBuffer: 8 * 1024 * 1024 });
  return stdout;
}

export async function observeStandaloneInstallRelay(config, verified, expectedTopology,
  dependencies = {}) {
  const runDocker = dependencies.docker ?? docker;
  const pin = verified?.installRelay;
  if (!pin) throw new Error("Verified install bundle has no installation relay pin");
  const stat = await lstat(pin.path);
  if (!stat.isFile() || createHash("sha256").update(await readFile(pin.path)).digest("hex")
    !== pin.sha256) {
    throw new Error("Installation relay script changed after bundle verification");
  }
  const ids = (await runDocker(["ps", "-aq", "--filter", `label=com.docker.compose.project=${config.project}`]))
    .trim().split("\n").filter(Boolean);
  if (ids.length !== 3) throw new Error("Dedicated Compose project has an unexpected service count");
  const [network] = JSON.parse(await runDocker(["network", "inspect", config.network]));
  const [relay] = JSON.parse(await runDocker(["inspect", "--type", "container",
    `${config.project}-install-relay`]));
  const containers = JSON.parse(await runDocker(["inspect", ...ids]));
  const nodeImage = verified.images.find((image) => image.role === "node");
  if (!nodeImage) throw new Error("Verified install bundle has no node image pin");
  const [baseImage] = JSON.parse(await runDocker(["image", "inspect", nodeImage.reference]));
  const observation = checkStandaloneInstallRelay(network, containers, relay, config, verified,
    expectedTopology, baseImage);
  const mountedHash = (await runDocker(["exec", relay.Id, "/usr/bin/python3", "-I", "-c",
    "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1], 'rb').read()).hexdigest())",
    "/relay.py"])).trim();
  if (mountedHash !== pin.sha256) {
    throw new Error("Running installation relay script differs from the verified bundle");
  }
  return observation;
}
