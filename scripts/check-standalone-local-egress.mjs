#!/usr/bin/env node

import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { observeStandaloneTopology, standaloneStackConfig } from "./check-standalone-topology.mjs";
import { assertOnlyLedgerRoutes, ledgerSubnet, parseCanaryAddress,
  validateEgressProbe, verifiedOfflineEgressTopology } from "./check-standalone-egress.mjs";

const run = promisify(execFile);
const port = 45987;
export const localEgressCanaryServerScript = String.raw`require('node:net').createServer(socket=>socket.end(
  'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n'
)).listen(${port},'0.0.0.0')`;

async function docker(args, allowFailure = false) {
  try {
    const { stdout, stderr } = await run("docker", args, { timeout: 30_000, maxBuffer: 1024 * 1024 });
    return { code: 0, stdout, stderr };
  } catch (error) {
    if (allowFailure && Number.isInteger(error.code)) {
      return { code: error.code, stdout: error.stdout ?? "", stderr: error.stderr ?? "" };
    }
    throw error;
  }
}

function requireSuccess(result, description) {
  if (result.code !== 0) throw new Error(`${description} failed`);
  return result.stdout.trim();
}

async function probe(command, image, network, entrypoint, args) {
  const name = `tr-local-egress-probe-${randomUUID()}`;
  try {
    const result = await command(["run", "--rm", "--name", name, "--pull", "never",
      "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
      "--user", "65534:65534", "--network", network,
      "--entrypoint", entrypoint, image, ...args], true);
    if (result.code >= 125) throw new Error("Docker could not start the local egress probe");
    return result;
  } catch (error) {
    await command(["rm", "-f", name], true).catch(() => {});
    throw error;
  }
}

export async function observeStandaloneLocalEgress(dependencies = {}) {
  const command = dependencies.dockerCommand ?? docker;
  const topology = dependencies.observeTopology ?? observeStandaloneTopology;
  const expected = dependencies.expectedTopology;
  const apiImage = expected?.apiRuntime?.imageId;
  const node = expected?.images?.find((entry) => entry.role === "node");
  if (!expected?.allowOffline || !expected?.sourceRevision || !expected?.installRelay
    || !apiImage
    || !/^sha256:[0-9a-f]{64}$/u.test(apiImage)
    || !node?.acceptedIds?.length) {
    throw new Error("Local egress probe requires verified v6 node and API image identities");
  }
  const config = standaloneStackConfig(dependencies.env ?? process.env);
  const before = await topology(config, expected);
  if (!before?.networkId) throw new Error("Ledger network identity was not observed");
  const inspected = JSON.parse(requireSuccess(await command(["network", "inspect", before.networkId]),
    "Ledger network inspection"));
  const subnet = ledgerSubnet(inspected?.[0], before.networkId);
  const nodeContainer = `${config.project}-node-1`;
  const nodeImage = requireSuccess(await command(["inspect", "--format", "{{.Image}}", nodeContainer]),
    "Node image inspection");
  if (!node.acceptedIds.includes(nodeImage)) {
    throw new Error("Running node image differs from the verified bundle");
  }
  const suffix = randomUUID();
  const networkName = `tr-local-egress-${suffix}`;
  const canaryName = `tr-canary-${suffix}.invalid`;
  const containerName = `tr-local-egress-canary-${suffix}`;
  let networkCreated = false;
  let canaryStarted = false;
  let observation;
  let failure;
  try {
    requireSuccess(await command(["network", "create", "--driver", "bridge", networkName]),
      "Local control network creation");
    networkCreated = true;
    requireSuccess(await command(["run", "-d", "--rm", "--name", containerName,
      "--pull", "never", "--read-only", "--cap-drop", "ALL",
      "--security-opt", "no-new-privileges", "--network", networkName,
      "--network-alias", canaryName, "--entrypoint", "node", apiImage,
      "-e", localEgressCanaryServerScript]), "Local canary start");
    canaryStarted = true;
    const [canary] = JSON.parse(requireSuccess(await command(["inspect", containerName]),
      "Local canary inspection"));
    const address = canary?.NetworkSettings?.Networks?.[networkName]?.IPAddress;
    if (canary?.Image !== apiImage || isIP(address) !== 4) {
      throw new Error("Local canary identity or IPv4 address differs from the verified image");
    }
    const octets = address.split(".").map(Number);
    const numericAddress = octets.reduce((value, octet) => ((value << 8) | octet) >>> 0, 0);
    if (((numericAddress & subnet.mask) >>> 0) === subnet.address) {
      throw new Error("Local canary overlaps the isolated ledger subnet");
    }
    const routes = async (network) => requireSuccess(await probe(command, nodeImage,
      network, "cat", ["/proc/net/route"]), "Probe route inspection");
    const controlRoute = await routes(networkName);
    const isolatedRoute = await routes(before.networkId);
    const dns = async (network) => probe(command, nodeImage, network, "getent",
      ["ahostsv4", canaryName]);
    let dnsControlBefore;
    for (let attempt = 0; attempt < 10; attempt += 1) {
      dnsControlBefore = await dns(networkName);
      if (dnsControlBefore.code === 0) break;
      await delay(100);
    }
    if (dnsControlBefore.code !== 0 || parseCanaryAddress(dnsControlBefore.stdout) !== address) {
      throw new Error("Local DNS positive control did not resolve the canary");
    }
    const curlArgs = ["--noproxy", "*", "--resolve", `${canaryName}:${port}:${address}`,
      "--connect-timeout", "5", "--max-time", "10", "-fsSI", `http://${canaryName}:${port}`];
    let control;
    for (let attempt = 0; attempt < 10; attempt += 1) {
      control = await probe(command, nodeImage, networkName, "curl", curlArgs);
      if (control.code === 0) break;
      await delay(100);
    }
    const isolated = await probe(command, nodeImage, before.networkId, "curl", curlArgs);
    const isolatedDns = await dns(before.networkId);
    const controlAfter = await probe(command, nodeImage, networkName, "curl", curlArgs);
    const dnsControlAfter = await dns(networkName);
    if (controlAfter.code !== 0 || dnsControlAfter.code !== 0
      || parseCanaryAddress(dnsControlAfter.stdout) !== address) {
      throw new Error("Local positive control changed during the probe");
    }
    validateEgressProbe({ controlRoute, isolatedRoute, controlCode: control.code,
      isolatedCode: isolated.code, isolatedDnsCode: isolatedDns.code,
      isolatedDnsOutput: isolatedDns.stdout });
    assertOnlyLedgerRoutes(isolatedRoute, subnet);
    const after = await topology(config, expected);
    if (after.networkId !== before.networkId) {
      throw new Error("Ledger network identity changed during the local egress probe");
    }
    observation = { kind: "standalone-ledger-local-egress-probe", observedAt: new Date().toISOString(),
      project: config.project, networkId: before.networkId, ledgerSubnet: subnet.text,
      nodeImage, canaryImage: apiImage, canaryAddress: address,
      controlHttpReachable: true, internalBridgeHttpConnectionDenied: true,
      internalBridgeCanaryDnsResolutionDenied: true, internalBridgeBroadOutboundRouteAbsent: true,
      scope: "disposable local HTTP/Docker DNS canary and node-image route probe; no public Internet required; running node, wallet, API, browser, backup and actor journeys not verified",
      releaseQualified: false };
  } catch (error) {
    failure = error;
  } finally {
    const canaryCleanup = networkCreated
      ? await command(["rm", "-f", containerName], true).catch(() => ({ code: -1 }))
      : { code: 0 };
    const networkCleanup = networkCreated
      ? await command(["network", "rm", networkName], true).catch(() => ({ code: -1 }))
      : { code: 0 };
    if (canaryStarted && canaryCleanup.code !== 0) {
      failure = new Error("Could not remove the local egress canary", { cause: failure });
    }
    if (networkCreated && networkCleanup.code !== 0) {
      failure = new Error("Could not remove the local control network", { cause: failure });
    }
  }
  if (failure) throw failure;
  return observation;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) {
      throw new Error("Usage: check-standalone-local-egress.mjs <verified-v6-install-bundle>");
    }
    const expectedTopology = await verifiedOfflineEgressTopology(process.argv[2]);
    console.log(JSON.stringify(await observeStandaloneLocalEgress({ expectedTopology })));
  } catch (error) {
    console.error(`Local egress probe inconclusive: ${error.message}`);
    process.exitCode = 1;
  }
}
