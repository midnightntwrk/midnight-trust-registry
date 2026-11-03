#!/usr/bin/env node

import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { observeStandaloneTopology, standaloneStackConfig } from "./check-standalone-topology.mjs";
import { apiEgressCanaryServerScript, apiEgressDnsScript, canaryPort as port,
  dnsCanaryAddress as dnsAddress, dnsCanaryName as canaryName } from "./standalone-egress-canary-scripts.mjs";
import { assertOnlyLedgerRoutes, hasBroadOutboundRoute, hasValidRouteTable,
  ledgerSubnet, verifiedOfflineEgressTopology } from "./check-standalone-egress.mjs";

const run = promisify(execFile);
const privateControlSubnet = /^10\.(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.(?:0|[1-9]\d?|1\d\d|2[0-4]\d|25[0-5])\.0\/24$/u;
export const localEgressCanaryServerScript = apiEgressCanaryServerScript;
const deniedDns = /^denied:(?:ETIMEOUT|ENETUNREACH|EHOSTUNREACH|ECONNREFUSED)$/u;

/** @typedef {{code: number, stdout: string, stderr: string}} DockerResult */
/** @typedef {(args: string[], allowFailure?: boolean) => Promise<DockerResult>} DockerCommand */
/** @typedef {{dockerCommand?: DockerCommand,
 *   observeTopology?: typeof observeStandaloneTopology, env?: NodeJS.ProcessEnv,
 *   expectedTopology?: Awaited<ReturnType<typeof verifiedOfflineEgressTopology>>}} LocalEgressDependencies */

/** @param {string} output */
function countCanaryQueries(output) {
  return output.split(/\r?\n/u).filter((line) => line === "tr-offline-dns-query").length;
}

/** @param {string[]} args @param {boolean} allowFailure */
async function docker(args, allowFailure = false) {
  try {
    const { stdout, stderr } = await run("docker", args, { timeout: 30_000, maxBuffer: 1024 * 1024 });
    return { code: 0, stdout, stderr };
  } catch (error) {
    if (allowFailure && error && typeof error === "object" && "code" in error
      && typeof error.code === "number" && Number.isInteger(error.code)) {
      return { code: error.code,
        stdout: "stdout" in error && typeof error.stdout === "string" ? error.stdout : "",
        stderr: "stderr" in error && typeof error.stderr === "string" ? error.stderr : "" };
    }
    throw error;
  }
}

/** @param {DockerResult} result @param {string} description */
function requireSuccess(result, description) {
  if (result.code !== 0) throw new Error(`${description} failed`);
  return result.stdout.trim();
}

/** @param {DockerCommand} command @param {string} image @param {string} network
 * @param {string} entrypoint @param {string[]} args */
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

/** @param {LocalEgressDependencies} dependencies */
export async function observeStandaloneLocalEgress(dependencies = {}) {
  const command = dependencies.dockerCommand ?? docker;
  const topology = dependencies.observeTopology ?? observeStandaloneTopology;
  const expected = dependencies.expectedTopology;
  const apiIds = [expected?.apiRuntime?.configId, expected?.apiRuntime?.imageId];
  const node = expected?.images?.find((entry) => entry.role === "node");
  if (!expected?.allowOffline || !expected?.sourceRevision || !expected?.installRelay
    || apiIds.some((id) => !/^sha256:[0-9a-f]{64}$/u.test(id ?? ""))
    || !node?.acceptedIds?.length) {
    throw new Error("Local egress probe requires verified v6 node and API image identities");
  }
  const config = standaloneStackConfig(dependencies.env ?? process.env);
  const controlSubnet = (dependencies.env ?? process.env).TR_EGRESS_CONTROL_SUBNET;
  if (controlSubnet !== undefined && !privateControlSubnet.test(controlSubnet)) {
    throw new Error("TR_EGRESS_CONTROL_SUBNET must be a private canonical 10.x.x.0/24");
  }
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
  const apiTag = `tr-standalone/api:sha-${expected.sourceRevision}`;
  const apiImage = requireSuccess(await command(["image", "inspect", "--format", "{{.Id}}", apiTag]),
    "API image inspection");
  if (!apiIds.includes(apiImage)) {
    throw new Error("Loaded API image differs from the verified bundle");
  }
  const suffix = randomUUID();
  const networkName = `tr-local-egress-${suffix}`;
  const containerName = `tr-local-egress-canary-${suffix}`;
  let networkCreated = false;
  let canaryStarted = false;
  let observation;
  let failure;
  try {
    requireSuccess(await command(["network", "create", "--driver", "bridge",
      ...(controlSubnet ? ["--subnet", controlSubnet] : []), networkName]),
      "Local control network creation");
    networkCreated = true;
    requireSuccess(await command(["run", "-d", "--rm", "--name", containerName,
      "--pull", "never", "--read-only", "--cap-drop", "ALL",
      "--security-opt", "no-new-privileges", "--network", networkName,
      "--entrypoint", "node", apiImage,
      "-e", localEgressCanaryServerScript]), "Local canary start");
    canaryStarted = true;
    const [canary] = JSON.parse(requireSuccess(await command(["inspect", containerName]),
      "Local canary inspection"));
    const address = canary?.NetworkSettings?.Networks?.[networkName]?.IPAddress;
    if (!apiIds.includes(canary?.Image) || typeof address !== "string" || isIP(address) !== 4) {
      throw new Error("Local canary identity or IPv4 address differs from the verified image");
    }
    const octets = address.split(".").map(Number);
    const numericAddress = octets.reduce((value, octet) => ((value << 8) | octet) >>> 0, 0);
    if (((numericAddress & subnet.mask) >>> 0) === subnet.address) {
      throw new Error("Local canary overlaps the isolated ledger subnet");
    }
    /** @param {string} network */
    const routes = async (network) => requireSuccess(await probe(command, nodeImage,
      network, "cat", ["/proc/net/route"]), "Probe route inspection");
    const controlRoute = await routes(networkName);
    const isolatedRoute = await routes(before.networkId);
    /** @param {string} network */
    const dns = async (network) => probe(command, apiImage, network, "node",
      ["-e", apiEgressDnsScript, address, String(port)]);
    let dnsControlBefore;
    for (let attempt = 0; attempt < 10; attempt += 1) {
      dnsControlBefore = await dns(networkName);
      if (dnsControlBefore.code === 0
        && dnsControlBefore.stdout.trim() === `resolved:${dnsAddress}`) break;
      await delay(100);
    }
    if (!dnsControlBefore || dnsControlBefore.code !== 0
      || dnsControlBefore.stdout.trim() !== `resolved:${dnsAddress}`) {
      throw new Error("Local DNS/UDP positive control did not resolve the canary");
    }
    const queryCountBefore = countCanaryQueries(requireSuccess(await command(["logs", containerName]),
      "Canary DNS query log"));
    if (queryCountBefore < 1) throw new Error("Canary did not log the DNS positive control");
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
    await delay(200);
    const queryCountAfterIsolation = countCanaryQueries(requireSuccess(
      await command(["logs", containerName]), "Canary DNS isolation log"));
    const controlAfter = await probe(command, nodeImage, networkName, "curl", curlArgs);
    const dnsControlAfter = await dns(networkName);
    if (controlAfter.code !== 0 || dnsControlAfter.code !== 0
      || dnsControlAfter.stdout.trim() !== `resolved:${dnsAddress}`) {
      throw new Error("Local positive control changed during the probe");
    }
    let queryCountAfter;
    for (let attempt = 0; attempt < 10; attempt += 1) {
      queryCountAfter = countCanaryQueries(requireSuccess(await command(["logs", containerName]),
        "Canary final DNS query log"));
      if (queryCountAfter > queryCountBefore) break;
      await delay(100);
    }
    if (!hasValidRouteTable(controlRoute) || !hasValidRouteTable(isolatedRoute)
      || !hasBroadOutboundRoute(controlRoute) || hasBroadOutboundRoute(isolatedRoute)
      || !control || control.code !== 0 || isolated.code !== 7) {
      throw new Error("Local HTTP canary or route isolation check failed");
    }
    if (isolatedDns.code !== 7 || !deniedDns.test(isolatedDns.stdout.trim())
      || queryCountAfterIsolation !== queryCountBefore
      || queryCountAfter !== queryCountBefore + 1) {
      throw new Error(`Local DNS/UDP canary route was not denied: code=${isolatedDns.code}, result=${isolatedDns.stdout.trim()}, queries=${queryCountBefore}/${queryCountAfterIsolation}/${queryCountAfter}`);
    }
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
      scope: "disposable local HTTP and DNS/UDP canary routes using node/API probe images; no public Internet required; other DNS routes, running services, wallet, browser, backup and actor journeys not verified",
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
    console.error(`Local egress probe inconclusive: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
