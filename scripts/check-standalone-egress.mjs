#!/usr/bin/env node

import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { realpath } from "node:fs/promises";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";

import { observeStandaloneTopology, standaloneStackConfig } from "./check-standalone-topology.mjs";
import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";

const run = promisify(execFile);
const CANARY = "example.com";
const DIGEST_IMAGE = /^[a-z0-9][a-z0-9./_-]*@sha256:[0-9a-f]{64}$/u;

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

async function runInNetwork(command, image, network, entrypoint, args) {
  const name = `tr-egress-probe-${randomUUID()}`;
  try {
    const result = await command([
      "run", "--rm", "--name", name, "--pull", "never", "--read-only", "--cap-drop", "ALL",
      "--security-opt", "no-new-privileges", "--user", "65534:65534", "--network", network,
      "--entrypoint", entrypoint, image, ...args,
    ], true);
    if (result.code >= 125) throw new Error("Docker could not start the egress probe container");
    return result;
  } catch (error) {
    await command(["rm", "-f", name], true).catch(() => {});
    throw error;
  }
}

function routePrefixLength(hexMask) {
  if (!/^[0-9a-fA-F]{8}$/u.test(hexMask)) return null;
  const mask = routeAddress(hexMask);
  const hostMask = (~mask) >>> 0;
  if ((hostMask & ((hostMask + 1) >>> 0)) !== 0) return null;
  return Math.clz32(hostMask);
}

function routeAddress(hex) {
  const bytes = hex.match(/../gu).map((byte) => Number.parseInt(byte, 16));
  return ((bytes[3] << 24) | (bytes[2] << 16) | (bytes[1] << 8) | bytes[0]) >>> 0;
}

function ipv4Address(value) {
  const parts = value.split(".");
  if (parts.length !== 4 || parts.some((part) => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part)
    || Number(part) > 255)) return null;
  return parts.reduce((address, part) => ((address << 8) | Number(part)) >>> 0, 0);
}

export function ledgerSubnet(network, expectedId) {
  if (network?.Id !== expectedId || network?.Internal !== true
    || network?.EnableIPv6 !== false || network?.IPAM?.Config?.length !== 1) {
    throw new Error("Observed ledger network IPAM differs from the isolated topology");
  }
  const subnet = network.IPAM.Config[0]?.Subnet;
  const match = typeof subnet === "string" ? /^(\d+(?:\.\d+){3})\/(\d{1,2})$/u.exec(subnet) : null;
  const address = match ? ipv4Address(match[1]) : null;
  const prefix = match ? Number(match[2]) : null;
  if (address === null || prefix === null || !Number.isInteger(prefix) || prefix < 1 || prefix > 32) {
    throw new Error("Ledger bridge has no valid IPv4 subnet");
  }
  const mask = (0xffffffff << (32 - prefix)) >>> 0;
  if (((address & mask) >>> 0) !== address) throw new Error("Ledger bridge subnet is not canonical");
  return { address, mask, prefix, text: subnet };
}

export function assertOnlyLedgerRoutes(routeTable, subnet) {
  if (!hasValidRouteTable(routeTable)) throw new Error("Ledger route table is malformed");
  const lines = routeTable.trim().split("\n").slice(1);
  for (const line of lines) {
    const columns = line.trim().split(/\s+/u);
    const prefix = routePrefixLength(columns[7]);
    const destination = routeAddress(columns[1]);
    if (prefix === null || prefix < subnet.prefix
      || ((destination & subnet.mask) >>> 0) !== subnet.address) {
      throw new Error("Ledger bridge route escapes the observed subnet");
    }
  }
}

export function hasBroadOutboundRoute(routeTable) {
  return routeTable.split("\n").slice(1).some((line) => {
    const columns = line.trim().split(/\s+/u);
    if (columns.length < 8) return false;
    const prefix = routePrefixLength(columns[7]);
    return prefix !== null && prefix <= 8;
  });
}

export function hasValidRouteTable(routeTable) {
  const lines = routeTable.trim().split("\n");
  if (!/^Iface\s+Destination\s+Gateway\s+Flags\s+/u.test(lines[0] ?? "")
    || lines.length < 2) return false;
  return lines.slice(1).every((line) => {
    const columns = line.trim().split(/\s+/u);
    return columns.length >= 8
      && /^[0-9a-fA-F]{8}$/u.test(columns[1])
      && routePrefixLength(columns[7]) !== null;
  });
}

export function parseCanaryAddress(output) {
  const address = output.match(/^((?:\d{1,3}\.){3}\d{1,3})\s/mu)?.[1];
  if (!address || address.split(".").some((part) => Number(part) > 255)) {
    throw new Error("Canary did not resolve to an IPv4 address");
  }
  return address;
}

export function validateEgressProbe({ controlRoute, isolatedRoute, controlCode, isolatedCode,
  isolatedDnsCode, isolatedDnsOutput }) {
  if (!hasValidRouteTable(controlRoute) || !hasValidRouteTable(isolatedRoute)) {
    throw new Error("Probe route table is empty or malformed");
  }
  if (!hasBroadOutboundRoute(controlRoute)) {
    throw new Error("Positive-control container has no broad outbound route");
  }
  if (hasBroadOutboundRoute(isolatedRoute)) {
    throw new Error("Isolated ledger network unexpectedly has a broad outbound route");
  }
  if (controlCode !== 0) {
    throw new Error("Positive-control HTTPS request did not succeed");
  }
  if (isolatedCode !== 7) {
    throw new Error("Isolated HTTPS request did not fail with a connection error");
  }
  if (isolatedDnsCode !== 2 || isolatedDnsOutput.trim() !== "") {
    throw new Error("Isolated canary DNS resolution was not denied");
  }
}

export async function verifiedOfflineEgressTopology(bundleDirectory,
  verifyBundle = verifyStandaloneInstallBundle) {
  const root = await realpath(resolve(bundleDirectory));
  const verified = await verifyBundle(root);
  if (!verified.runtimeComposeSha256 || !verified.runtimeOfflineComposeSha256
    || !Array.isArray(verified.images) || verified.images.length !== 3) {
    throw new Error("Offline egress probe requires a verified v3-v6 install bundle");
  }
  return { sourceRevision: verified.sourceRevision, images: verified.images,
    apiRuntime: verified.apiRuntime,
    allowOffline: true, allowUnpublishedHostPorts: true,
    composeFiles: [join(root, "compose.yml"),
      join(root, "compose.offline.yml")] };
}

export async function observeStandaloneEgress(dependencies = {}) {
  const command = dependencies.dockerCommand ?? docker;
  const topology = dependencies.observeTopology ?? observeStandaloneTopology;
  const config = standaloneStackConfig(dependencies.env ?? process.env);
  const expectedTopology = dependencies.expectedTopology;
  const before = await topology(config, expectedTopology);
  if (typeof before?.networkId !== "string" || before.networkId.length === 0) {
    throw new Error("Ledger network identity was not observed before the egress probe");
  }
  const inspectedNetwork = JSON.parse((await command(["network", "inspect", before.networkId])).stdout);
  const subnet = ledgerSubnet(inspectedNetwork?.[0], before.networkId);
  const image = (await command([
    "inspect", "--format", "{{.Config.Image}}", `${config.project}-node-1`,
  ])).stdout.trim();
  let probeImage = image;
  if (expectedTopology?.images) {
    const node = expectedTopology.images?.find((entry) => entry.role === "node");
    const approvedTag = `tr-standalone/node:sha-${expectedTopology.sourceRevision}`;
    const verifiedDigest = image === node?.reference;
    const verifiedOfflineTag = expectedTopology.allowOffline === true && image === approvedTag
      && Array.isArray(expectedTopology.composeFiles)
      && expectedTopology.composeFiles.length === 2;
    if (!node || !Array.isArray(node.acceptedIds)
      || (!verifiedDigest && !verifiedOfflineTag)) {
      throw new Error("Probe image is not tied to the verified bundle");
    }
    const imageId = (await command([
      "inspect", "--format", "{{.Image}}", `${config.project}-node-1`,
    ])).stdout.trim();
    if (!node.acceptedIds.includes(imageId)) {
      throw new Error("Offline probe image ID differs from the verified bundle");
    }
    probeImage = imageId;
  } else if (!DIGEST_IMAGE.test(image)) {
    throw new Error("Probe image is not digest-pinned");
  }

  const addresses = await runInNetwork(command, probeImage, "bridge", "getent", ["ahostsv4", CANARY]);
  if (addresses.code !== 0) throw new Error("Canary DNS resolution failed on control bridge");
  const address = parseCanaryAddress(addresses.stdout);

  const curlArgs = [
    "--noproxy", "*", "--resolve", `${CANARY}:443:${address}`,
    "--connect-timeout", "5", "--max-time", "10", "-fsSI", `https://${CANARY}`,
  ];
  const controlRoute = await runInNetwork(command, probeImage, "bridge", "cat", ["/proc/net/route"]);
  const isolatedRoute = await runInNetwork(command, probeImage, before.networkId, "cat", ["/proc/net/route"]);
  if (controlRoute.code !== 0 || isolatedRoute.code !== 0) {
    throw new Error("Could not inspect probe route tables");
  }
  const control = await runInNetwork(command, probeImage, "bridge", "curl", curlArgs);
  const isolated = await runInNetwork(command, probeImage, before.networkId, "curl", curlArgs);
  const isolatedDns = await runInNetwork(command, probeImage, before.networkId, "getent", ["ahostsv4", CANARY]);
  validateEgressProbe({
    controlRoute: controlRoute.stdout,
    isolatedRoute: isolatedRoute.stdout,
    controlCode: control.code,
    isolatedCode: isolated.code,
    isolatedDnsCode: isolatedDns.code,
    isolatedDnsOutput: isolatedDns.stdout,
  });
  assertOnlyLedgerRoutes(isolatedRoute.stdout, subnet);
  const after = await topology(config, expectedTopology);
  if (after?.networkId !== before.networkId) {
    throw new Error("Ledger network identity changed during the egress probe");
  }
  return {
    kind: "standalone-ledger-egress-probe",
    observedAt: new Date().toISOString(),
    project: config.project,
    networkId: before.networkId,
    ledgerSubnet: subnet.text,
    image,
    probeImage,
    canary: CANARY,
    canaryAddress: address,
    controlHttpsReachable: true,
    internalBridgeHttpsConnectionDenied: true,
    internalBridgeCanaryDnsResolutionDenied: true,
    internalBridgeBroadOutboundRouteAbsent: true,
    scope: "canary HTTPS and DNS plus routes confined to the observed ledger subnet; wallet, API, browser, backups, and actor journeys not verified",
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length > 3) {
      throw new Error("Usage: check-standalone-egress.mjs [verified-install-bundle]");
    }
    const expectedTopology = process.argv[2]
      ? await verifiedOfflineEgressTopology(process.argv[2]) : undefined;
    console.log(JSON.stringify(await observeStandaloneEgress({ expectedTopology })));
  } catch (error) {
    console.error(`Standalone egress probe inconclusive: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
