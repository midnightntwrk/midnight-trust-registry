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
    if (allowFailure && Number.isInteger(error.code)) {
      return { code: error.code, stdout: error.stdout ?? "", stderr: error.stderr ?? "" };
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

export function hasBroadOutboundRoute(routeTable) {
  return routeTable.split("\n").slice(1).some((line) => {
    const columns = line.trim().split(/\s+/u);
    if (columns.length < 8 || !/^[0-9a-fA-F]{8}$/u.test(columns[7])) return false;
    const mask = Number.parseInt(columns[7], 16);
    return (mask === 0 || (mask & (mask - 1)) === 0) && mask !== 0xffffffff;
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
      && /^[0-9a-fA-F]{8}$/u.test(columns[7]);
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
    throw new Error("Offline egress probe requires a verified v3/v4 install bundle");
  }
  return { sourceRevision: verified.sourceRevision, images: verified.images,
    allowOffline: true, composeFiles: [join(root, "compose.yml"),
      join(root, "compose.offline.yml")] };
}

export async function observeStandaloneEgress(dependencies = {}) {
  const command = dependencies.dockerCommand ?? docker;
  const topology = dependencies.observeTopology ?? observeStandaloneTopology;
  const config = standaloneStackConfig(dependencies.env ?? process.env);
  const expectedTopology = dependencies.expectedTopology;
  await topology(config, expectedTopology);
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
  const isolatedRoute = await runInNetwork(command, probeImage, config.network, "cat", ["/proc/net/route"]);
  if (controlRoute.code !== 0 || isolatedRoute.code !== 0) {
    throw new Error("Could not inspect probe route tables");
  }
  const control = await runInNetwork(command, probeImage, "bridge", "curl", curlArgs);
  const isolated = await runInNetwork(command, probeImage, config.network, "curl", curlArgs);
  const isolatedDns = await runInNetwork(command, probeImage, config.network, "getent", ["ahostsv4", CANARY]);
  validateEgressProbe({
    controlRoute: controlRoute.stdout,
    isolatedRoute: isolatedRoute.stdout,
    controlCode: control.code,
    isolatedCode: isolated.code,
    isolatedDnsCode: isolatedDns.code,
    isolatedDnsOutput: isolatedDns.stdout,
  });
  await topology(config, expectedTopology);
  return {
    kind: "standalone-ledger-egress-probe",
    observedAt: new Date().toISOString(),
    project: config.project,
    image,
    probeImage,
    canary: CANARY,
    canaryAddress: address,
    controlHttpsReachable: true,
    internalBridgeHttpsConnectionDenied: true,
    internalBridgeCanaryDnsResolutionDenied: true,
    internalBridgeBroadOutboundRouteAbsent: true,
    scope: "canary HTTPS and DNS on ledger bridge only; wallet, API, browser, backups, and actor journeys not verified",
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
    console.error(`Standalone egress probe inconclusive: ${error.message}`);
    process.exitCode = 1;
  }
}
