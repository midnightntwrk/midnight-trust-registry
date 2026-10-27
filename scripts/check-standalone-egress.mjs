#!/usr/bin/env node

import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { realpath } from "node:fs/promises";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { join, resolve } from "node:path";

import { observeStandaloneTopology, standaloneStackConfig } from "./check-standalone-topology.mjs";
import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { assertOnlyLedgerRoutes, ledgerSubnet, parseCanaryAddress,
  validateEgressProbe } from "./standalone-egress-route-policy.mjs";

export { assertOnlyLedgerRoutes, hasBroadOutboundRoute, hasValidRouteTable,
  ledgerSubnet, parseCanaryAddress, validateEgressProbe } from "./standalone-egress-route-policy.mjs";

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
    installRelay: verified.installRelay,
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
