#!/usr/bin/env node

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";

import { observeStandaloneTopology } from "./check-standalone-topology.mjs";

const run = promisify(execFile);
const PROJECT = "tr-standalone-local-smoke";
const NETWORK = `${PROJECT}_ledger`;
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

function runInNetwork(image, network, entrypoint, args) {
  return docker([
    "run", "--rm", "--pull", "never", "--network", network,
    "--entrypoint", entrypoint, image, ...args,
  ], true);
}

export function hasDefaultRoute(routeTable) {
  return routeTable.split("\n").slice(1).some((line) => {
    const columns = line.trim().split(/\s+/u);
    return columns.length >= 4 && columns[1] === "00000000" && columns[3] === "0003";
  });
}

export function validateEgressProbe({ controlRoute, isolatedRoute, controlCode, isolatedCode }) {
  if (!hasDefaultRoute(controlRoute)) {
    throw new Error("Positive-control container has no default route");
  }
  if (hasDefaultRoute(isolatedRoute)) {
    throw new Error("Isolated ledger network unexpectedly has a default route");
  }
  if (controlCode !== 0) {
    throw new Error("Positive-control HTTPS request did not succeed");
  }
  if (isolatedCode !== 7) {
    throw new Error("Isolated HTTPS request did not fail with a connection error");
  }
}

export async function observeStandaloneEgress() {
  await observeStandaloneTopology();
  const image = (await docker([
    "inspect", "--format", "{{.Config.Image}}", `${PROJECT}-node-1`,
  ])).stdout.trim();
  if (!DIGEST_IMAGE.test(image)) throw new Error("Probe image is not digest-pinned");

  const addresses = await runInNetwork(image, "bridge", "getent", ["ahostsv4", CANARY]);
  if (addresses.code !== 0) throw new Error("Canary DNS resolution failed on control bridge");
  const address = addresses.stdout.match(/^((?:\d{1,3}\.){3}\d{1,3})\s/mu)?.[1];
  if (!address || address.split(".").some((part) => Number(part) > 255)) {
    throw new Error("Canary did not resolve to an IPv4 address");
  }

  const curlArgs = [
    "--noproxy", "*", "--resolve", `${CANARY}:443:${address}`,
    "--connect-timeout", "5", "--max-time", "10", "-fsSI", `https://${CANARY}`,
  ];
  const controlRoute = await runInNetwork(image, "bridge", "cat", ["/proc/net/route"]);
  const isolatedRoute = await runInNetwork(image, NETWORK, "cat", ["/proc/net/route"]);
  if (controlRoute.code !== 0 || isolatedRoute.code !== 0) {
    throw new Error("Could not inspect probe route tables");
  }
  const control = await runInNetwork(image, "bridge", "curl", curlArgs);
  const isolated = await runInNetwork(image, NETWORK, "curl", curlArgs);
  validateEgressProbe({
    controlRoute: controlRoute.stdout,
    isolatedRoute: isolatedRoute.stdout,
    controlCode: control.code,
    isolatedCode: isolated.code,
  });
  await observeStandaloneTopology();
  return {
    kind: "standalone-ledger-egress-probe",
    observedAt: new Date().toISOString(),
    project: PROJECT,
    image,
    canary: CANARY,
    canaryAddress: address,
    controlHttpsReachable: true,
    internalBridgeHttpsConnectionDenied: true,
    internalBridgeHasDefaultRoute: false,
    scope: "ledger bridge only; wallet, API, browser, backups, and actor journeys not verified",
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    console.log(JSON.stringify(await observeStandaloneEgress()));
  } catch (error) {
    console.error(`Standalone egress probe inconclusive: ${error.message}`);
    process.exitCode = 1;
  }
}
