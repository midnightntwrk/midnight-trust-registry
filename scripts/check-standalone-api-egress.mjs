#!/usr/bin/env node

import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

import { observeStandaloneApiRuntime } from "./check-standalone-api-runtime.mjs";
import { assertOnlyLedgerRoutes, ledgerSubnet } from "./check-standalone-egress.mjs";
import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";

const run = promisify(execFile);
const canaryPort = 45987;
const serverScript = `require('node:net').createServer(socket => socket.end()).listen(${canaryPort}, '0.0.0.0')`;
const connectionScript = `const net=require('node:net');const socket=net.connect(Number(process.argv[2]),process.argv[1]);socket.setTimeout(3000);socket.on('connect',()=>{console.log('connected');socket.end()});socket.on('timeout',()=>socket.destroy(Object.assign(new Error('timeout'),{code:'ETIMEDOUT'})));socket.on('error',error=>{console.log('denied:'+error.code);process.exitCode=7})`;
const routeScript = "process.stdout.write(require('node:fs').readFileSync('/proc/net/route','utf8'))";
const deniedCodes = new Set(["ENETUNREACH", "EHOSTUNREACH", "ETIMEDOUT"]);

async function docker(args, allowFailure = false) {
  try {
    const { stdout, stderr } = await run("docker", args, { timeout: 20_000, maxBuffer: 1024 * 1024 });
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

export function validateApiEgressProbe(input) {
  const { subnet, routeTable, canaryAddress, controlBefore, isolated, controlAfter } = input;
  if (isIP(canaryAddress) !== 4) throw new Error("Canary address is not IPv4");
  const address = canaryAddress.split(".").reduce((value, octet) =>
    ((value << 8) | Number(octet)) >>> 0, 0);
  if (((address & subnet.mask) >>> 0) === subnet.address) {
    throw new Error("Canary is inside the API's isolated subnet");
  }
  assertOnlyLedgerRoutes(routeTable, subnet);
  if (controlBefore.code !== 0 || controlBefore.stdout.trim() !== "connected"
    || controlAfter.code !== 0 || controlAfter.stdout.trim() !== "connected") {
    throw new Error("Bridge canary positive control was not reachable throughout the probe");
  }
  if (isolated.code !== 7 || !deniedCodes.has(isolated.stdout.trim().replace(/^denied:/u, ""))
    || !isolated.stdout.trim().startsWith("denied:")) {
    throw new Error("Running API container did not show an outbound route denial");
  }
}

export async function observeStandaloneApiEgress(bundle, env = process.env, dependencies = {}) {
  const command = dependencies.dockerCommand ?? docker;
  const observe = dependencies.observeApiRuntime ?? observeStandaloneApiRuntime;
  const verify = dependencies.verifyBundle ?? verifyStandaloneInstallBundle;
  const verified = await verify(resolve(bundle));
  if (!verified.apiRuntime?.imageId || !verified.runtimeApiComposeSha256) {
    throw new Error("API egress probe requires a verified API-bearing install bundle");
  }
  const before = await observe(bundle, env);
  if (before.sourceRevision !== verified.sourceRevision || !before.internalNetworkOnly
    || !before.apiContainerId || !before.networkId) {
    throw new Error("API topology does not match the verified install");
  }
  const inspected = JSON.parse(requireSuccess(await command(["network", "inspect", before.networkId]),
    "API network inspection"));
  const subnet = ledgerSubnet(inspected?.[0], before.networkId);
  const name = `tr-api-egress-canary-${randomUUID()}`;
  const image = verified.apiRuntime.imageId;
  let canaryStarted = false;
  try {
    requireSuccess(await command(["run", "-d", "--rm", "--name", name, "--pull", "never",
      "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
      "--network", "bridge", "--entrypoint", "node", image, "-e", serverScript]),
    "Bridge canary start");
    canaryStarted = true;
    const [canary] = JSON.parse(requireSuccess(await command(["inspect", name]), "Bridge canary inspection"));
    const canaryAddress = canary?.NetworkSettings?.Networks?.bridge?.IPAddress;
    if (typeof canaryAddress !== "string" || isIP(canaryAddress) !== 4) {
      throw new Error("Bridge canary address is unavailable");
    }
    const connect = ["node", "-e", connectionScript, canaryAddress, String(canaryPort)];
    const controlArgs = ["run", "--rm", "--pull", "never", "--read-only", "--cap-drop", "ALL",
      "--security-opt", "no-new-privileges", "--network", "bridge", "--entrypoint", "node",
      image, "-e", connectionScript, canaryAddress, String(canaryPort)];
    let controlBefore;
    for (let attempt = 0; attempt < 10; attempt += 1) {
      controlBefore = await command(controlArgs, true);
      if (controlBefore.code === 0 && controlBefore.stdout.trim() === "connected") break;
      await delay(100);
    }
    const routeTable = requireSuccess(await command(["exec", before.apiContainerId,
      "node", "-e", routeScript]), "API route inspection");
    const isolated = await command(["exec", before.apiContainerId, ...connect], true);
    const controlAfter = await command(controlArgs, true);
    validateApiEgressProbe({ subnet, routeTable, canaryAddress,
      controlBefore, isolated, controlAfter });
    const after = await observe(bundle, env);
    if (after.apiContainerId !== before.apiContainerId
      || after.apiStartedAt !== before.apiStartedAt
      || after.apiRestartCount !== before.apiRestartCount
      || after.networkId !== before.networkId
      || after.sourceRevision !== before.sourceRevision) {
      throw new Error("API container or network changed during the egress probe");
    }
    return {
      kind: "standalone-api-egress-observation",
      observedAt: new Date().toISOString(),
      sourceRevision: verified.sourceRevision,
      project: before.project,
      apiContainerId: before.apiContainerId,
      networkId: before.networkId,
      ledgerSubnet: subnet.text,
      bridgeCanaryAddress: canaryAddress,
      bridgePositiveControlReachable: true,
      apiCanaryConnectionDenied: true,
      apiRoutesConfinedToLedgerSubnet: true,
      scope: "running API TCP route to one local bridge canary; other protocols, DNS, host ingress, and actor journeys not verified",
      releaseQualified: false,
    };
  } finally {
    const cleanup = await command(["rm", "-f", name], true);
    if (canaryStarted && cleanup.code !== 0) {
      throw new Error("Could not remove the dedicated API egress canary");
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) {
      throw new Error("Usage: check-standalone-api-egress.mjs <verified-install-bundle>");
    }
    console.log(JSON.stringify(await observeStandaloneApiEgress(process.argv[2])));
  } catch (error) {
    console.error(`Dedicated API egress probe inconclusive: ${error.message}`);
    process.exitCode = 1;
  }
}
