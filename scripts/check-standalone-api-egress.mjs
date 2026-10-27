#!/usr/bin/env node

import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";

import { observeStandaloneApiRuntime } from "./check-standalone-api-runtime.mjs";
import { ledgerSubnet } from "./check-standalone-egress.mjs";
import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { validateApiEgressProbe } from "./standalone-api-egress-policy.mjs";
import { executeDockerProbe, requireDockerProbeSuccess } from "./standalone-docker-probe-command.mjs";
import { apiEgressCanaryServerScript, apiEgressDnsScript, canaryPort,
  dnsCanaryAddress } from "./standalone-egress-canary-scripts.mjs";

export { validateApiEgressProbe } from "./standalone-api-egress-policy.mjs";
export { apiEgressCanaryServerScript, apiEgressDnsScript } from "./standalone-egress-canary-scripts.mjs";

const connectionScript = `const net=require('node:net');const socket=net.connect(Number(process.argv[2]),process.argv[1]);socket.setTimeout(3000);socket.on('connect',()=>{console.log('connected');socket.end()});socket.on('timeout',()=>socket.destroy(Object.assign(new Error('timeout'),{code:'ETIMEDOUT'})));socket.on('error',error=>{console.log('denied:'+error.code);process.exitCode=7})`;
const routeScript = "process.stdout.write(require('node:fs').readFileSync('/proc/net/route','utf8'))";

export async function observeStandaloneApiEgress(bundle, env = process.env, dependencies = {}) {
  const command = dependencies.dockerCommand ?? executeDockerProbe;
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
  const inspected = JSON.parse(requireDockerProbeSuccess(await command(["network", "inspect", before.networkId]),
    "API network inspection"));
  const subnet = ledgerSubnet(inspected?.[0], before.networkId);
  const name = `tr-api-egress-canary-${randomUUID()}`;
  const image = verified.apiRuntime.imageId;
  let canaryStarted = false;
  let observation;
  let failure;
  try {
    requireDockerProbeSuccess(await command(["run", "-d", "--rm", "--name", name, "--pull", "never",
      "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
      "--network", "bridge", "--entrypoint", "node", image, "-e", apiEgressCanaryServerScript]),
    "Bridge canary start");
    canaryStarted = true;
    const [canary] = JSON.parse(requireDockerProbeSuccess(await command(["inspect", name]), "Bridge canary inspection"));
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
    const routeTable = requireDockerProbeSuccess(await command(["exec", before.apiContainerId,
      "node", "-e", routeScript]), "API route inspection");
    const isolated = await command(["exec", before.apiContainerId, ...connect], true);
    const controlAfter = await command(controlArgs, true);
    const dnsControlArgs = ["run", "--rm", "--pull", "never", "--read-only", "--cap-drop", "ALL",
      "--security-opt", "no-new-privileges", "--network", "bridge", "--entrypoint", "node",
      image, "-e", apiEgressDnsScript, canaryAddress, String(canaryPort)];
    let dnsControlBefore;
    for (let attempt = 0; attempt < 10; attempt += 1) {
      dnsControlBefore = await command(dnsControlArgs, true);
      if (dnsControlBefore.code === 0
        && dnsControlBefore.stdout.trim() === `resolved:${dnsCanaryAddress}`) break;
      await delay(100);
    }
    const dnsIsolated = await command(["exec", before.apiContainerId,
      "node", "-e", apiEgressDnsScript, canaryAddress, String(canaryPort)], true);
    const dnsControlAfter = await command(dnsControlArgs, true);
    validateApiEgressProbe({ subnet, routeTable, canaryAddress,
      controlBefore, isolated, controlAfter, dnsControlBefore, dnsIsolated, dnsControlAfter });
    const after = await observe(bundle, env);
    if (after.apiContainerId !== before.apiContainerId
      || after.apiStartedAt !== before.apiStartedAt
      || after.apiRestartCount !== before.apiRestartCount
      || after.networkId !== before.networkId
      || after.sourceRevision !== before.sourceRevision) {
      throw new Error("API container or network changed during the egress probe");
    }
    observation = {
      kind: "standalone-api-egress-observation",
      observedAt: new Date().toISOString(),
      sourceRevision: verified.sourceRevision,
      project: before.project,
      apiContainerId: before.apiContainerId,
      networkId: before.networkId,
      ledgerSubnet: subnet.text,
      bridgeCanaryAddress: canaryAddress,
      bridgePositiveControlReachable: true,
      bridgeDnsCanaryReachable: true,
      apiCanaryConnectionDenied: true,
      apiBridgeDnsRouteDenied: true,
      apiRoutesConfinedToLedgerSubnet: true,
      scope: "running API TCP and DNS/UDP routes to one local bridge canary; Docker DNS recursion, other protocols, host ingress, and actor journeys not verified",
      releaseQualified: false,
    };
  } catch (error) {
    failure = error;
  } finally {
    const cleanup = await command(["rm", "-f", name], true).catch(() => ({ code: -1 }));
    if (canaryStarted && cleanup.code !== 0) {
      failure = new Error("Could not remove the dedicated API egress canary", { cause: failure });
    }
  }
  if (failure) throw failure;
  return observation;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3) {
      throw new Error("Usage: check-standalone-api-egress.mjs <verified-install-bundle>");
    }
    console.log(JSON.stringify(await observeStandaloneApiEgress(process.argv[2])));
  } catch (error) {
    console.error(`Dedicated API egress probe inconclusive: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
