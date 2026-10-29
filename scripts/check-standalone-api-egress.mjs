#!/usr/bin/env node

import { execFile } from "node:child_process";
import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

import { observeStandaloneApiRuntime } from "./check-standalone-api-runtime.mjs";
import { ledgerSubnet } from "./check-standalone-egress.mjs";
import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { validateApiEgressProbe } from "./standalone-api-egress-policy.mjs";

export { validateApiEgressProbe } from "./standalone-api-egress-policy.mjs";

const run = promisify(execFile);
const canaryPort = 45987;
const dnsCanaryName = "tr-offline-canary.invalid";
const dnsCanaryAddress = "198.51.100.7";
export const apiEgressCanaryServerScript = String.raw`const net=require('node:net'),dgram=require('node:dgram');
net.createServer(socket=>socket.end('HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')).listen(${canaryPort},'0.0.0.0');
const server=dgram.createSocket('udp4');
server.on('message',(query,remote)=>{
  if(query.length<18)return;
  let offset=12;const labels=[];
  while(offset<query.length&&query[offset]!==0){
    const length=query[offset++];if(length>63||offset+length>query.length)return;
    labels.push(query.subarray(offset,offset+length).toString('ascii'));offset+=length;
  }
  if(offset+5>query.length||labels.join('.')!=='${dnsCanaryName}'
    ||query.readUInt16BE(offset+1)!==1||query.readUInt16BE(offset+3)!==1)return;
  console.log('tr-offline-dns-query');
  const question=query.subarray(12,offset+5);
  const answer=Buffer.from([0xc0,0x0c,0,1,0,1,0,0,0,0,0,4,198,51,100,7]);
  const reply=Buffer.alloc(12+question.length+answer.length);
  query.copy(reply,0,0,2);reply.writeUInt16BE(0x8180,2);
  reply.writeUInt16BE(1,4);reply.writeUInt16BE(1,6);
  question.copy(reply,12);answer.copy(reply,12+question.length);
  server.send(reply,remote.port,remote.address);
});server.bind(${canaryPort},'0.0.0.0');`;
const connectionScript = `const net=require('node:net');const socket=net.connect(Number(process.argv[2]),process.argv[1]);socket.setTimeout(3000);socket.on('connect',()=>{console.log('connected');socket.end()});socket.on('timeout',()=>socket.destroy(Object.assign(new Error('timeout'),{code:'ETIMEDOUT'})));socket.on('error',error=>{console.log('denied:'+error.code);process.exitCode=7})`;
export const apiEgressDnsScript = `const resolver=new (require('node:dns')).Resolver({timeout:1500,tries:1});resolver.setServers([process.argv[1]+':'+process.argv[2]]);resolver.resolve4('${dnsCanaryName}',(error,addresses)=>{if(error){console.log('denied:'+error.code);process.exitCode=7}else{console.log('resolved:'+addresses[0])}})`;
const routeScript = "process.stdout.write(require('node:fs').readFileSync('/proc/net/route','utf8'))";

async function docker(args, allowFailure = false) {
  try {
    const { stdout, stderr } = await run("docker", args, { timeout: 20_000, maxBuffer: 1024 * 1024 });
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

function requireSuccess(result, description) {
  if (result.code !== 0) throw new Error(`${description} failed`);
  return result.stdout.trim();
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
  let observation;
  let failure;
  try {
    requireSuccess(await command(["run", "-d", "--rm", "--name", name, "--pull", "never",
      "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
      "--network", "bridge", "--entrypoint", "node", image, "-e", apiEgressCanaryServerScript]),
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
