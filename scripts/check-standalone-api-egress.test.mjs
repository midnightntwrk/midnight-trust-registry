import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { test } from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

import { apiEgressCanaryServerScript, apiEgressDnsScript,
  observeStandaloneApiEgress, validateApiEgressProbe } from "./check-standalone-api-egress.mjs";
import { ledgerSubnet } from "./check-standalone-egress.mjs";

const run = promisify(execFile);

const revision = "a".repeat(40);
const imageId = `sha256:${"b".repeat(64)}`;
const networkId = "ledger-network-id";
const network = { Id: networkId, Internal: true, EnableIPv6: false,
  IPAM: { Config: [{ Subnet: "10.0.0.0/24" }] } };
const routeTable = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n"
  + "eth0\t0000000A\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
const control = { code: 0, stdout: "connected\n", stderr: "" };
const isolated = { code: 7, stdout: "denied:ENETUNREACH\n", stderr: "" };
const dnsControl = { code: 0, stdout: "resolved:198.51.100.7\n", stderr: "" };
const dnsIsolated = { code: 7, stdout: "denied:ETIMEOUT\n", stderr: "" };
const before = {
  project: "tr-api-test", sourceRevision: revision, internalNetworkOnly: true,
  apiContainerId: "api-container-id", apiStartedAt: "2026-10-24T10:00:00Z",
  apiRestartCount: 0, networkId,
};

test("requires a live bridge control, confined routes, and a route-denied API connection", () => {
  const input = { subnet: ledgerSubnet(network, networkId), routeTable,
    canaryAddress: "172.17.0.2", controlBefore: control, isolated, controlAfter: control,
    dnsControlBefore: dnsControl, dnsIsolated, dnsControlAfter: dnsControl };
  assert.doesNotThrow(() => validateApiEgressProbe(input));
  assert.throws(() => validateApiEgressProbe({ ...input, canaryAddress: "10.0.0.2" }), /inside/u);
  assert.throws(() => validateApiEgressProbe({ ...input, controlAfter: { ...control, code: 1 } }),
    /positive control/u);
  assert.throws(() => validateApiEgressProbe({ ...input, isolated: { code: 0, stdout: "connected" } }),
    /route denial/u);
  assert.throws(() => validateApiEgressProbe({ ...input,
    isolated: { code: 7, stdout: "denied:ECONNREFUSED" } }), /route denial/u);
  assert.throws(() => validateApiEgressProbe({ ...input,
    routeTable: routeTable.replace("00FFFFFF", "00000000") }), /route escapes/u);
  assert.throws(() => validateApiEgressProbe({ ...input,
    dnsControlAfter: { code: 7, stdout: "denied:ETIMEOUT" } }), /DNS positive control/u);
  assert.throws(() => validateApiEgressProbe({ ...input,
    dnsIsolated: { code: 0, stdout: "resolved:198.51.100.7" } }), /bridge DNS canary/u);
  assert.throws(() => validateApiEgressProbe({ ...input,
    dnsIsolated: { code: 7, stdout: "denied:ECONNREFUSED" } }), /bridge DNS canary/u);
});

test("the disposable DNS canary answers a synthetic name without public DNS", async () => {
  const server = spawn(process.execPath, ["-e", apiEgressCanaryServerScript],
    { stdio: "ignore" });
  try {
    let result;
    for (let attempt = 0; attempt < 5; attempt += 1) {
      if (server.exitCode !== null) throw new Error("Local canary exited before DNS resolution");
      try {
        result = await run(process.execPath,
          ["-e", apiEgressDnsScript, "127.0.0.1", "45987"], { timeout: 5_000 });
        break;
      } catch {
        await delay(100);
      }
    }
    assert.equal(result?.stdout.trim(), "resolved:198.51.100.7");
  } finally {
    server.kill();
  }
});

function fixture(overrides = {}) {
  const calls = [];
  const command = async (args) => {
    calls.push(args);
    if (args[0] === "network") return { code: 0, stdout: JSON.stringify([network]) };
    if (args[0] === "inspect") return { code: 0, stdout: JSON.stringify([
      { NetworkSettings: { Networks: { bridge: { IPAddress: "172.17.0.2" } } } },
    ]) };
    if (args[0] === "run" && args.includes("-d")) return { code: 0, stdout: "canary-id\n" };
    if (args[0] === "run") return args.some((arg) => arg.includes("node:dns"))
      ? dnsControl : control;
    if (args[0] === "exec" && args.at(-1).includes("/proc/net/route")) {
      return { code: 0, stdout: routeTable };
    }
    if (args[0] === "exec") return args.some((arg) => arg.includes("node:dns"))
      ? dnsIsolated : isolated;
    if (args[0] === "rm") return { code: 0, stdout: "canary-id\n" };
    throw new Error(`Unexpected Docker call: ${args.join(" ")}`);
  };
  let observations = 0;
  const observe = async () => {
    observations += 1;
    return observations === 1 ? before : { ...before, ...overrides };
  };
  const verify = async () => ({ sourceRevision: revision,
    runtimeApiComposeSha256: "c".repeat(64), apiRuntime: { imageId } });
  return { calls, command, observe, verify };
}

test("observes the packaged API's actual route and egress without a release claim", async () => {
  const { calls, command, observe, verify } = fixture();
  const result = await observeStandaloneApiEgress("/bundle", {}, {
    dockerCommand: command, observeApiRuntime: observe, verifyBundle: verify,
  });
  assert.equal(result.sourceRevision, revision);
  assert.equal(result.apiCanaryConnectionDenied, true);
  assert.equal(result.apiBridgeDnsRouteDenied, true);
  assert.equal(result.bridgeDnsCanaryReachable, true);
  assert.equal(result.apiRoutesConfinedToLedgerSubnet, true);
  assert.equal(result.releaseQualified, false);
  assert.equal(calls.filter((args) => args[0] === "run" && !args.includes("-d")).length, 4);
  assert.equal(calls.filter((args) => args[0] === "exec").length, 3);
  assert.equal(calls.at(-1)[0], "rm");
  assert.ok(calls.every((args) => !args.includes("--publish")));
});

test("rejects restart drift and always removes its own canary", async () => {
  const { calls, command, observe, verify } = fixture({ apiRestartCount: 1 });
  await assert.rejects(observeStandaloneApiEgress("/bundle", {}, {
    dockerCommand: command, observeApiRuntime: observe, verifyBundle: verify,
  }), /changed/u);
  assert.equal(calls.at(-1)[0], "rm");
});

test("fails closed when its temporary canary cannot be removed", async () => {
  const { calls, command, observe, verify } = fixture();
  await assert.rejects(observeStandaloneApiEgress("/bundle", {}, {
    dockerCommand: async (args, allowFailure) => args[0] === "rm"
      ? { code: 1, stdout: "", stderr: "cleanup failed" }
      : command(args, allowFailure),
    observeApiRuntime: observe, verifyBundle: verify,
  }), /Could not remove/u);
  assert.equal(calls.filter((args) => args[0] === "run" && args.includes("-d")).length, 1);
});

test("rejects an install without a pinned API before creating a canary", async () => {
  const { calls, command, observe } = fixture();
  await assert.rejects(observeStandaloneApiEgress("/bundle", {}, {
    dockerCommand: command, observeApiRuntime: observe,
    verifyBundle: async () => ({ sourceRevision: revision }),
  }), /API-bearing/u);
  assert.equal(calls.length, 0);
});
