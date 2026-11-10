import assert from "node:assert/strict";
import { test } from "node:test";
import { Script } from "node:vm";

import { localEgressCanaryServerScript,
  observeStandaloneLocalEgress } from "./check-standalone-local-egress.mjs";
import { apiEgressCanaryServerScript, apiEgressDnsScript } from "./check-standalone-api-egress.mjs";
import { apiEgressDnsScript as sharedDnsScript } from "./standalone-egress-canary-scripts.mjs";

const header = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT";
const subnetRoute = "eth0\t000015AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0";
const defaultRoute = "eth0\t00000000\t010015AC\t0003\t0\t0\t0\t00000000\t0\t0\t0";
const nodeImage = `sha256:${"a".repeat(64)}`;
const apiImage = `sha256:${"b".repeat(64)}`;
const apiIndex = `sha256:${"d".repeat(64)}`;
const expectedTopology = { allowOffline: true, sourceRevision: "c".repeat(40),
  images: [{ role: "node", acceptedIds: [nodeImage] }],
  installRelay: { imageRole: "api" },
  apiRuntime: { imageId: apiIndex, configId: apiImage } };

test("generated canary script is valid Node source with escaped HTTP framing", () => {
  assert.equal(localEgressCanaryServerScript, apiEgressCanaryServerScript);
  assert.equal(apiEgressDnsScript, sharedDnsScript);
  assert.doesNotThrow(() => new Script(localEgressCanaryServerScript));
  assert.match(localEgressCanaryServerScript, /\\r\\nContent-Length: 0\\r\\n/u);
  assert.ok(!localEgressCanaryServerScript.includes("No Content\r\n"));
});

function harness({ isolatedCurlCode = 7, isolatedDnsCode = 7, canaryImage,
  canaryAddress = "172.31.0.7",
  loadedApiImage = apiImage,
  changedNetwork = false, canaryStartCode = 0, isolatedDnsDelivered = false } = {}) {
  const calls = [];
  let observations = 0;
  let controlNetwork;
  let dnsQueries = 0;
  const dockerCommand = async (args) => {
    calls.push(args);
    if (args[0] === "network" && args[1] === "inspect") return { code: 0,
      stdout: JSON.stringify([{ Id: "ledger-id", Internal: true, EnableIPv6: false,
        IPAM: { Config: [{ Subnet: "172.21.0.0/16" }] } }]) };
    if (args[0] === "network" && args[1] === "create") {
      controlNetwork = args.at(-1);
      return { code: 0, stdout: "control-id\n" };
    }
    if (args[0] === "network" && args[1] === "rm") return { code: 0, stdout: "" };
    if (args[0] === "rm") return { code: 0, stdout: "" };
    if (args[0] === "logs") return { code: 0,
      stdout: "tr-offline-dns-query\n".repeat(dnsQueries) };
    if (args[0] === "image" && args[1] === "inspect") {
      return { code: 0, stdout: `${loadedApiImage}\n` };
    }
    if (args[0] === "inspect" && args[1] === "--format") {
      return { code: 0, stdout: `${nodeImage}\n` };
    }
    if (args[0] === "inspect") return { code: 0, stdout: JSON.stringify([{
      Image: canaryImage ?? loadedApiImage, NetworkSettings: { Networks: {
        [controlNetwork]: { IPAddress: canaryAddress },
      } },
    }]) };
    if (args[0] !== "run") throw new Error(`Unexpected Docker call: ${args.join(" ")}`);
    if (args.includes("-d")) return { code: canaryStartCode, stdout: "canary-id\n" };
    const network = args[args.indexOf("--network") + 1];
    const entrypoint = args[args.indexOf("--entrypoint") + 1];
    if (entrypoint === "cat") return { code: 0, stdout: `${header}\n${subnetRoute}\n${network === controlNetwork ? `${defaultRoute}\n` : ""}` };
    if (entrypoint === "node") {
      if (network === controlNetwork || isolatedDnsDelivered || isolatedDnsCode === 0) {
        dnsQueries += 1;
      }
      return network === controlNetwork
        ? { code: 0, stdout: "resolved:198.51.100.7\n" }
        : { code: isolatedDnsCode,
          stdout: isolatedDnsCode === 0 ? "resolved:198.51.100.7\n" : "denied:ETIMEOUT\n" };
    }
    if (entrypoint === "curl") return { code: network === controlNetwork ? 0 : isolatedCurlCode,
      stdout: "" };
    throw new Error(`Unexpected entrypoint: ${entrypoint}`);
  };
  return { calls, dockerCommand, observeTopology: async () => ({
    networkId: changedNetwork && ++observations > 1 ? "changed" : "ledger-id",
  }) };
}

test("offline ledger probe uses a disposable local canary and cleans up", async () => {
  const setup = harness();
  const result = await observeStandaloneLocalEgress({ ...setup, expectedTopology,
    env: { TR_STACK_NAME: "tr-standalone-local-probe" } });
  assert.equal(result.kind, "standalone-ledger-local-egress-probe");
  assert.equal(result.releaseQualified, false);
  assert.equal(result.internalBridgeCanaryDnsResolutionDenied, true);
  assert.equal(result.canaryAddress, "172.31.0.7");
  const runs = setup.calls.filter((args) => args[0] === "run");
  assert.ok(runs.every((args) => args.includes("--pull") && args.includes("never")));
  assert.ok(runs.every((args) => args.includes("--read-only") && args.includes("--cap-drop")));
  assert.ok(runs.some((args) => args.includes("node") && args.some((arg) => arg.includes("node:dns"))));
  assert.ok(runs.some((args) => args.includes(apiImage)));
  assert.ok(runs.every((args) => !args.includes(apiIndex)));
  assert.ok(runs.every((args) => !args.join(" ").includes("example.com")));
  assert.ok(setup.calls.some((args) => args[0] === "rm" && args[1] === "-f"));
  assert.ok(setup.calls.some((args) => args[0] === "network" && args[1] === "rm"));
});

test("offline ledger probe rejects leakage and changed identities", async () => {
  for (const options of [{ isolatedCurlCode: 0 }, { isolatedDnsCode: 0 },
    { isolatedDnsCode: 2 }, { isolatedDnsDelivered: true },
    { canaryImage: nodeImage }, { canaryAddress: null },
    { canaryAddress: "not-an-ip" }, { changedNetwork: true }]) {
    const setup = harness(options);
    await assert.rejects(observeStandaloneLocalEgress({ ...setup, expectedTopology,
      env: { TR_STACK_NAME: "tr-standalone-local-probe" } }));
    assert.ok(setup.calls.some((args) => args[0] === "network" && args[1] === "rm"));
  }
  await assert.rejects(observeStandaloneLocalEgress({ ...harness(),
    expectedTopology: { ...expectedTopology, apiRuntime: null } }), /verified v6/u);
  await assert.rejects(observeStandaloneLocalEgress({ ...harness(),
    expectedTopology: { ...expectedTopology, installRelay: null } }), /verified v6/u);
  const unapproved = harness({ loadedApiImage: nodeImage });
  await assert.rejects(observeStandaloneLocalEgress({ ...unapproved, expectedTopology }),
    /Loaded API image differs/u);
  assert.ok(!unapproved.calls.some((args) => args[0] === "network" && args[1] === "create"));
});

test("offline ledger probe accepts the verified OCI index ID loaded by Docker", async () => {
  const setup = harness({ loadedApiImage: apiIndex });
  const result = await observeStandaloneLocalEgress({ ...setup, expectedTopology,
    env: { TR_STACK_NAME: "tr-standalone-local-probe" } });
  assert.equal(result.canaryImage, apiIndex);
  const canaryRun = setup.calls.find((args) => args[0] === "run" && args.includes("-d"));
  assert.ok(canaryRun.includes(apiIndex));
});

test("offline ledger probe cleans its network after canary startup failure", async () => {
  const setup = harness({ canaryStartCode: 125 });
  await assert.rejects(observeStandaloneLocalEgress({ ...setup, expectedTopology }),
    /Local canary start/u);
  assert.ok(setup.calls.some((args) => args[0] === "network" && args[1] === "rm"));
  assert.ok(setup.calls.some((args) => args[0] === "rm" && args[1] === "-f"));
});

test("offline ledger probe accepts an explicit private control subnet", async () => {
  const setup = harness();
  await observeStandaloneLocalEgress({ ...setup, expectedTopology,
    env: { TR_STACK_NAME: "tr-standalone-local-probe",
      TR_EGRESS_CONTROL_SUBNET: "10.253.247.0/24" } });
  const created = setup.calls.find((args) => args[0] === "network" && args[1] === "create");
  assert.deepEqual(created.slice(2, 6), ["--driver", "bridge", "--subnet", "10.253.247.0/24"]);
  await assert.rejects(observeStandaloneLocalEgress({ ...harness(), expectedTopology,
    env: { TR_STACK_NAME: "tr-standalone-local-probe",
      TR_EGRESS_CONTROL_SUBNET: "8.8.8.0/24" } }), /private canonical/u);
});
