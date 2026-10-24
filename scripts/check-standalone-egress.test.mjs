import assert from "node:assert/strict";
import { test } from "node:test";

import { hasBroadOutboundRoute, hasValidRouteTable, observeStandaloneEgress, parseCanaryAddress,
  validateEgressProbe, verifiedOfflineEgressTopology } from "./check-standalone-egress.mjs";

const header = "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT";
const subnet = "eth0\t000015AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0";
const defaultRoute = "eth0\t00000000\t010015AC\t0003\t0\t0\t0\t00000000\t0\t0\t0";
const controlRoute = `${header}\n${subnet}\n${defaultRoute}\n`;
const isolatedRoute = `${header}\n${subnet}\n`;
const observedNetwork = { networkId: "ledger-id" };

test("accepts only a reachable control and denied isolated connection", () => {
  assert.equal(hasBroadOutboundRoute(controlRoute), true);
  assert.equal(hasBroadOutboundRoute(isolatedRoute), false);
  assert.doesNotThrow(() => validateEgressProbe({
    controlRoute, isolatedRoute, controlCode: 0, isolatedCode: 7,
    isolatedDnsCode: 2, isolatedDnsOutput: "",
  }));
});

test("does not mistake DNS, TLS, or timeout failure for denied egress", () => {
  for (const isolatedCode of [0, 6, 28, 35, 60]) {
    assert.throws(() => validateEgressProbe({
      controlRoute, isolatedRoute, controlCode: 0, isolatedCode,
      isolatedDnsCode: 2, isolatedDnsOutput: "",
    }), /connection error/u);
  }
  assert.throws(() => validateEgressProbe({
    controlRoute, isolatedRoute, controlCode: 7, isolatedCode: 7,
    isolatedDnsCode: 2, isolatedDnsOutput: "",
  }), /Positive-control/u);
  assert.throws(() => validateEgressProbe({
    controlRoute, isolatedRoute: controlRoute, controlCode: 0, isolatedCode: 7,
    isolatedDnsCode: 2, isolatedDnsOutput: "",
  }), /broad outbound route/u);
  assert.throws(() => validateEgressProbe({
    controlRoute: isolatedRoute, isolatedRoute, controlCode: 0, isolatedCode: 7,
    isolatedDnsCode: 2, isolatedDnsOutput: "",
  }), /Positive-control/u);
  assert.throws(() => validateEgressProbe({
    controlRoute, isolatedRoute, controlCode: 0, isolatedCode: 7,
    isolatedDnsCode: 0, isolatedDnsOutput: "104.20.23.154 STREAM example.com",
  }), /DNS resolution/u);
});

test("rejects broad /0 through /8 routes regardless of flags", () => {
  assert.equal(hasBroadOutboundRoute(`${header}\neth0\t00000000\t00000000\t0001\t0\t0\t0\t00000000\n`), true);
  assert.equal(hasBroadOutboundRoute(`${header}\neth0\t00000000\t00000000\t0007\t0\t0\t0\t00000080\n`), true);
  assert.equal(hasBroadOutboundRoute(`${header}\neth0\t00000000\t00000000\t0001\t0\t0\t0\t000000C0\n`), true);
  assert.equal(hasBroadOutboundRoute(`${header}\neth0\t00000000\t00000000\t0001\t0\t0\t0\t000000FF\n`), true);
  assert.equal(hasBroadOutboundRoute(`${header}\neth0\t00000000\t00000000\t0001\t0\t0\t0\t000080FF\n`), false);
  assert.equal(hasBroadOutboundRoute(`${header}\r\n${subnet}\r\n`), false);
  assert.equal(hasBroadOutboundRoute(`${header}\n`), false);
  assert.equal(hasValidRouteTable(isolatedRoute), true);
  assert.equal(hasValidRouteTable(`${header}\neth0\t00000000\t00000000\t0001\t0\t0\t0\t00FF00FF\n`), false);
  assert.equal(hasValidRouteTable(`${header}\n`), false);
  assert.equal(hasValidRouteTable(""), false);
  assert.throws(() => validateEgressProbe({
    controlRoute, isolatedRoute: `${header}\neth0\t00000000\t00000000\t0001\t0\t0\t0\t000000C0\n`,
    controlCode: 0, isolatedCode: 7, isolatedDnsCode: 2, isolatedDnsOutput: "",
  }), /broad outbound route/u);
  assert.throws(() => validateEgressProbe({
    controlRoute, isolatedRoute: `${header}\n`, controlCode: 0, isolatedCode: 7,
    isolatedDnsCode: 2, isolatedDnsOutput: "",
  }), /empty or malformed/u);
});

test("requires a valid IPv4 canary address", () => {
  assert.equal(parseCanaryAddress("104.20.23.154 STREAM example.com\n"), "104.20.23.154");
  assert.throws(() => parseCanaryAddress("999.20.23.154 STREAM example.com\n"), /IPv4/u);
  assert.throws(() => parseCanaryAddress("2001:db8::1 STREAM example.com\n"), /IPv4/u);
});

test("orchestrates restricted probes and checks topology before and after", async () => {
  const calls = [];
  let observations = 0;
  const project = "tr-standalone-local-qualification";
  const image = `midnightntwrk/midnight-node@sha256:${"a".repeat(64)}`;
  const dockerCommand = async (args) => {
    calls.push(args);
    if (args[0] === "inspect") return { code: 0, stdout: `${image}\n` };
    const network = args[args.indexOf("--network") + 1];
    const entrypoint = args[args.indexOf("--entrypoint") + 1];
    if (entrypoint === "cat") return { code: 0, stdout: network === "bridge" ? controlRoute : isolatedRoute };
    if (entrypoint === "getent") return network === "bridge"
      ? { code: 0, stdout: "104.20.23.154 STREAM example.com\n" }
      : { code: 2, stdout: "" };
    if (entrypoint === "curl") return { code: network === "bridge" ? 0 : 7, stdout: "" };
    throw new Error("unexpected Docker call");
  };
  const result = await observeStandaloneEgress({
    dockerCommand, env: { TR_STACK_NAME: project, TR_NODE_PORT: "39944",
      TR_INDEXER_PORT: "38088", TR_PROOF_PORT: "36300" },
    observeTopology: async (config) => {
      observations += 1;
      assert.equal(config.project, project);
      return observedNetwork;
    },
  });
  assert.equal(observations, 2);
  assert.equal(result.project, project);
  assert.equal(result.networkId, observedNetwork.networkId);
  assert.equal(result.internalBridgeCanaryDnsResolutionDenied, true);
  assert.equal(calls[0].at(-1), `${project}-node-1`);
  assert.equal(calls.filter((args) => args[0] === "run").length, 6);
  for (const args of calls.filter((entry) => entry[0] === "run")) {
    assert.ok(args.includes("--read-only"));
    assert.match(args[args.indexOf("--name") + 1], /^tr-egress-probe-[0-9a-f-]{36}$/u);
    assert.deepEqual(args.slice(args.indexOf("--user"), args.indexOf("--user") + 2),
      ["--user", "65534:65534"]);
    assert.ok(args.includes("--cap-drop"));
    assert.ok(["bridge", observedNetwork.networkId].includes(args[args.indexOf("--network") + 1]));
  }
});

test("uses the verified image ID for a source-scoped offline bundle probe", async () => {
  const project = "tr-standalone-local-wizard-a1";
  const sourceRevision = "a".repeat(40);
  const image = `tr-standalone/node:sha-${sourceRevision}`;
  const digest = `midnightntwrk/midnight-node@sha256:${"a".repeat(64)}`;
  const imageId = `sha256:${"b".repeat(64)}`;
  const expectedTopology = { allowOffline: true, sourceRevision,
    images: [{ role: "node", reference: digest, acceptedIds: [imageId] }],
    composeFiles: ["/bundle/compose.yml", "/bundle/compose.offline.yml"] };
  let observations = 0;
  const dockerCommand = async (args) => {
    if (args[0] === "inspect") return { code: 0,
      stdout: `${args[2] === "{{.Image}}" ? imageId : image}\n` };
    assert.equal(args[args.indexOf("--entrypoint") + 2], imageId);
    const network = args[args.indexOf("--network") + 1];
    const entrypoint = args[args.indexOf("--entrypoint") + 1];
    if (entrypoint === "cat") return { code: 0, stdout: network === "bridge" ? controlRoute : isolatedRoute };
    if (entrypoint === "getent") return network === "bridge"
      ? { code: 0, stdout: "104.20.23.154 STREAM example.com\n" }
      : { code: 2, stdout: "" };
    return { code: network === "bridge" ? 0 : 7, stdout: "" };
  };
  const result = await observeStandaloneEgress({ dockerCommand, expectedTopology,
    env: { TR_STACK_NAME: project }, observeTopology: async (config, expected) => {
      assert.equal(config.project, project);
      assert.equal(expected, expectedTopology);
      observations += 1;
      return observedNetwork;
    } });
  assert.equal(observations, 2);
  assert.equal(result.image, image);
  assert.equal(result.probeImage, imageId);
  const digestResult = await observeStandaloneEgress({ dockerCommand: async (args) =>
    args[0] === "inspect" && args[2] === "{{.Config.Image}}"
      ? { code: 0, stdout: `${digest}\n` } : dockerCommand(args),
  expectedTopology, env: { TR_STACK_NAME: project },
  observeTopology: async (_config, expected) => {
    assert.equal(expected, expectedTopology);
    return observedNetwork;
  } });
  assert.equal(digestResult.image, digest);
  assert.equal(digestResult.probeImage, imageId);
  await assert.rejects(observeStandaloneEgress({ expectedTopology,
    env: { TR_STACK_NAME: project }, observeTopology: async () => observedNetwork,
    dockerCommand: async (args) => args[0] === "inspect" && args[2] === "{{.Config.Image}}"
      ? { code: 0, stdout: "unapproved:latest\n" } : dockerCommand(args),
  }), /not tied/u);
  await assert.rejects(observeStandaloneEgress({ expectedTopology, env: { TR_STACK_NAME: project },
    observeTopology: async () => observedNetwork, dockerCommand: async (args) => ({ code: 0,
      stdout: `${args[2] === "{{.Image}}" ? `sha256:${"c".repeat(64)}` : image}\n` }),
  }), /image ID differs/u);
});

test("fails if the ledger bridge is replaced during the egress probe", async () => {
  let observations = 0;
  const image = `midnightntwrk/midnight-node@sha256:${"a".repeat(64)}`;
  const dockerCommand = async (args) => {
    if (args[0] === "inspect") return { code: 0, stdout: `${image}\n` };
    const network = args[args.indexOf("--network") + 1];
    const entrypoint = args[args.indexOf("--entrypoint") + 1];
    if (entrypoint === "cat") return { code: 0,
      stdout: network === "bridge" ? controlRoute : isolatedRoute };
    if (entrypoint === "getent") return network === "bridge"
      ? { code: 0, stdout: "104.20.23.154 STREAM example.com\n" }
      : { code: 2, stdout: "" };
    return { code: network === "bridge" ? 0 : 7, stdout: "" };
  };
  await assert.rejects(observeStandaloneEgress({ dockerCommand,
    observeTopology: async () => ({ networkId: `ledger-${++observations}` }),
  }), /identity changed/u);
  assert.equal(observations, 2);
  await assert.rejects(observeStandaloneEgress({ dockerCommand,
    observeTopology: async () => ({}),
  }), /identity was not observed/u);
});

test("standalone offline probe requires a verified v3-v6 bundle", async () => {
  const sourceRevision = "a".repeat(40);
  const images = [{ role: "node", acceptedIds: [`sha256:${"b".repeat(64)}`] },
    { role: "indexer" }, { role: "proof-server" }];
  const expected = await verifiedOfflineEgressTopology(".", async () => ({
    sourceRevision, images, runtimeComposeSha256: "c".repeat(64),
    runtimeOfflineComposeSha256: "d".repeat(64),
  }));
  assert.equal(expected.sourceRevision, sourceRevision);
  assert.equal(expected.allowOffline, true);
  assert.equal(expected.images, images);
  assert.equal(expected.composeFiles.length, 2);
  await assert.rejects(verifiedOfflineEgressTopology(".", async () => ({
    sourceRevision, images, runtimeComposeSha256: null,
  })), /verified v3-v6/u);
});

test("removes only its own probe container after a Docker startup failure", async () => {
  const image = `midnightntwrk/midnight-node@sha256:${"a".repeat(64)}`;
  let probeName;
  let removedName;
  const dockerCommand = async (args) => {
    if (args[0] === "inspect") return { code: 0, stdout: `${image}\n` };
    if (args[0] === "rm") {
      removedName = args[2];
      return { code: 0, stdout: "" };
    }
    probeName = args[args.indexOf("--name") + 1];
    return { code: 125, stdout: "" };
  };
  await assert.rejects(observeStandaloneEgress({ dockerCommand,
    observeTopology: async () => observedNetwork }),
    /could not start/u);
  assert.equal(removedName, probeName);
});

test("fails closed on a floating image or leaking isolated DNS", async () => {
  await assert.rejects(observeStandaloneEgress({
    observeTopology: async () => observedNetwork,
    dockerCommand: async () => ({ code: 0, stdout: "midnight-node:latest\n" }),
  }), /digest-pinned/u);
  const image = `midnightntwrk/midnight-node@sha256:${"a".repeat(64)}`;
  const dockerCommand = async (args) => {
    if (args[0] === "inspect") return { code: 0, stdout: `${image}\n` };
    const network = args[args.indexOf("--network") + 1];
    const entrypoint = args[args.indexOf("--entrypoint") + 1];
    if (entrypoint === "cat") return { code: 0, stdout: network === "bridge" ? controlRoute : isolatedRoute };
    if (entrypoint === "getent") return { code: 0, stdout: "104.20.23.154 STREAM example.com\n" };
    return { code: network === "bridge" ? 0 : 7, stdout: "" };
  };
  await assert.rejects(observeStandaloneEgress({ dockerCommand,
    observeTopology: async () => observedNetwork }),
    /DNS resolution/u);
});
