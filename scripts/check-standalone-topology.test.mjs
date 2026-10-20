import assert from "node:assert/strict";
import { test } from "node:test";

import { checkStandaloneTopology, standaloneStackConfig } from "./check-standalone-topology.mjs";

const project = "tr-standalone-local-smoke";
const ledger = `${project}_ledger`;
const expected = { proofParamsDir: "/private/verified/proof-params",
  indexerPassword: "test-password", indexerSecret: "test-secret" };
const network = {
  Name: ledger, Id: "ledger-id", Internal: true, Driver: "bridge", EnableIPv6: false,
  Labels: { "com.docker.compose.project": project },
  Containers: Object.fromEntries(["node", "indexer", "proof-server"].map((service) => [
    `${service}-id`, { Name: `${project}-${service}-1` },
  ])),
};
const container = (service) => ({
  Id: `${service}-id`,
  Image: `sha256:${"a".repeat(64)}`,
  Config: {
    Image: `midnightntwrk/${service}@sha256:${"a".repeat(64)}`,
    Labels: { "com.docker.compose.project": project, "com.docker.compose.service": service },
    Env: service === "proof-server" ? ["MIDNIGHT_PROOF_SERVER_NO_FETCH_PARAMS=true"]
      : service === "indexer" ? [
        "APP__INFRA__STORAGE__PASSWORD=test-password",
        "APP__INFRA__PUB_SUB__PASSWORD=test-password",
        "APP__INFRA__LEDGER_STATE_STORAGE__PASSWORD=test-password",
        "APP__INFRA__SECRET=test-secret",
      ] : [],
  },
  State: { Running: true, Paused: false, Health: { Status: "healthy" } },
  HostConfig: { PortBindings: { [service === "node" ? "9944/tcp"
    : service === "indexer" ? "8088/tcp" : "6300/tcp"]: [{ HostIp: "127.0.0.1",
    HostPort: service === "node" ? "29944" : service === "indexer" ? "28088" : "26300" }] } },
  NetworkSettings: { Networks: { [ledger]: { NetworkID: "ledger-id" } } },
  Mounts: [service === "proof-server"
    ? { Destination: "/.cache/midnight/zk-params", Type: "bind", RW: false,
      Source: expected.proofParamsDir }
    : { Destination: service === "node" ? "/node/chain" : "/data", Type: "volume", RW: true,
      Name: `${project}_${service === "node" ? "node-data" : "indexer-data"}` }],
});
const containers = ["node", "indexer", "proof-server"].map(container);

test("reports only topology, never offline qualification", () => {
  assert.deepEqual(checkStandaloneTopology(network, containers), {
    kind: "standalone-runtime-topology-observation",
    project, network: ledger, networkId: "ledger-id", services: ["indexer", "node", "proof-server"],
    internalNetworkOnly: true, proofParameterCacheReadOnly: true,
    egressDenied: "not-verified", actorJourneys: "not-run",
  });
});

test("rejects external attachment and network drift", () => {
  assert.throws(() => checkStandaloneTopology({ ...network, Internal: false }, containers), /internal IPv4/u);
  assert.throws(() => checkStandaloneTopology({ ...network, Id: "" }, containers), /internal IPv4/u);
  const wrongNetworkId = structuredClone(containers);
  wrongNetworkId[0].NetworkSettings.Networks[ledger].NetworkID = "other-ledger-id";
  assert.throws(() => checkStandaloneTopology(network, wrongNetworkId), /non-internal/u);
  const attached = structuredClone(containers);
  attached[0].NetworkSettings.Networks.bridge = { NetworkID: "outside" };
  assert.throws(() => checkStandaloneTopology(network, attached), /non-internal/u);
  const relay = structuredClone(network);
  relay.Containers["relay-id"] = { Name: "tr-standalone-install-relay" };
  assert.throws(() => checkStandaloneTopology(relay, containers), /extra container attachment/u);
  const detached = structuredClone(network);
  delete detached.Containers["node-id"];
  assert.throws(() => checkStandaloneTopology(detached, containers), /missing or extra/u);
  const anonymous = structuredClone(containers);
  delete anonymous[0].Id;
  assert.throws(() => checkStandaloneTopology(network, anonymous), /missing or extra/u);
});

test("rejects writable proof cache, fetch mode, and persistence drift", () => {
  const writable = structuredClone(containers);
  writable[2].Mounts[0].RW = true;
  assert.throws(() => checkStandaloneTopology(network, writable), /mount drifted/u);
  const fetching = structuredClone(containers);
  fetching[2].Config.Env = [];
  assert.throws(() => checkStandaloneTopology(network, fetching), /no-fetch/u);
  const ephemeral = structuredClone(containers);
  ephemeral[0].Mounts = [];
  assert.throws(() => checkStandaloneTopology(network, ephemeral), /unexpected mount/u);
});

test("matches prepared private inputs without returning their values", () => {
  const result = checkStandaloneTopology(network, containers, standaloneStackConfig({}), expected);
  assert.equal(result.preparedInputsMatched, true);
  assert.equal(JSON.stringify(result).includes(expected.indexerSecret), false);
  const wrongCache = structuredClone(containers);
  wrongCache[2].Mounts[0].Source = "/other/proof-params";
  assert.throws(() => checkStandaloneTopology(network, wrongCache, standaloneStackConfig({}), expected),
    /proof cache differs/u);
  const wrongSecret = structuredClone(containers);
  wrongSecret[1].Config.Env[3] = "APP__INFRA__SECRET=other";
  assert.throws(() => checkStandaloneTopology(network, wrongSecret, standaloneStackConfig({}), expected),
    /prepared private stack environment/u);
  const duplicateSecret = structuredClone(containers);
  duplicateSecret[1].Config.Env.push("APP__INFRA__SECRET=test-secret");
  assert.throws(() => checkStandaloneTopology(network, duplicateSecret, standaloneStackConfig({}), expected),
    /prepared private stack environment/u);
});

test("explicit private-input requirement rejects missing wizard values", () => {
  assert.throws(() => checkStandaloneTopology(network, containers, standaloneStackConfig({}),
    { requirePrivateInputs: true }), /Prepared private stack inputs are incomplete/u);
});

test("accepts only verified source-scoped offline image tags and bundle Compose labels", () => {
  const expectedBundle = { sourceRevision: "b".repeat(40), allowOffline: true,
    composeFiles: ["/bundle/compose.yml", "/bundle/compose.offline.yml"],
    images: containers.map((item) => ({ role: item.Config.Labels["com.docker.compose.service"],
      reference: item.Config.Image, acceptedIds: [item.Image] })) };
  const direct = structuredClone(containers);
  for (const item of direct) {
    item.Config.Labels["com.docker.compose.project.config_files"] = "/bundle/compose.yml";
  }
  assert.equal(checkStandaloneTopology(network, direct, standaloneStackConfig({}), expectedBundle)
    .verifiedImageIdsMatched, true);
  const offline = structuredClone(direct);
  for (const item of offline) {
    const role = item.Config.Labels["com.docker.compose.service"];
    item.Config.Image = `tr-standalone/${role}:sha-${expectedBundle.sourceRevision}`;
    item.Config.Labels["com.docker.compose.project.config_files"] =
      expectedBundle.composeFiles.join(",");
  }
  const result = checkStandaloneTopology(network, offline, standaloneStackConfig({}), expectedBundle);
  assert.equal(result.verifiedImageIdsMatched, true);
  assert.equal(result.bundleComposeFilesMatched, true);
  const wrongId = structuredClone(offline);
  wrongId[0].Image = `sha256:${"c".repeat(64)}`;
  assert.throws(() => checkStandaloneTopology(network, wrongId, standaloneStackConfig({}), expectedBundle),
    /image differs/u);
  const wrongTag = structuredClone(offline);
  wrongTag[0].Config.Image = "tr-standalone/node:latest";
  assert.throws(() => checkStandaloneTopology(network, wrongTag, standaloneStackConfig({}), expectedBundle),
    /image differs/u);
  const wrongFiles = structuredClone(offline);
  wrongFiles[0].Config.Labels["com.docker.compose.project.config_files"] = "/checkout/compose.yml";
  assert.throws(() => checkStandaloneTopology(network, wrongFiles, standaloneStackConfig({}), expectedBundle),
    /verified bundle Compose files/u);
  const mixed = structuredClone(offline);
  mixed[0].Config.Image = expectedBundle.images[0].reference;
  assert.throws(() => checkStandaloneTopology(network, mixed, standaloneStackConfig({}), expectedBundle),
    /two-file Compose overlay/u);
});

test("rejects unexpected mounts and elevated container privileges", () => {
  const extra = structuredClone(containers);
  extra[0].Mounts.push({ Destination: "/host", Type: "bind", RW: true });
  assert.throws(() => checkStandaloneTopology(network, extra), /unexpected mount/u);
  const privileged = structuredClone(containers);
  privileged[0].HostConfig.Privileged = true;
  assert.throws(() => checkStandaloneTopology(network, privileged), /elevated container privileges/u);
  const capAdd = structuredClone(containers);
  capAdd[2].HostConfig.CapAdd = ["SYS_ADMIN"];
  assert.throws(() => checkStandaloneTopology(network, capAdd), /elevated container privileges/u);
  for (const field of ["PidMode", "IpcMode", "UsernsMode", "CgroupnsMode"]) {
    const hostNamespace = structuredClone(containers);
    hostNamespace[0].HostConfig[field] = "host";
    assert.throws(() => checkStandaloneTopology(network, hostNamespace), /elevated container privileges/u);
  }
  for (const field of ["Devices", "DeviceRequests"]) {
    const device = structuredClone(containers);
    device[1].HostConfig[field] = [{ PathOnHost: "/dev/example" }];
    assert.throws(() => checkStandaloneTopology(network, device), /elevated container privileges/u);
  }
  for (const option of ["seccomp=unconfined", "apparmor=unconfined",
    "seccomp:unconfined", "apparmor:unconfined", "systempaths:unconfined", "label=disable"]) {
    const unconfined = structuredClone(containers);
    unconfined[2].HostConfig.SecurityOpt = [option];
    assert.throws(() => checkStandaloneTopology(network, unconfined), /elevated container privileges/u);
  }
});

test("rejects extra, unhealthy, and unpinned services", () => {
  assert.throws(() => checkStandaloneTopology(network, [...containers, container("node")]), /exactly three/u);
  const unhealthy = structuredClone(containers);
  unhealthy[1].State.Health.Status = "unhealthy";
  assert.throws(() => checkStandaloneTopology(network, unhealthy), /unhealthy/u);
  const floating = structuredClone(containers);
  floating[0].Config.Image = "midnightntwrk/midnight-node:latest";
  assert.throws(() => checkStandaloneTopology(network, floating), /digest-pinned/u);
});

test("validates an alternate isolated project and distinct loopback ports", () => {
  const config = standaloneStackConfig({ TR_STACK_NAME: "tr-standalone-local-qualification",
    TR_NODE_PORT: "39944", TR_INDEXER_PORT: "38088", TR_PROOF_PORT: "36300" });
  const alternateNetwork = structuredClone(network);
  alternateNetwork.Name = config.network;
  alternateNetwork.Labels["com.docker.compose.project"] = config.project;
  const alternateContainers = structuredClone(containers);
  for (const item of alternateContainers) {
    const service = item.Config.Labels["com.docker.compose.service"];
    item.Config.Labels["com.docker.compose.project"] = config.project;
    item.NetworkSettings.Networks = { [config.network]: { NetworkID: network.Id } };
    Object.values(item.HostConfig.PortBindings)[0][0].HostPort = config.ports[service];
    if (service !== "proof-server") {
      item.Mounts[0].Name = `${config.project}_${service === "node" ? "node-data" : "indexer-data"}`;
    }
  }
  assert.equal(checkStandaloneTopology(alternateNetwork, alternateContainers, config).project,
    "tr-standalone-local-qualification");
  assert.throws(() => checkStandaloneTopology(alternateNetwork, alternateContainers), /internal IPv4/u);
  assert.throws(() => standaloneStackConfig({ TR_STACK_NAME: "mn-passport-sdk-localnet" }), /namespace/u);
  assert.throws(() => standaloneStackConfig({ TR_STACK_NAME: "tr-standalone-local-qualification",
    COMPOSE_PROJECT_NAME: project }), /must match/u);
  assert.throws(() => standaloneStackConfig({ TR_STACK_NAME: "tr-standalone-local-qualification",
    TR_NODE_PORT: "38088", TR_INDEXER_PORT: "38088" }), /distinct/u);
  assert.throws(() => standaloneStackConfig({ TR_NODE_PORT: "0" }), /Invalid private loopback/u);
});

test("rejects public or extra port bindings and mismatched private ports", () => {
  const publicBinding = structuredClone(containers);
  publicBinding[0].HostConfig.PortBindings["9944/tcp"][0].HostIp = "0.0.0.0";
  assert.throws(() => checkStandaloneTopology(network, publicBinding), /approved loopback/u);
  const extraBinding = structuredClone(containers);
  extraBinding[1].HostConfig.PortBindings["9999/tcp"] = [{ HostIp: "127.0.0.1", HostPort: "39999" }];
  assert.throws(() => checkStandaloneTopology(network, extraBinding), /approved loopback/u);
  const changedPort = structuredClone(containers);
  changedPort[2].HostConfig.PortBindings["6300/tcp"][0].HostPort = "36300";
  assert.throws(() => checkStandaloneTopology(network, changedPort), /approved loopback/u);
  const sharedVolume = structuredClone(containers);
  sharedVolume[0].Mounts[0].Name = "tr-standalone-local-other_node-data";
  assert.throws(() => checkStandaloneTopology(network, sharedVolume), /mount drifted/u);
});
