import assert from "node:assert/strict";
import { test } from "node:test";

import { checkStandaloneTopology } from "./check-standalone-topology.mjs";

const project = "tr-standalone-local-smoke";
const ledger = `${project}_ledger`;
const network = {
  Name: ledger, Id: "ledger-id", Internal: true, Driver: "bridge", EnableIPv6: false,
  Labels: { "com.docker.compose.project": project },
  Containers: Object.fromEntries(["node", "indexer", "proof-server"].map((service) => [
    `${service}-id`, { Name: `${project}-${service}-1` },
  ])),
};
const container = (service) => ({
  Id: `${service}-id`,
  Config: {
    Image: `midnightntwrk/${service}@sha256:${"a".repeat(64)}`,
    Labels: { "com.docker.compose.project": project, "com.docker.compose.service": service },
    Env: service === "proof-server" ? ["MIDNIGHT_PROOF_SERVER_NO_FETCH_PARAMS=true"] : [],
  },
  State: { Running: true, Paused: false, Health: { Status: "healthy" } },
  NetworkSettings: { Networks: { [ledger]: { NetworkID: "ledger-id" } } },
  Mounts: [service === "proof-server"
    ? { Destination: "/.cache/midnight/zk-params", Type: "bind", RW: false }
    : { Destination: service === "node" ? "/node/chain" : "/data", Type: "volume", RW: true }],
});
const containers = ["node", "indexer", "proof-server"].map(container);

test("reports only topology, never offline qualification", () => {
  assert.deepEqual(checkStandaloneTopology(network, containers), {
    kind: "standalone-runtime-topology-observation",
    project, network: ledger, services: ["indexer", "node", "proof-server"],
    internalNetworkOnly: true, proofParameterCacheReadOnly: true,
    egressDenied: "not-verified", actorJourneys: "not-run",
  });
});

test("rejects external attachment and network drift", () => {
  assert.throws(() => checkStandaloneTopology({ ...network, Internal: false }, containers), /internal IPv4/u);
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
  assert.throws(() => checkStandaloneTopology(network, ephemeral), /mount drifted/u);
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
