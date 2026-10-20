import assert from "node:assert/strict";
import { test } from "node:test";

import { checkStandaloneInstallRelay } from "./check-standalone-install-relay.mjs";
import { standaloneStackConfig } from "./check-standalone-topology.mjs";

const config = standaloneStackConfig({ TR_STACK_NAME: "tr-standalone-local-relaytest" });
const digest = `sha256:${"a".repeat(64)}`;
const reference = `midnightntwrk/node@${digest}`;
const services = ["node", "indexer", "proof-server"];
const targets = { node: "9944/tcp", indexer: "8088/tcp", "proof-server": "6300/tcp" };
const ports = { node: "29944", indexer: "28088", "proof-server": "26300" };
const relayTargets = { node: "30944/tcp", indexer: "38088/tcp", "proof-server": "36300/tcp" };
const relayPorts = { node: "60944", indexer: "60888", "proof-server": "60630" };
const bundle = { installRelay: { path: "/private/bundle/install-relay.py", sha256: "b".repeat(64) },
  images: [{ role: "node", reference, acceptedIds: [digest] }] };
const network = { Name: config.network, Id: "ledger-id", Internal: true,
  Driver: "bridge", EnableIPv6: false,
  Labels: { "com.docker.compose.project": config.project },
  Containers: Object.fromEntries([...services.map((name) => [`${name}-id`, {}]), ["relay-id", {}]]) };
const containers = services.map((service) => ({
  Id: `${service}-id`, Image: digest,
  Config: { Image: reference, Labels: { "com.docker.compose.project": config.project,
    "com.docker.compose.service": service },
  Env: service === "proof-server" ? ["MIDNIGHT_PROOF_SERVER_NO_FETCH_PARAMS=true"] : [] },
  State: { Running: true, Health: { Status: "healthy" } },
  HostConfig: { PortBindings: { [targets[service]]: [{ HostIp: "127.0.0.1",
    HostPort: ports[service] }] } },
  NetworkSettings: { Networks: { [config.network]: { NetworkID: "ledger-id" } },
    Ports: { [targets[service]]: [] } },
  Mounts: [service === "proof-server"
    ? { Type: "bind", Destination: "/.cache/midnight/zk-params", RW: false,
      Source: "/private/bundle/proof-params" }
    : { Type: "volume", Destination: service === "node" ? "/node/chain" : "/data",
      RW: true, Name: `${config.project}_${service === "node" ? "node-data" : "indexer-data"}` }],
}));
const bindings = Object.fromEntries(services.map((service) => [relayTargets[service],
  [{ HostIp: "127.0.0.1", HostPort: relayPorts[service] }]]));
const relay = {
  Id: "relay-id", Name: `/${config.project}-install-relay`, Image: digest,
  Config: { Image: reference, Entrypoint: ["/usr/bin/python3"], Cmd: ["/relay.py"], Labels: {} },
  State: { Running: true }, HostConfig: { PortBindings: bindings },
  NetworkSettings: { Networks: { bridge: { NetworkID: "bridge-id" },
    [config.network]: { NetworkID: "ledger-id" } }, Ports: structuredClone(bindings) },
  Mounts: [{ Type: "bind", Source: bundle.installRelay.path,
    Destination: "/relay.py", RW: false }],
};

test("verified relay grants installation-only loopback access to the unpublished bridge", () => {
  const observed = checkStandaloneInstallRelay(network, containers, relay, config, bundle);
  assert.equal(observed.kind, "standalone-install-relay-observation");
  assert.equal(observed.relayId, "relay-id");
  assert.equal(observed.ports.node, "60944");
  assert.equal(observed.offlineEgressDenied, "not-verified");
  assert.equal(observed.topology.hostPortAccess, "unpublished-install-access-required");
});

test("relay identity, mount, network, and effective ports fail closed", () => {
  const changedImage = structuredClone(relay);
  changedImage.Config.Image = "midnightntwrk/node:latest";
  assert.throws(() => checkStandaloneInstallRelay(network, containers, changedImage, config, bundle),
    /identity or entrypoint/u);
  const injectedEnvironment = structuredClone(relay);
  injectedEnvironment.Config.Env = ["PYTHONPATH=/tmp/override"];
  assert.throws(() => checkStandaloneInstallRelay(network, containers, injectedEnvironment,
    config, bundle), /identity or entrypoint/u);
  const writableScript = structuredClone(relay);
  writableScript.Mounts[0].RW = true;
  assert.throws(() => checkStandaloneInstallRelay(network, containers, writableScript, config, bundle),
    /script mount/u);
  const extraNetwork = structuredClone(relay);
  extraNetwork.NetworkSettings.Networks.external = { NetworkID: "outside" };
  assert.throws(() => checkStandaloneInstallRelay(network, containers, extraNetwork, config, bundle),
    /network attachments/u);
  const publicPort = structuredClone(relay);
  publicPort.NetworkSettings.Ports["30944/tcp"][0].HostIp = "0.0.0.0";
  assert.throws(() => checkStandaloneInstallRelay(network, containers, publicPort, config, bundle),
    /loopback-bound/u);
  const missingEffective = structuredClone(relay);
  missingEffective.NetworkSettings.Ports["30944/tcp"] = [];
  assert.throws(() => checkStandaloneInstallRelay(network, containers, missingEffective, config, bundle),
    /loopback-bound/u);
  const extraAttachment = structuredClone(network);
  extraAttachment.Containers.other = {};
  assert.throws(() => checkStandaloneInstallRelay(extraAttachment, containers, relay, config, bundle),
    /missing or extra container attachment/u);
  const publicLedger = structuredClone(containers);
  publicLedger[0].NetworkSettings.Networks.external = { NetworkID: "outside" };
  assert.throws(() => checkStandaloneInstallRelay(network, publicLedger, relay, config, bundle),
    /non-internal network attachment/u);
});
