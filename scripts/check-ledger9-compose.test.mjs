import assert from "node:assert/strict";
import { test } from "node:test";

import { checkRenderedLedger9Compose, LEDGER9_IMAGES,
  syntheticLedger9Environment } from "./check-ledger9-compose.mjs";

const project = "tr-standalone-ledger9-rendercheck";
const config = () => ({
  name: project,
  networks: { ledger: { internal: true } },
  volumes: {
    "ledger9-node-data": { name: `${project}_ledger9-node-data` },
    "ledger9-indexer-data": { name: `${project}_ledger9-indexer-data` },
  },
  services: {
    node: { image: LEDGER9_IMAGES.node, platform: "linux/arm64", networks: { ledger: null },
      ports: [{ host_ip: "127.0.0.1", target: 9944, published: "39944" }],
      volumes: [{ type: "volume", source: "ledger9-node-data", target: "/node/chain" }] },
    indexer: { image: LEDGER9_IMAGES.indexer, platform: "linux/arm64", networks: { ledger: null },
      ports: [{ host_ip: "127.0.0.1", target: 8088, published: "38088" }],
      volumes: [{ type: "volume", source: "ledger9-indexer-data", target: "/data" }],
      environment: { APP__INFRA__NODE__URL: "ws://node:9944",
        APP__INFRA__SPO_NODE__URL: "ws://node:9944" } },
    "proof-server": { image: LEDGER9_IMAGES["proof-server"], platform: "linux/arm64",
      networks: { ledger: null },
      ports: [{ host_ip: "127.0.0.1", target: 6300, published: "36300" }] },
  },
});

test("synthetic inputs cannot inherit the Ledger 8 project or ports", () => {
  const env = syntheticLedger9Environment({ COMPOSE_PROJECT_NAME: "tr-standalone-local-smoke",
    TR_LEDGER9_STACK_NAME: "tr-standalone-local-smoke", TR_LEDGER9_NODE_PORT: "29944" });
  assert.equal(env.COMPOSE_PROJECT_NAME, project);
  assert.equal(env.TR_LEDGER9_STACK_NAME, project);
  assert.equal(env.TR_LEDGER9_NODE_PORT, "39944");
});

test("render policy accepts the official isolated profile", () => {
  checkRenderedLedger9Compose(config());
});

test("render policy rejects Ledger 8 image, volume, port and external bridge", () => {
  const base = config();
  base.services.node.image = "midnightntwrk/midnight-node@sha256:" + "a".repeat(64);
  assert.throws(() => checkRenderedLedger9Compose(base));
  const invalidVolume = config();
  invalidVolume.services.node.volumes[0].source = "node-data";
  assert.throws(() => checkRenderedLedger9Compose(invalidVolume));
  const publicPort = config();
  publicPort.services.node.ports[0].host_ip = "0.0.0.0";
  assert.throws(() => checkRenderedLedger9Compose(publicPort));
  const externalNetwork = config();
  externalNetwork.networks.ledger.internal = false;
  assert.throws(() => checkRenderedLedger9Compose(externalNetwork));
});
