import assert from "node:assert/strict";
import { test } from "node:test";

import { checkRenderedStandaloneCompose } from "./check-standalone-compose-render.mjs";

const base = () => ({
  name: "tr-standalone-local-rendercheck",
  networks: { ledger: { internal: true, name: "tr-standalone-local-rendercheck_ledger" } },
  services: Object.fromEntries(["indexer", "node", "proof-server"].map((name) => {
    const [target, published] = { indexer: [8088, "28088"], node: [9944, "29944"],
      "proof-server": [6300, "26300"] }[name];
    return [name, { networks: { ledger: null }, ports: [{ host_ip: "127.0.0.1",
      target, published, protocol: "tcp" }], pull_policy: "never",
    image: `tr-standalone/${name}:synthetic-render-only`,
    environment: name === "indexer" ? { APP__INFRA__NODE__URL: "ws://node:9944",
      APP__INFRA__SPO_NODE__URL: "ws://node:9944" } : {} }];
  })),
});

test("render policy accepts the isolated offline topology", () => {
  checkRenderedStandaloneCompose(base(), true);
});

test("render policy rejects an extra peer, public port, or external bridge", () => {
  const peer = base();
  peer.services.api = peer.services.node;
  assert.throws(() => checkRenderedStandaloneCompose(peer, true));
  const publicPort = base();
  publicPort.services.indexer.ports[0].host_ip = "0.0.0.0";
  assert.throws(() => checkRenderedStandaloneCompose(publicPort, true));
  const external = base();
  external.networks.ledger.internal = false;
  assert.throws(() => checkRenderedStandaloneCompose(external, true));
});

test("render policy rejects an offline pull or external indexer endpoint", () => {
  const pull = base();
  pull.services.node.pull_policy = "always";
  assert.throws(() => checkRenderedStandaloneCompose(pull, true));
  const endpoint = base();
  endpoint.services.indexer.environment.APP__INFRA__NODE__URL = "ws://outside:9944";
  assert.throws(() => checkRenderedStandaloneCompose(endpoint, true));
});
