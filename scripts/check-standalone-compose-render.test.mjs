import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

import { checkRenderedStandaloneCompose, ledger9Images, syntheticRenderEnvironment } from "./check-standalone-compose-render.mjs";

const composePath = fileURLToPath(new URL("../deploy/standalone/compose.yml", import.meta.url));
const internalLedgerNodeUrl = yaml.load(readFileSync(composePath, "utf8"))
  .services.indexer.environment.APP__INFRA__NODE__URL;

const base = () => ({
  name: "tr-standalone-local-rendercheck",
  networks: {
    ledger: { internal: true, name: "tr-standalone-local-rendercheck_ledger" },
    "host-access": { name: "tr-standalone-local-rendercheck_host-access" },
  },
  services: Object.fromEntries(["indexer", "node", "proof-server"].map((name) => {
    const [target, published] = { indexer: [8088, "28088"], node: [9944, "29944"],
      "proof-server": [6300, "26300"] }[name];
    return [name, { networks: { ledger: null, "host-access": null }, ports: [{ host_ip: "127.0.0.1",
      target, published, protocol: "tcp" }], pull_policy: "never",
    image: `tr-standalone/${name}:synthetic-render-only`,
    environment: name === "indexer" ? { APP__INFRA__NODE__URL: internalLedgerNodeUrl,
      APP__INFRA__SPO_NODE__URL: internalLedgerNodeUrl } : {} }];
  })),
});

test("render policy accepts an isolated ledger and localhost infrastructure bridge", () => {
  checkRenderedStandaloneCompose(base(), true);
});

test("base stack uses the pinned Ledger 9 image cohort", () => {
  const config = base();
  for (const [service, image] of Object.entries(ledger9Images)) {
    config.services[service].image = image;
  }
  checkRenderedStandaloneCompose(config, false);
  config.services.node.image = "midnightntwrk/midnight-node@sha256:" + "a".repeat(64);
  assert.throws(() => checkRenderedStandaloneCompose(config, false));
});

test("synthetic render inputs ignore inherited project and ports", () => {
  const env = syntheticRenderEnvironment({ COMPOSE_PROJECT_NAME: "other-project",
    TR_STACK_NAME: "other-project", TR_NODE_PORT: "39944",
    TR_INDEXER_PORT: "38088", TR_PROOF_PORT: "36300" });
  assert.equal(env.COMPOSE_PROJECT_NAME, "tr-standalone-local-rendercheck");
  assert.equal(env.TR_STACK_NAME, "tr-standalone-local-rendercheck");
  assert.equal(env.TR_NODE_PORT, "29944");
  assert.equal(env.TR_INDEXER_PORT, "28088");
  assert.equal(env.TR_PROOF_PORT, "26300");
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
  const missingAccess = base();
  delete missingAccess.services.node.networks["host-access"];
  assert.throws(() => checkRenderedStandaloneCompose(missingAccess, true));
  const sharedAccess = base();
  sharedAccess.networks["host-access"].external = true;
  assert.throws(() => checkRenderedStandaloneCompose(sharedAccess, true));
});

test("render policy rejects an offline pull or external indexer endpoint", () => {
  const pull = base();
  pull.services.node.pull_policy = "always";
  assert.throws(() => checkRenderedStandaloneCompose(pull, true));
  const endpoint = base();
  endpoint.services.indexer.environment.APP__INFRA__NODE__URL = "ws://outside:9944";
  assert.throws(() => checkRenderedStandaloneCompose(endpoint, true));
});
