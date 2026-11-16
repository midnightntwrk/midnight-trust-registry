#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const project = "tr-standalone-ledger9-rendercheck";
export const LEDGER9_IMAGES = {
  node: "midnightntwrk/midnight-node@sha256:0c1ad548d523c1109aa1f16daab1bf72dcb78c7e17b8a8c6d97424ad0eba7b8a",
  indexer: "midnightntwrk/indexer-standalone@sha256:119f35db548ba1c390845f215bb1e928e73038bef7c315825aee0461bd54499d",
  "proof-server": "midnightntwrk/proof-server@sha256:5617e26aa76d06c44f4bee667c37eb71ccf02fefe0e5848100fa84001282d515",
};
const ports = { node: [9944, "39944"], indexer: [8088, "38088"],
  "proof-server": [6300, "36300"] };

export function syntheticLedger9Environment(inherited = process.env) {
  return { ...inherited, COMPOSE_PROJECT_NAME: project, TR_LEDGER9_STACK_NAME: project,
    TR_LEDGER9_NODE_PORT: "39944", TR_LEDGER9_INDEXER_PORT: "38088",
    TR_LEDGER9_PROOF_PORT: "36300", TR_NETWORK_ID: "undeployed",
    TR_INDEXER_PASSWORD: "synthetic-render-only", TR_INDEXER_SECRET: "synthetic-render-only",
    TR_LEDGER9_PROOF_PARAMS_DIR: "/tmp" };
}

export function checkRenderedLedger9Compose(config) {
  assert.equal(config.name, project);
  assert.deepEqual(Object.keys(config.services).sort(), Object.keys(LEDGER9_IMAGES).sort());
  assert.deepEqual(Object.keys(config.volumes).sort(),
    ["ledger9-indexer-data", "ledger9-node-data"]);
  assert.deepEqual(Object.keys(config.networks), ["ledger"]);
  assert.equal(config.networks.ledger.internal, true);
  for (const [role, image] of Object.entries(LEDGER9_IMAGES)) {
    const service = config.services[role];
    assert.equal(service.image, image);
    assert.equal(service.platform, "linux/arm64");
    assert.deepEqual(Object.keys(service.networks), ["ledger"]);
    assert.equal(service.ports.length, 1);
    const [target, published] = ports[role];
    assert.equal(service.ports[0].host_ip, "127.0.0.1");
    assert.equal(service.ports[0].target, target);
    assert.equal(String(service.ports[0].published), published);
  }
  for (const [role, source, target] of [
    ["node", "ledger9-node-data", "/node/chain"],
    ["indexer", "ledger9-indexer-data", "/data"],
  ]) {
    assert.deepEqual(config.services[role].volumes.map(({ type, source: actual, target: mount }) =>
      ({ type, source: actual, target: mount })), [{ type: "volume", source, target }]);
    assert.equal(config.volumes[source].name, `${project}_${source}`);
  }
  assert.equal(config.services.indexer.environment.APP__INFRA__NODE__URL, "ws://node:9944");
  assert.equal(config.services.indexer.environment.APP__INFRA__SPO_NODE__URL, "ws://node:9944");
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    if (process.argv.length !== 2) throw new Error("No arguments accepted");
    const { stdout } = await run("docker", ["compose", "-f",
      join(root, "deploy/standalone/compose.ledger9.yml"), "config", "--format", "json"],
    { env: syntheticLedger9Environment(), timeout: 20_000, maxBuffer: 8 * 1024 * 1024 });
    checkRenderedLedger9Compose(JSON.parse(stdout));
    console.log("Ledger 9 Compose renders with isolated volumes and pinned images.");
  } catch (error) {
    console.error("Ledger 9 Compose render is not qualified:", error);
    process.exitCode = 1;
  }
}
