#!/usr/bin/env node

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { promisify } from "node:util";

const run = promisify(execFile);
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const compose = join(root, "deploy/standalone/compose.yml");
const offlineCompose = join(root, "deploy/standalone/compose.offline.yml");
const project = "tr-standalone-local-rendercheck";
const services = ["indexer", "node", "proof-server"];
const ports = { indexer: [8088, "28088"], node: [9944, "29944"],
  "proof-server": [6300, "26300"] };

/** The render check must not inherit an operator's real Compose project or ports.
 * @param {NodeJS.ProcessEnv} inherited */
export function syntheticRenderEnvironment(inherited = process.env) {
  return { ...inherited, COMPOSE_PROJECT_NAME: project, TR_STACK_NAME: project,
    TR_NODE_PORT: "29944", TR_INDEXER_PORT: "28088", TR_PROOF_PORT: "26300",
    TR_NETWORK_ID: "undeployed", TR_INDEXER_PASSWORD: "synthetic-render-only",
    TR_INDEXER_SECRET: "synthetic-render-only", TR_PROOF_PARAMS_DIR: "/tmp",
    TR_NODE_IMAGE: "tr-standalone/node:synthetic-render-only",
    TR_INDEXER_IMAGE: "tr-standalone/indexer:synthetic-render-only",
    TR_PROOF_SERVER_IMAGE: "tr-standalone/proof-server:synthetic-render-only" };
}

/** @param {Record<string, any>} config @param {boolean} offline */
export function checkRenderedStandaloneCompose(config, offline) {
  assert.equal(config.name, project);
  assert.deepEqual(Object.keys(config.services).sort(), services);
  assert.deepEqual(Object.keys(config.networks), ["ledger"]);
  assert.equal(config.networks.ledger.internal, true);
  assert.equal(config.networks.ledger.name, `${project}_ledger`);
  for (const service of services) {
    const actual = config.services[service];
    assert.deepEqual(Object.keys(actual.networks), ["ledger"]);
    assert.equal(actual.ports?.length, 1);
    const [target, published] = ports[service];
    assert.equal(actual.ports[0].host_ip, "127.0.0.1");
    assert.equal(actual.ports[0].target, target);
    assert.equal(String(actual.ports[0].published), published);
    assert.equal(actual.ports[0].protocol, "tcp");
    if (offline) {
      assert.equal(actual.pull_policy, "never");
      assert.equal(actual.image, `tr-standalone/${service}:synthetic-render-only`);
    }
  }
  assert.equal(config.services.indexer.environment.APP__INFRA__NODE__URL, "ws://node:9944");
  assert.equal(config.services.indexer.environment.APP__INFRA__SPO_NODE__URL, "ws://node:9944");
}

/** @param {boolean} offline */
async function render(offline) {
  const env = syntheticRenderEnvironment();
  const args = ["compose", "-f", compose];
  if (offline) args.push("-f", offlineCompose);
  args.push("config", "--format", "json");
  const { stdout } = await run("docker", args, { env, timeout: 20_000,
    maxBuffer: 8 * 1024 * 1024 });
  checkRenderedStandaloneCompose(JSON.parse(stdout), offline);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  try {
    if (process.argv.length !== 2) throw new Error("No arguments accepted");
    await render(false);
    await render(true);
    console.log("Standalone base and offline Compose renders retain the local transport boundary.");
  } catch {
    console.error("Standalone Compose render boundary failed; do not treat configuration as qualified.");
    process.exitCode = 1;
  }
}
