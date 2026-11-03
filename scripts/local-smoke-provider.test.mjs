import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  loadOrCreateSmokeMaintenanceKey,
  PUBLIC_LOCAL_SMOKE_SEED,
  validateLocalSmokeEnvironment,
} from "./local-smoke-provider.mjs";

const network = {
  networkId: "undeployed",
  rpcUrl: "http://127.0.0.1:30944/",
  indexerHttpUrl: "http://127.0.0.1:38088/api/v4/graphql",
  indexerWsUrl: "ws://127.0.0.1:38088/api/v4/graphql/ws",
  allowedHosts: ["127.0.0.1"],
};
const environment = {
  TR_SMOKE_WALLET_SEED: PUBLIC_LOCAL_SMOKE_SEED,
  TR_SMOKE_STATE_DIR: "/private/setup",
  TR_SMOKE_PROOF_URL: "http://127.0.0.1:36300",
};

test("public-genesis smoke profile requires undeployed loopback endpoints", () => {
  assert.equal(validateLocalSmokeEnvironment(network, environment).walletSeed, PUBLIC_LOCAL_SMOKE_SEED);
  assert.throws(() => validateLocalSmokeEnvironment({ ...network, networkId: "preprod" }, environment), /requires the public/u);
  assert.throws(() => validateLocalSmokeEnvironment(network, { ...environment, TR_SMOKE_WALLET_SEED: "a".repeat(64) }), /requires the public/u);
  assert.throws(() => validateLocalSmokeEnvironment({ ...network, rpcUrl: "http://public.example:9944" }, environment), /only accepts explicit/u);
  assert.throws(() => validateLocalSmokeEnvironment(network, { ...environment, TR_SMOKE_PROOF_URL: "http://localhost:6300" }), /only accepts explicit/u);
  assert.throws(() => validateLocalSmokeEnvironment({ ...network, allowedHosts: ["127.0.0.1", "private.example"] }, environment), /requires the public/u);
});

test("smoke maintenance key is generated once in a private directory", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-smoke-key-"));
  const first = await loadOrCreateSmokeMaintenanceKey(directory);
  const second = await loadOrCreateSmokeMaintenanceKey(directory);
  assert.match(first, /^[0-9a-f]{64}$/u);
  assert.equal(second, first);
  const path = join(directory, "smoke-maintenance-key");
  assert.equal((await lstat(path)).mode & 0o077, 0);
  assert.equal((await readFile(path, "utf8")).trim(), first);
  await chmod(directory, 0o755);
  await assert.rejects(loadOrCreateSmokeMaintenanceKey(directory), /mode 0700/u);
});
