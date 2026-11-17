import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  connectSmokeWallet,
  localSmokeMidnightConfig,
  loadOrCreateSmokeMaintenanceKey,
  smokeMaintenanceSigningKey,
  PUBLIC_LOCAL_SMOKE_SEED,
  validateLocalSmokeEnvironment,
} from "./local-smoke-provider.mjs";
import { createLocalDeploymentMaterial as createPolicyBoundMaterial,
  policyBoundSmokeBootstrap } from "./local-policy-bound-smoke-provider.mjs";
import { signatureVerifyingKey } from "@midnight-ntwrk/compact-runtime";

test("Ledger 9 smoke provider passes WalletSeeds to testkit-js v5", async () => {
  const logger = { marker: "logger" };
  const env = { marker: "environment" };
  const built = { wallet: { marker: "wallet" }, seeds: { marker: "seeds" }, keystore: { marker: "keystore" } };
  const connected = { marker: "connected" };
  const result = await connectSmokeWallet(logger, env, built, async (...args) => {
    assert.deepEqual(args, [logger, env, built.wallet, built.seeds, built.keystore]);
    return connected;
  });
  assert.equal(result, connected);
});

test("Ledger 9 smoke provider pins the local network and transaction TTL", () => {
  assert.deepEqual(localSmokeMidnightConfig(network), { networkId: "undeployed", ttlSeconds: 3600 });
});

test("Ledger 9 smoke maintenance key uses the tagged Compact signing-key shape", () => {
  const key = smokeMaintenanceSigningKey("1".repeat(64));
  assert.deepEqual(key, { tag: "schnorr", value: "1".repeat(64) });
  assert.equal(signatureVerifyingKey(key).tag, "schnorr");
  assert.throws(() => smokeMaintenanceSigningKey("not-hex"), /malformed/u);
});

test("policy-bound development provider requires approved canonical policy input", async () => {
  await assert.rejects(createPolicyBoundMaterial({}), /approved canonical policy input/u);
  await assert.rejects(createPolicyBoundMaterial({ approvedPolicy: { registryId: "registry:local",
    commitment: "bad" } }), /approved canonical policy input/u);
  const oldCommitment = Buffer.alloc(32, 3);
  const original = { registryId: "registry:old", governancePolicyCommitment: oldCommitment,
    maintainerThreshold: 1n };
  const result = policyBoundSmokeBootstrap(original,
    { registryId: "registry:midnight:local:v1", commitment: `0x${"a".repeat(64)}` });
  assert.equal(result.registryId, "registry:midnight:local:v1");
  assert.equal(Buffer.from(result.governancePolicyCommitment).toString("hex"), "a".repeat(64));
  assert.equal(result.maintainerThreshold, 1n);
  assert.equal(original.governancePolicyCommitment, oldCommitment);
  assert.throws(() => policyBoundSmokeBootstrap(original,
    { registryId: "registry:midnight:local:v1", commitment: "not-a-hash" }), /approved canonical/u);
});

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
