#!/usr/bin/env node

import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createLocalRpcFinalizedCheckpointSource, getLocalNetworkProfile } from "@midnight-ntwrk/trust-registry-integration";

const HASH = /^0x[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const FIELDS = ["allowedHosts", "expectedGenesisHash", "format", "networkId", "rpcUrl", "sourceRevision"];

/** Node observation only; an operator must approve the genesis from another channel. */
export async function checkLocalLedgerPreflight(plan, fetchImpl) {
  if (plan === null || typeof plan !== "object" || Array.isArray(plan)
    || Object.keys(plan).sort().join("\0") !== FIELDS.join("\0")
    || plan.format !== "tr-local-ledger-pin-v1" || plan.networkId !== getLocalNetworkProfile().networkId
    || !REVISION.test(plan.sourceRevision)
    || !HASH.test(plan.expectedGenesisHash)
    || /^0x0{64}$/u.test(plan.expectedGenesisHash)
    || typeof plan.rpcUrl !== "string"
    || !Array.isArray(plan.allowedHosts) || plan.allowedHosts.length === 0
    || plan.allowedHosts.some((host) => typeof host !== "string" || host.length === 0)) {
    throw new Error("Local ledger preflight requires an exact approved network, source, and genesis pin");
  }
  const source = createLocalRpcFinalizedCheckpointSource({
    rpcUrl: plan.rpcUrl,
    expectedGenesisHash: plan.expectedGenesisHash,
    allowedHosts: plan.allowedHosts,
    fetchImpl,
  });
  const checkpoint = await source.readCurrentFinalizedCheckpoint();
  if (checkpoint === null || checkpoint.networkId !== getLocalNetworkProfile().networkId
    || checkpoint.blockHash === plan.expectedGenesisHash.slice(2)) {
    throw new Error("Local ledger has no progressing finalized head");
  }
  return {
    kind: "local-node-observation-only",
    sourceRevision: plan.sourceRevision,
    networkId: checkpoint.networkId,
    expectedGenesisHash: plan.expectedGenesisHash,
    finalizedBlockHash: `0x${checkpoint.blockHash}`,
    observedAt: new Date().toISOString(),
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    throw new Error("Usage: node scripts/local-ledger-preflight.mjs <approved-pin.json>");
  }
  const path = resolve(process.argv[2]);
  if (!(await lstat(path)).isFile()) throw new Error("Approved local ledger pin must be a regular file");
  const plan = JSON.parse(await readFile(path, "utf8"));
  console.log(JSON.stringify(await checkLocalLedgerPreflight(plan)));
}
