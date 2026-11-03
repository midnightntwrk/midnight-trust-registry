#!/usr/bin/env node

import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createLocalRpcFinalizedCheckpointSource, getLocalNetworkProfile } from "@midnight-ntwrk/trust-registry-integration";
import { exactFields } from "./standalone-exact-fields-policy.mjs";

const HASH = /^0x[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const FIELDS = ["allowedHosts", "expectedGenesisHash", "format", "networkId", "rpcUrl", "sourceRevision"];

/** @typedef {{allowedHosts: string[], expectedGenesisHash: string, format: "tr-local-ledger-pin-v1",
 * networkId: "undeployed", rpcUrl: string, sourceRevision: string}} LocalLedgerPin */
/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/** Validate exact proposed pin bytes before any topology or node observation.
 * @param {unknown} candidate
 * @returns {LocalLedgerPin}
 */
export function validateLocalLedgerPin(candidate) {
  if (!isRecord(candidate)
    || !exactFields(candidate, FIELDS)
    || candidate.format !== "tr-local-ledger-pin-v1"
    || candidate.networkId !== getLocalNetworkProfile().networkId
    || typeof candidate.sourceRevision !== "string" || !REVISION.test(candidate.sourceRevision)
    || typeof candidate.expectedGenesisHash !== "string" || !HASH.test(candidate.expectedGenesisHash)
    || /^0x0{64}$/u.test(candidate.expectedGenesisHash)
    || typeof candidate.rpcUrl !== "string"
    || !Array.isArray(candidate.allowedHosts) || candidate.allowedHosts.length === 0
    || candidate.allowedHosts.some((host) => typeof host !== "string" || host.length === 0)) {
    throw new Error("Local ledger preflight requires an exact approved network, source, and genesis pin");
  }
  return /** @type {LocalLedgerPin} */ (/** @type {unknown} */ (candidate));
}

/** The standalone wizard exposes only its prepared loopback endpoint during installation.
 * @param {unknown} candidate
 * @param {string} sourceRevision
 * @returns {LocalLedgerPin}
 */
export function validateStandaloneGenesisPin(candidate, sourceRevision) {
  const pin = validateLocalLedgerPin(candidate);
  if (pin.sourceRevision !== sourceRevision) {
    throw new Error("Genesis pin source revision disagrees with the installed bundle");
  }
  if (pin.allowedHosts.length !== 1 || pin.allowedHosts[0] !== "127.0.0.1"
    || !/^http:\/\/127\.0\.0\.1:([1-9][0-9]*)$/u.test(pin.rpcUrl)) {
    throw new Error("Genesis pin must allow only the prepared loopback host");
  }
  const port = Number(pin.rpcUrl.slice(pin.rpcUrl.lastIndexOf(":") + 1));
  if (port < 1024 || port > 65535) {
    throw new Error("Genesis pin must use a valid prepared loopback port");
  }
  return pin;
}

/** Node observation only; an operator must approve the genesis from another channel.
 * @param {unknown} candidate
 * @param {typeof fetch} [fetchImpl]
 */
export async function checkLocalLedgerPreflight(candidate, fetchImpl) {
  const plan = validateLocalLedgerPin(candidate);
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
