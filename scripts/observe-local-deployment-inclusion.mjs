#!/usr/bin/env node

import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { FileDeploymentAttemptJournal } from "@midnightntwrk/trust-registry-integration";
import { validateLocalDeploymentPlan } from "./local-deployment-plan-policy.mjs";

const HASH = /^0x[0-9a-f]{64}$/u;
const RAW_HASH = /^[0-9a-f]{64}$/u;
const IDENTIFIER = /^(?:[0-9a-f]{2}){1,256}$/u;

function localHttpEndpoint(value) {
  const url = new URL(value);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1"
    || !url.port || url.username || url.password || url.search || url.hash) {
    throw new Error("Deployment inclusion observation requires loopback HTTP endpoints");
  }
}

async function postJson(fetchImpl, url, body) {
  const response = await fetchImpl(url, {
    method: "POST", headers: { "content-type": "application/json" },
    body: JSON.stringify(body), signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) throw new Error(`Read-only chain query failed: HTTP ${response.status}`);
  return response.json();
}

/** @param {ReturnType<typeof validateLocalDeploymentPlan>} plan
 * @param {Awaited<ReturnType<FileDeploymentAttemptJournal["inspect"]>>} entry
 * @param {typeof fetch} [fetchImpl] */
export async function observeLocalDeploymentInclusion(plan, entry, fetchImpl = fetch) {
  if (!entry?.submitted) throw new Error("Deployment has no journaled receipt");
  localHttpEndpoint(plan.network.rpcUrl);
  localHttpEndpoint(plan.network.indexerHttpUrl);
  if (plan.network.allowedHosts?.length !== 1 || plan.network.allowedHosts[0] !== "127.0.0.1") {
    throw new Error("Deployment inclusion observation requires one approved loopback host");
  }
  if (entry.reservation.sourceRevision !== plan.sourceRevision
    || entry.reservation.expectedGenesisHash !== plan.network.expectedGenesisHash
    || entry.reservation.networkId !== plan.network.networkId) {
    throw new Error("Deployment reservation disagrees with the approved plan");
  }
  const receipt = entry.submitted;
  if (!Number.isSafeInteger(receipt.blockHeight) || receipt.blockHeight < 1
    || !HASH.test(receipt.blockHash) || !HASH.test(receipt.contractAddress)
    || !IDENTIFIER.test(receipt.txId)) {
    throw new Error("Journaled deployment receipt is malformed");
  }
  const rpc = async (method, params = []) => {
    const result = await postJson(fetchImpl, plan.network.rpcUrl,
      { jsonrpc: "2.0", id: 1, method, params });
    if (result.jsonrpc !== "2.0" || result.error || result.result === undefined) {
      throw new Error(`Invalid node RPC response for ${method}`);
    }
    return result.result;
  };
  if (await rpc("chain_getBlockHash", [0]) !== plan.network.expectedGenesisHash) {
    throw new Error("Local chain genesis differs from the approved plan");
  }
  const finalizedHash = await rpc("chain_getFinalizedHead");
  const finalizedHeader = await rpc("chain_getHeader", [finalizedHash]);
  const finalizedHeight = Number.parseInt(finalizedHeader?.number, 16);
  if (!HASH.test(finalizedHash) || !Number.isSafeInteger(finalizedHeight)
    || finalizedHeight < receipt.blockHeight) {
    throw new Error("Deployment block is not finalized on the current node");
  }
  if (await rpc("chain_getBlockHash", [receipt.blockHeight]) !== receipt.blockHash) {
    throw new Error("Journaled deployment block differs from the finalized node chain");
  }
  const query = `{ block(offset:{height:${receipt.blockHeight}}) {
    height hash transactions { hash contractActions { __typename address }
      ... on RegularTransaction { identifiers } }
  } }`;
  const indexed = await postJson(fetchImpl, plan.network.indexerHttpUrl, { query });
  if (indexed.errors || indexed.data?.block?.height !== receipt.blockHeight
    || indexed.data.block.hash !== receipt.blockHash.slice(2)
    || !Array.isArray(indexed.data.block.transactions)) {
    throw new Error("Indexer deployment block differs from the finalized node chain");
  }
  const matches = indexed.data.block.transactions.filter((transaction) =>
    Array.isArray(transaction.identifiers)
    && transaction.identifiers.includes(receipt.txId)
    && Array.isArray(transaction.contractActions)
    && transaction.contractActions.some((action) => action.__typename === "ContractDeploy"
      && action.address === receipt.contractAddress.slice(2)));
  if (matches.length !== 1 || !RAW_HASH.test(matches[0].hash)) {
    throw new Error("Indexer has no unique deployment action matching the journaled receipt ID");
  }
  return {
    kind: "local-deployment-inclusion-observation",
    attribution: "indexer-reported-transaction-in-finalized-node-block-not-cryptographic-proof",
    sourceRevision: plan.sourceRevision,
    blockHeight: receipt.blockHeight,
    blockHash: receipt.blockHash,
    contractAddress: receipt.contractAddress,
    receiptTxId: receipt.txId,
    indexerTransactionHash: matches[0].hash,
    finalizedHeight,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) throw new Error("Usage: observe-local-deployment-inclusion.mjs <plan.json>");
  const plan = validateLocalDeploymentPlan(JSON.parse(await readFile(resolve(process.argv[2]), "utf8")));
  const entry = await new FileDeploymentAttemptJournal(plan.journalPath).inspect();
  console.log(JSON.stringify(await observeLocalDeploymentInclusion(plan, entry)));
}
