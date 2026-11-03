#!/usr/bin/env node

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { validateLocalDeploymentPlan } from "./local-ledger-deploy.mjs";
import { exactRecordFields } from "./standalone-exact-fields-policy.mjs";

const HASH = /^0x[0-9a-f]{64}$/u;
const RAW_HASH = /^[0-9a-f]{64}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const BATCH_SIZE = 20;
const MAX_BLOCKS = 10_000;
const MIN_OBSERVATION_MS = 60 * 60_000;
const RESERVATION_FIELDS = ["bootstrapMaintenanceVerifyingKey", "expectedGenesisHash",
  "intentSha256", "networkId", "registryIdCommitment", "reservedAt", "sourceRevision", "version"];

/** @param {string | Buffer} bytes */
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
/** @param {{number?: unknown} | null | undefined} header */
const heightOf = (header) => typeof header?.number === "string" && /^0x[0-9a-f]+$/u.test(header.number)
  ? Number.parseInt(header.number.slice(2), 16) : NaN;

/** @param {string} value @param {readonly string[]} allowedHosts */
function localUrl(value, allowedHosts) {
  const url = new URL(value);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1"
    || !allowedHosts.includes(url.hostname) || url.username || url.password
    || url.search || url.hash) {
    throw new Error("Deployment scan endpoints must be approved loopback HTTP URLs");
  }
  return url.toString();
}

/** @param {string} url @param {unknown} body @param {typeof fetch} fetchImpl */
async function postJson(url, body, fetchImpl) {
  const response = await fetchImpl(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error("Local ledger scan endpoint returned an HTTP error");
  return response.json();
}

/** @param {string} url @param {string} method @param {unknown[]} params @param {typeof fetch} fetchImpl */
async function rpc(url, method, params, fetchImpl) {
  const result = await postJson(url, { jsonrpc: "2.0", id: 1, method, params }, fetchImpl);
  if (result?.error || result?.result === undefined) {
    throw new Error(`Local node rejected ${method}`);
  }
  return result.result;
}

/** @param {string} url @param {number[]} heights @param {typeof fetch} fetchImpl */
async function indexedBlocks(url, heights, fetchImpl) {
  const query = `{ ${heights.map((height) => `h${height}:block(offset:{height:${height}}) { height hash timestamp parent { hash } transactions { hash contractActions { __typename address } } }`).join(" ")} }`;
  const result = await postJson(url, { query }, fetchImpl);
  if (result?.errors?.length || !result?.data) {
    throw new Error("Local indexer did not return the requested block range");
  }
  return heights.map((height) => result.data[`h${height}`]);
}

/** @param {string} url @param {number[]} heights @param {typeof fetch} fetchImpl */
async function nodeBlockHashes(url, heights, fetchImpl) {
  const requests = heights.map((height) => ({
    jsonrpc: "2.0", id: height, method: "chain_getBlockHash", params: [height],
  }));
  const result = await postJson(url, requests, fetchImpl);
  if (!Array.isArray(result) || result.length !== heights.length) {
    throw new Error("Local node did not return the complete block-hash batch");
  }
  const byHeight = new Map();
  for (const item of result) {
    if (!Number.isSafeInteger(item?.id) || !HASH.test(item.result)
      || item.error || byHeight.has(item.id)) {
      throw new Error("Local node returned malformed or duplicate block-hash evidence");
    }
    byHeight.set(item.id, item.result);
  }
  return heights.map((height) => {
    const hash = byHeight.get(height);
    if (!hash) throw new Error("Local node omitted a requested block hash");
    return hash;
  });
}

/** Reports finalized, public chain observations only; it never authorizes a retry. */
/** @param {unknown} plan @param {unknown} reservation @param {number} startHeight @param {typeof fetch} fetchImpl */
export async function scanLocalDeploymentAttempt(plan, reservation, startHeight, fetchImpl = fetch) {
  const approvedPlan = validateLocalDeploymentPlan(plan);
  if (!approvedPlan.network.allowedHosts.includes("127.0.0.1")
    || !exactRecordFields(reservation, RESERVATION_FIELDS)
    || reservation.version !== 1
    || reservation.networkId !== "undeployed"
    || reservation.sourceRevision !== approvedPlan.sourceRevision
    || reservation.expectedGenesisHash !== approvedPlan.network.expectedGenesisHash
    || typeof reservation.registryIdCommitment !== "string" || !HASH.test(reservation.registryIdCommitment)
    || typeof reservation.bootstrapMaintenanceVerifyingKey !== "string"
    || !HASH.test(reservation.bootstrapMaintenanceVerifyingKey)
    || typeof reservation.intentSha256 !== "string" || !SHA256.test(reservation.intentSha256)
    || typeof reservation.reservedAt !== "string"
    || !Number.isSafeInteger(Date.parse(reservation.reservedAt))
    || new Date(reservation.reservedAt).toISOString() !== reservation.reservedAt
    || !Number.isSafeInteger(startHeight) || startHeight < 1) {
    throw new Error("Deployment scan requires matching local plan, reservation, and start height");
  }
  const rpcUrl = localUrl(approvedPlan.network.rpcUrl, approvedPlan.network.allowedHosts);
  const indexerUrl = localUrl(approvedPlan.network.indexerHttpUrl, approvedPlan.network.allowedHosts);
  const genesis = await rpc(rpcUrl, "chain_getBlockHash", [0], fetchImpl);
  if (genesis !== approvedPlan.network.expectedGenesisHash) {
    throw new Error("Local node genesis disagrees with the approved deployment plan");
  }
  const finalizedHash = await rpc(rpcUrl, "chain_getFinalizedHead", [], fetchImpl);
  if (!HASH.test(finalizedHash)) throw new Error("Local node has no valid finalized checkpoint");
  const header = await rpc(rpcUrl, "chain_getHeader", [finalizedHash], fetchImpl);
  const finalizedHeight = heightOf(header);
  if (!Number.isSafeInteger(finalizedHeight)) {
    throw new Error("Local node has no valid finalized checkpoint");
  }
  const blockCount = finalizedHeight - startHeight + 1;
  if (!Number.isSafeInteger(finalizedHeight) || blockCount < 2 || blockCount > MAX_BLOCKS) {
    throw new Error("Deployment scan must bracket the attempt in at most 10000 finalized blocks");
  }
  const startParent = await rpc(rpcUrl, "chain_getBlockHash", [startHeight - 1], fetchImpl);
  const startHash = await rpc(rpcUrl, "chain_getBlockHash", [startHeight], fetchImpl);
  if (!HASH.test(startParent) || !HASH.test(startHash)) {
    throw new Error("Local node cannot anchor the beginning of the scan");
  }

  let previousHash = startParent.slice(2);
  let observedStartHash;
  let firstTimestamp;
  let lastTimestamp;
  let indexerReportedTransactionCount = 0;
  const transactionHashes = new Set();
  const indexerReportedDeployments = [];
  for (let height = startHeight; height <= finalizedHeight; height += BATCH_SIZE) {
    const heights = Array.from({ length: Math.min(BATCH_SIZE, finalizedHeight - height + 1) },
      (_, index) => height + index);
    const blocks = await indexedBlocks(indexerUrl, heights, fetchImpl);
    const nodeHashes = await nodeBlockHashes(rpcUrl, heights, fetchImpl);
    for (let index = 0; index < blocks.length; index += 1) {
      const block = blocks[index];
      if (block?.height !== heights[index] || !RAW_HASH.test(block.hash)
        || `0x${block.hash}` !== nodeHashes[index]
        || block.parent?.hash !== previousHash
        || !Number.isSafeInteger(block.timestamp)
        || (lastTimestamp !== undefined && block.timestamp < lastTimestamp)
        || !Array.isArray(block.transactions)) {
        throw new Error(`Indexer block ${heights[index]} is missing or not contiguous with the node-pinned chain`);
      }
      if (firstTimestamp === undefined) {
        firstTimestamp = block.timestamp;
        observedStartHash = block.hash;
      }
      lastTimestamp = block.timestamp;
      previousHash = block.hash;
      for (const transaction of block.transactions) {
        if (!RAW_HASH.test(transaction?.hash) || !Array.isArray(transaction.contractActions)
          || transactionHashes.has(transaction.hash)) {
          throw new Error(`Indexer transaction metadata is invalid at block ${block.height}`);
        }
        transactionHashes.add(transaction.hash);
        indexerReportedTransactionCount += 1;
        for (const action of transaction.contractActions) {
          if (action?.__typename === "ContractDeploy") {
            if (typeof action.address !== "string"
              || !RAW_HASH.test(action.address.replace(/^0x/u, ""))
              || indexerReportedDeployments.length >= 1000) {
              throw new Error("Indexer returned invalid or excessive contract deployment metadata");
            }
            indexerReportedDeployments.push({ blockHeight: block.height, txHash: transaction.hash,
              contractAddress: `0x${action.address.replace(/^0x/u, "")}` });
          }
        }
      }
    }
  }
  const observationWindowMs = lastTimestamp - Date.parse(reservation.reservedAt);
  if (`0x${previousHash}` !== finalizedHash || `0x${observedStartHash}` !== startHash
    || firstTimestamp > Date.parse(reservation.reservedAt)
    || observationWindowMs < MIN_OBSERVATION_MS
    || await rpc(rpcUrl, "chain_getBlockHash", [finalizedHeight], fetchImpl) !== finalizedHash) {
    throw new Error("Indexed range must bracket the reservation by at least one hour at the captured finalized head");
  }
  const finalizedAtEndHash = await rpc(rpcUrl, "chain_getFinalizedHead", [], fetchImpl);
  if (!HASH.test(finalizedAtEndHash)) throw new Error("Local node lost its finalized checkpoint");
  const finalizedAtEndHeight = heightOf(await rpc(rpcUrl, "chain_getHeader", [finalizedAtEndHash], fetchImpl));
  const bestAtEndHeight = heightOf(await rpc(rpcUrl, "chain_getHeader", [], fetchImpl));
  if (!Number.isSafeInteger(finalizedAtEndHeight) || !Number.isSafeInteger(bestAtEndHeight)
    || finalizedAtEndHeight < finalizedHeight || bestAtEndHeight < finalizedAtEndHeight) {
    throw new Error("Local node head moved inconsistently during the scan");
  }
  const pending = await rpc(rpcUrl, "author_pendingExtrinsics", [], fetchImpl);
  if (!Array.isArray(pending)) throw new Error("Local node pending-extrinsic query is unavailable");
  return {
    kind: "local-deployment-attempt-finalized-scan",
    conclusion: "observation-only-not-recovery-approval",
    transactionEnumeration: "indexer-reported-not-independently-verified-by-node",
    sourceRevision: approvedPlan.sourceRevision,
    expectedGenesisHash: genesis,
    reservedAt: reservation.reservedAt,
    scanned: { startHeight, endHeight: finalizedHeight, startHash, endHash: finalizedHash,
      startTimestamp: firstTimestamp, endTimestamp: lastTimestamp, observationWindowMs,
      blockCount, indexerReportedTransactionCount, indexerReportedDeployments },
    chainAtEnd: { finalizedHeight: finalizedAtEndHeight, finalizedHash: finalizedAtEndHash,
      bestHeight: bestAtEndHeight,
      newerFinalizedBlocksNotScanned: finalizedAtEndHeight - finalizedHeight,
      bestChainBlocksNotScanned: bestAtEndHeight - finalizedHeight },
    pendingExtrinsicsAtEnd: pending.length,
  };
}

/** @param {string} path */
async function regularJson(path) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size === 0 || info.size > 32 * 1024) {
      throw new Error("Deployment scan input must be a bounded regular file");
    }
    const bytes = await handle.readFile();
    if (bytes.length !== info.size) throw new Error("Deployment scan input changed during read");
    return { bytes, value: JSON.parse(bytes.toString("utf8")) };
  } finally {
    await handle.close();
  }
}

/** @param {string} journalPath */
async function requireNoReceipt(journalPath) {
  try {
    await lstat(`${journalPath}.submitted`);
    throw new Error("Deployment journal already has a submitted receipt; use receipt reconciliation");
  } catch (error) {
    if (!(error instanceof Error && "code" in error && error.code === "ENOENT")) throw error;
  }
}

/** @param {string} planPath @param {number} startHeight @param {typeof fetch} fetchImpl */
export async function scanLocalDeploymentAttemptFiles(planPath, startHeight, fetchImpl = fetch) {
  const { bytes: planBytes, value: plan } = await regularJson(resolve(planPath));
  const approvedPlan = validateLocalDeploymentPlan(plan);
  if (!isAbsolute(approvedPlan.journalPath)) {
    throw new Error("Approved plan has no absolute attempt journal path");
  }
  const journalPath = resolve(approvedPlan.journalPath);
  const { bytes: reservationBytes, value: reservation } = await regularJson(journalPath);
  await requireNoReceipt(journalPath);
  const report = await scanLocalDeploymentAttempt(plan, reservation, startHeight, fetchImpl);
  const finalPlan = await regularJson(resolve(planPath));
  const finalReservation = await regularJson(journalPath);
  await requireNoReceipt(journalPath);
  if (sha256(planBytes) !== sha256(finalPlan.bytes)
    || sha256(reservationBytes) !== sha256(finalReservation.bytes)) {
    throw new Error("Deployment scan inputs changed while the finalized range was inspected");
  }
  return { ...report, planSha256: sha256(planBytes), reservationSha256: sha256(reservationBytes) };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [planPath, startHeight] = process.argv.slice(2);
  if (!planPath || !/^[1-9][0-9]*$/u.test(startHeight ?? "")) {
    throw new Error("Usage: node scripts/scan-local-deployment-attempt.mjs <approved-plan.json> <start-height-before-reservation>");
  }
  console.log(JSON.stringify(await scanLocalDeploymentAttemptFiles(planPath, Number(startHeight))));
}
