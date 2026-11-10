import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  scanLocalDeploymentAttempt,
  scanLocalDeploymentAttemptFiles,
} from "./scan-local-deployment-attempt.mjs";

const hash = (value) => `0x${value.toString(16).padStart(64, "0")}`;
const raw = (value) => hash(value).slice(2);
const sourceRevision = "a".repeat(40);

function fixture() {
  const plan = {
    format: "tr-local-deployment-plan-v1",
    sourceRevision,
    journalPath: "/private/attempt.json",
    providerModulePath: "/private/provider.mjs",
    providerModuleSha256: "b".repeat(64),
    releaseManifestPath: "/private/release-manifest.json",
    network: {
      networkId: "undeployed",
      expectedGenesisHash: hash(1),
      rpcUrl: "http://127.0.0.1:30944",
      indexerHttpUrl: "http://127.0.0.1:38088/api/v4/graphql",
      indexerWsUrl: "ws://127.0.0.1:38088/api/v4/graphql/ws",
      allowedHosts: ["127.0.0.1"],
    },
  };
  const reservation = {
    version: 1, networkId: "undeployed", sourceRevision,
    expectedGenesisHash: hash(1), reservedAt: new Date(15 * 60_000).toISOString(),
    registryIdCommitment: hash(2), bootstrapMaintenanceVerifyingKey: hash(3),
    intentSha256: "c".repeat(64),
  };
  const blocks = [10, 11, 12].map((height) => ({
    height, hash: raw(height), parent: { hash: raw(height - 1) },
    timestamp: [0, 30 * 60_000, 2 * 60 * 60_000][height - 10], transactions: [],
  }));
  const fetchImpl = async (url, options) => {
    assert.equal(options.method, "POST");
    assert.equal(options.redirect, "error");
    const body = JSON.parse(options.body);
    if (url.includes("30944")) {
      if (Array.isArray(body)) {
        return { ok: true, json: async () => body.map((request) => ({
          id: request.id, result: hash(request.params[0]),
        })) };
      }
      const { method, params } = body;
      const result = method === "chain_getFinalizedHead" ? hash(12)
        : method === "chain_getHeader" ? { number: "0xc" }
          : method === "author_pendingExtrinsics" ? []
            : method === "chain_getBlockHash" ? hash(params[0] === 0 ? 1 : params[0]) : undefined;
      return { ok: true, json: async () => ({ jsonrpc: "2.0", id: 1, result }) };
    }
    const data = {};
    for (const match of body.query.matchAll(/h(\d+):block/gu)) {
      data[`h${match[1]}`] = blocks.find((block) => block.height === Number(match[1])) ?? null;
    }
    return { ok: true, json: async () => ({ data }) };
  };
  return { plan, reservation, blocks, fetchImpl };
}

test("scan brackets the attempt with a node-pinned contiguous finalized range", async () => {
  const f = fixture();
  const report = await scanLocalDeploymentAttempt(f.plan, f.reservation, 10, f.fetchImpl);
  assert.equal(report.conclusion, "observation-only-not-recovery-approval");
  assert.equal(report.scanned.blockCount, 3);
  assert.equal(report.scanned.indexerReportedTransactionCount, 0);
  assert.deepEqual(report.scanned.indexerReportedDeployments, []);
  assert.equal(report.transactionEnumeration, "indexer-reported-not-independently-verified-by-node");
  assert.equal(report.chainAtEnd.bestChainBlocksNotScanned, 0);
  assert.equal(report.pendingExtrinsicsAtEnd, 0);
  assert.equal(report.scanned.endHash, hash(12));
});

test("scan rejects a delimiter-colliding reservation before querying the node", async () => {
  const f = fixture();
  const { networkId, registryIdCommitment, ...rest } = f.reservation;
  const colliding = { ...rest, "networkId\u0000registryIdCommitment": networkId };
  let requests = 0;
  await assert.rejects(scanLocalDeploymentAttempt(f.plan, colliding, 10, async () => {
    requests += 1;
    throw new Error("unexpected network request");
  }), /matching local plan, reservation/u);
  assert.equal(requests, 0);
});

test("scan reports public deployment candidates without inferring their constructor state", async () => {
  const f = fixture();
  f.blocks[1].transactions.push({
    hash: raw(99), contractActions: [{ __typename: "ContractDeploy", address: raw(77) }],
  });
  const report = await scanLocalDeploymentAttempt(f.plan, f.reservation, 10, f.fetchImpl);
  assert.equal(report.scanned.indexerReportedTransactionCount, 1);
  assert.deepEqual(report.scanned.indexerReportedDeployments, [{
    blockHeight: 11, txHash: raw(99), contractAddress: hash(77),
  }]);
});

test("scan rejects broken ancestry, wrong genesis, and a range after reservation", async () => {
  const f = fixture();
  f.blocks[1].parent.hash = raw(8);
  await assert.rejects(scanLocalDeploymentAttempt(f.plan, f.reservation, 10, f.fetchImpl),
    /not contiguous/u);
  f.blocks[1].parent.hash = raw(10);
  await assert.rejects(scanLocalDeploymentAttempt({ ...f.plan,
    network: { ...f.plan.network, expectedGenesisHash: hash(2) } },
  { ...f.reservation, expectedGenesisHash: hash(2) }, 10, f.fetchImpl), /genesis disagrees/u);
  await assert.rejects(scanLocalDeploymentAttempt(f.plan, f.reservation, 11, f.fetchImpl),
    /bracket the reservation/u);
});

test("scan rejects off-host endpoints and a nonfinalized indexer block", async () => {
  const f = fixture();
  await assert.rejects(scanLocalDeploymentAttempt({ ...f.plan,
    network: { ...f.plan.network, indexerHttpUrl: "https://example.com/graphql" } },
  f.reservation, 10, f.fetchImpl), /approved loopback/u);
  f.blocks[2].hash = raw(13);
  await assert.rejects(scanLocalDeploymentAttempt(f.plan, f.reservation, 10, f.fetchImpl),
    /not contiguous with the node-pinned chain/u);
});

test("scan fails closed on missing blocks and duplicate transaction hashes", async () => {
  const f = fixture();
  f.blocks.splice(1, 1);
  await assert.rejects(scanLocalDeploymentAttempt(f.plan, f.reservation, 10, f.fetchImpl),
    /missing or not contiguous/u);
  const complete = fixture();
  complete.blocks[0].transactions.push({ hash: raw(99), contractActions: [] });
  complete.blocks[1].transactions.push({ hash: raw(99), contractActions: [] });
  await assert.rejects(scanLocalDeploymentAttempt(
    complete.plan, complete.reservation, 10, complete.fetchImpl,
  ), /transaction metadata is invalid/u);
});

test("scan rejects a self-consistent indexer chain with an internal hash absent from the node", async () => {
  const f = fixture();
  f.blocks[1].hash = raw(99);
  f.blocks[2].parent.hash = raw(99);
  await assert.rejects(scanLocalDeploymentAttempt(f.plan, f.reservation, 10, f.fetchImpl),
    /not contiguous with the node-pinned chain/u);
});

test("scan file report pins exact input bytes without changing the reservation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-local-scan-"));
  try {
    const f = fixture();
    const planPath = join(directory, "plan.json");
    const journalPath = join(directory, "attempt.json");
    f.plan.journalPath = journalPath;
    const planBytes = JSON.stringify(f.plan);
    const reservationBytes = JSON.stringify(f.reservation);
    await writeFile(planPath, planBytes);
    await writeFile(journalPath, reservationBytes);
    const report = await scanLocalDeploymentAttemptFiles(planPath, 10, f.fetchImpl);
    assert.match(report.planSha256, /^[0-9a-f]{64}$/u);
    assert.match(report.reservationSha256, /^[0-9a-f]{64}$/u);
  assert.equal(report.scanned.indexerReportedTransactionCount, 0);
    assert.equal(await readFile(journalPath, "utf8"), reservationBytes);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("scan reports blocks newer than its captured finalized range", async () => {
  const f = fixture();
  let finalizedReads = 0;
  const fetchImpl = async (url, options) => {
    const body = JSON.parse(options.body);
    if (body.method === "chain_getFinalizedHead") {
      finalizedReads += 1;
      return { ok: true, json: async () => ({ result: hash(finalizedReads === 1 ? 12 : 13) }) };
    }
    if (body.method === "chain_getHeader" && body.params.length === 0) {
      return { ok: true, json: async () => ({ result: { number: "0xe" } }) };
    }
    if (body.method === "chain_getHeader" && body.params[0] === hash(13)) {
      return { ok: true, json: async () => ({ result: { number: "0xd" } }) };
    }
    return f.fetchImpl(url, options);
  };
  const report = await scanLocalDeploymentAttempt(f.plan, f.reservation, 10, fetchImpl);
  assert.equal(report.chainAtEnd.newerFinalizedBlocksNotScanned, 1);
  assert.equal(report.chainAtEnd.bestChainBlocksNotScanned, 2);
});

test("file scanner rejects a receipt that arrives during the scan", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-local-scan-"));
  try {
    const f = fixture();
    const planPath = join(directory, "plan.json");
    const journalPath = join(directory, "attempt.json");
    f.plan.journalPath = journalPath;
    await writeFile(planPath, JSON.stringify(f.plan));
    await writeFile(journalPath, JSON.stringify(f.reservation));
    let receiptWritten = false;
    const fetchImpl = async (url, options) => {
      if (url.includes("38088") && !receiptWritten) {
        await writeFile(`${journalPath}.submitted`, "{}");
        receiptWritten = true;
      }
      return f.fetchImpl(url, options);
    };
    await assert.rejects(scanLocalDeploymentAttemptFiles(planPath, 10, fetchImpl),
      /already has a submitted receipt/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("file scanner rejects a submitted journal and never calls the network", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-local-scan-"));
  try {
    const f = fixture();
    const planPath = join(directory, "plan.json");
    const journalPath = join(directory, "attempt.json");
    f.plan.journalPath = journalPath;
    await writeFile(planPath, JSON.stringify(f.plan));
    await writeFile(journalPath, JSON.stringify(f.reservation));
    await writeFile(`${journalPath}.submitted`, "{}");
    await assert.rejects(scanLocalDeploymentAttemptFiles(planPath, 10,
      async () => assert.fail("submitted journal must stop before a network call")),
    /already has a submitted receipt/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
