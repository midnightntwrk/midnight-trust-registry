import assert from "node:assert/strict";
import { test } from "node:test";

import { observeLocalDeploymentInclusion } from "./observe-local-deployment-inclusion.mjs";

const hash = (character) => `0x${character.repeat(64)}`;
const plan = {
  sourceRevision: "a".repeat(40),
  network: {
    networkId: "undeployed", expectedGenesisHash: hash("1"),
    allowedHosts: ["127.0.0.1"],
    rpcUrl: "http://127.0.0.1:9944",
    indexerHttpUrl: "http://127.0.0.1:8088/api/v4/graphql",
  },
};
const entry = {
  reservation: {
    sourceRevision: plan.sourceRevision,
    expectedGenesisHash: plan.network.expectedGenesisHash,
    networkId: "undeployed",
  },
  submitted: {
    networkId: "undeployed", blockHeight: 505, blockHash: hash("2"),
    contractAddress: hash("3"), txId: `00${"4".repeat(64)}`,
  },
};

function fixture(overrides = {}) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    const input = JSON.parse(options.body);
    calls.push({ url, input });
    if (input.query) return Response.json({ data: { block: {
      height: 505, hash: overrides.indexedHash ?? "2".repeat(64),
      transactions: [{ hash: "5".repeat(64),
        identifiers: overrides.identifiers ?? ["6".repeat(64), entry.submitted.txId],
        contractActions: [{ __typename: "ContractDeploy",
          address: overrides.address ?? entry.submitted.contractAddress.slice(2) }],
      }],
    } } });
    const value = {
      chain_getBlockHash: input.params[0] === 0
        ? plan.network.expectedGenesisHash : overrides.nodeBlockHash ?? entry.submitted.blockHash,
      chain_getFinalizedHead: hash("7"),
      chain_getHeader: { number: overrides.finalizedHeight ?? "0x1fa" },
    }[input.method];
    return Response.json({ jsonrpc: "2.0", id: 1, result: value });
  };
  return { fetchImpl, calls };
}

test("links the SDK receipt identifier to an indexed deploy action in a finalized node block", async () => {
  const { fetchImpl, calls } = fixture();
  const result = await observeLocalDeploymentInclusion(plan, entry, fetchImpl);
  assert.equal(result.receiptTxId, entry.submitted.txId);
  assert.equal(result.indexerTransactionHash, "5".repeat(64));
  assert.notEqual(result.receiptTxId, result.indexerTransactionHash);
  assert.equal(result.finalizedHeight, 506);
  assert.equal(result.attribution,
    "indexer-reported-transaction-in-finalized-node-block-not-cryptographic-proof");
  assert.ok(calls.every(({ url }) => url.startsWith("http://127.0.0.1:")));
});

test("rejects a different local chain, missing finality, or mismatched indexer block", async () => {
  await assert.rejects(observeLocalDeploymentInclusion(plan, entry,
    fixture({ nodeBlockHash: hash("8") }).fetchImpl), /differs from the finalized node chain/u);
  await assert.rejects(observeLocalDeploymentInclusion(plan, entry,
    fixture({ finalizedHeight: "0x1f8" }).fetchImpl), /not finalized/u);
  await assert.rejects(observeLocalDeploymentInclusion(plan, entry,
    fixture({ indexedHash: "9".repeat(64) }).fetchImpl), /Indexer deployment block differs/u);
});

test("rejects a hash-only match without the receipt identifier and deployed address", async () => {
  await assert.rejects(observeLocalDeploymentInclusion(plan, entry,
    fixture({ identifiers: ["6".repeat(64)] }).fetchImpl), /no unique deployment action/u);
  await assert.rejects(observeLocalDeploymentInclusion(plan, entry,
    fixture({ address: "8".repeat(64) }).fetchImpl), /no unique deployment action/u);
  await assert.rejects(observeLocalDeploymentInclusion(plan, { ...entry, submitted: null },
    fixture().fetchImpl), /no journaled receipt/u);
});

test("rejects non-loopback endpoints before querying the network", async () => {
  const { fetchImpl, calls } = fixture();
  await assert.rejects(observeLocalDeploymentInclusion({ ...plan, network: {
    ...plan.network, rpcUrl: "http://example.com:9944",
  } }, entry, fetchImpl), /loopback HTTP endpoints/u);
  assert.equal(calls.length, 0);
});
