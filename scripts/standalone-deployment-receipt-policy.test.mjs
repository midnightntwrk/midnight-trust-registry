import assert from "node:assert/strict";
import { test } from "node:test";

import { validLocalDeploymentReceipt } from "./standalone-deployment-receipt-policy.mjs";

const networkId = "undeployed";
const valid = {
  networkId,
  contractAddress: `0x${"ab".repeat(32)}`,
  blockHash: `0x${"cd".repeat(32)}`,
  txId: "tx-1",
  blockHeight: 0,
};

test("accepts a complete nonzero local deployment receipt", () => {
  assert.equal(validLocalDeploymentReceipt(valid, networkId), true);
});

test("rejects missing, malformed, or wrong-network deployment receipts", () => {
  for (const receipt of [null, undefined, [], "receipt", {},
    { ...valid, networkId: "preprod" },
    { ...valid, contractAddress: `0x${"00".repeat(32)}` },
    { ...valid, contractAddress: 42 },
    { ...valid, blockHash: `0x${"00".repeat(32)}` },
    { ...valid, blockHash: "not-a-hash" },
    { ...valid, txId: "" },
    { ...valid, blockHeight: -1 },
    { ...valid, blockHeight: 0.5 },
    { ...valid, blockHeight: Number.MAX_SAFE_INTEGER + 1 },
  ]) {
    assert.equal(validLocalDeploymentReceipt(receipt, networkId), false);
  }
});
