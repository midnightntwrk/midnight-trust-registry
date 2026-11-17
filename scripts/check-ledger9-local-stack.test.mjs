import assert from "node:assert/strict";
import { test } from "node:test";

import { checkLedger9LocalStack } from "./check-ledger9-local-stack.mjs";

const genesis = `0x${"a".repeat(64)}`;
function fixture(overrides = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    if (url.endsWith("/api/v4/graphql")) {
      const source = JSON.parse(init.body).query;
      const block = source.includes("height: 0")
        ? { height: 0, hash: genesis.slice(2), protocolVersion: 2001100 }
        : { height: 23, hash: "b".repeat(64), protocolVersion: overrides.indexerProtocol ?? 2001100 };
      return Response.json({ data: { block: overrides.indexerGenesis && block.height === 0
        ? { ...block, hash: "c".repeat(64) } : block } });
    }
    if (url.endsWith(":26300/")) return new Response("ready", { status: overrides.proofStatus ?? 200 });
    const { method } = JSON.parse(init.body);
    const result = {
      system_version: "2.1.101-test",
      state_getRuntimeVersion: { specVersion: overrides.nodeProtocol ?? 2001100 },
      chain_getBlockHash: genesis,
    }[method];
    return Response.json({ jsonrpc: "2.0", id: 1, result });
  };
  return { fetchImpl, calls };
}

test("checks node, indexer genesis and protocol, and proof-server reachability", async () => {
  const { fetchImpl, calls } = fixture();
  const result = await checkLedger9LocalStack({ fetchImpl, expectedGenesisHash: genesis });
  assert.deepEqual(result, { nodeVersion: "2.1.101-test", protocolVersion: 2001100,
    genesisHash: genesis, indexedHeight: 23, proofServerReachable: true });
  assert.equal(calls.length, 6);
  assert.ok(calls.every(({ url }) => url.startsWith("http://127.0.0.1:")));
});

test("rejects a mismatched approved or indexed genesis", async () => {
  await assert.rejects(checkLedger9LocalStack({ fetchImpl: fixture().fetchImpl,
    expectedGenesisHash: `0x${"d".repeat(64)}` }), /approved value/u);
  await assert.rejects(checkLedger9LocalStack({ fetchImpl: fixture({ indexerGenesis: true }).fetchImpl }),
    /genesis differ/u);
});

test("rejects wrong protocol, unavailable proof server, and invalid ports", async () => {
  await assert.rejects(checkLedger9LocalStack({ fetchImpl: fixture({ nodeProtocol: 1 }).fetchImpl }),
    /protocol version/u);
  await assert.rejects(checkLedger9LocalStack({ fetchImpl: fixture({ indexerProtocol: 1 }).fetchImpl }),
    /Ledger 9 protocol/u);
  await assert.rejects(checkLedger9LocalStack({ fetchImpl: fixture({ proofStatus: 503 }).fetchImpl }),
    /Proof server is unavailable/u);
  await assert.rejects(checkLedger9LocalStack({ nodePort: "99999" }), /port must be/u);
});
