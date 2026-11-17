import assert from "node:assert/strict";
import { test } from "node:test";

import { checkLedger9LocalStack, localnetAttachFailure,
  localnetInputFromEnvironment } from "./check-ledger9-local-stack.mjs";

const genesis = `0x${"a".repeat(64)}`;
function fixture(overrides = {}) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url, init });
    if (url.endsWith("/api/v4/graphql")) {
      const source = JSON.parse(init.body).query;
      const block = source.includes("height: 0")
        ? { height: 0, hash: genesis.slice(2), protocolVersion: 2001100 }
        : { height: overrides.indexedHeight ?? 23, hash: "b".repeat(64),
          protocolVersion: overrides.indexerProtocol ?? 2001100 };
      return Response.json({ data: { block: overrides.indexerGenesis && block.height === 0
        ? { ...block, hash: "c".repeat(64) } : block } });
    }
    if (url.endsWith("/version")) return new Response(overrides.proofVersion ?? "9.0.2", {
      status: overrides.proofStatus ?? 200,
    });
    const { method, params } = JSON.parse(init.body);
    const result = {
      system_version: "2.1.101-test",
      state_getRuntimeVersion: { specVersion: overrides.nodeProtocol ?? 2001100 },
      chain_getBlockHash: params[0] === 23
        ? `0x${(overrides.nodeIndexedHash ?? "b".repeat(64))}`
        : params[0] === 12 ? `0x${(overrides.checkpointHash ?? "d".repeat(64))}` : genesis,
    }[method];
    return Response.json({ jsonrpc: "2.0", id: 1, result });
  };
  return { fetchImpl, calls };
}

test("checks shared-stack node, indexed block and proof-server versions", async () => {
  const { fetchImpl, calls } = fixture();
  const result = await checkLedger9LocalStack({ fetchImpl, expectedGenesisHash: genesis });
  assert.deepEqual(result, { urls: {
    nodeRpcUrl: "http://127.0.0.1:9944",
    indexerHttpUrl: "http://127.0.0.1:8088/api/v4/graphql",
    indexerWsUrl: "ws://127.0.0.1:8088/api/v4/graphql/ws",
    proofServerUrl: "http://127.0.0.1:6300",
  }, nodeVersion: "2.1.101-test", protocolVersion: 2001100,
    genesisHash: genesis, indexedHeight: 23, indexedBlockHash: `0x${"b".repeat(64)}`,
    proofVersion: "9.0.2" });
  assert.equal(calls.length, 7);
  assert.ok(calls.every(({ url }) => url.startsWith("http://127.0.0.1:")));
  assert.ok(calls.some(({ url }) => url === "http://127.0.0.1:9944"));
  assert.ok(calls.some(({ url }) => url === "http://127.0.0.1:8088/api/v4/graphql"));
  assert.ok(calls.some(({ url }) => url === "http://127.0.0.1:6300/version"));
});

test("rejects a mismatched approved or indexed genesis", async () => {
  await assert.rejects(checkLedger9LocalStack({ fetchImpl: fixture().fetchImpl,
    expectedGenesisHash: `0x${"d".repeat(64)}` }), /approved value/u);
  await assert.rejects(checkLedger9LocalStack({ fetchImpl: fixture({ indexerGenesis: true }).fetchImpl }),
    /genesis differ/u);
});

test("rejects node/indexer divergence beyond genesis", async () => {
  await assert.rejects(checkLedger9LocalStack({
    fetchImpl: fixture({ nodeIndexedHash: "c".repeat(64) }).fetchImpl,
  }), /disagree at the indexed height/u);
});

test("pins a non-genesis checkpoint to distinguish replaced local chains", async () => {
  const approved = `0x${"d".repeat(64)}`;
  const { fetchImpl, calls } = fixture();
  await checkLedger9LocalStack({ fetchImpl, expectedCheckpointHeight: 12,
    expectedCheckpointHash: approved });
  assert.ok(calls.some(({ init }) => init.body?.includes('"chain_getBlockHash","params":[12]')));
  await assert.rejects(checkLedger9LocalStack({ fetchImpl: fixture({ checkpointHash: "e".repeat(64) }).fetchImpl,
    expectedCheckpointHeight: 12, expectedCheckpointHash: approved }), /approved checkpoint/u);
  await assert.rejects(checkLedger9LocalStack({ fetchImpl,
    expectedCheckpointHeight: 24, expectedCheckpointHash: approved }), /not reached/u);
  await assert.rejects(checkLedger9LocalStack({ fetchImpl,
    expectedCheckpointHeight: 12 }), /requires a positive height/u);
});

test("rejects wrong protocol, unavailable proof server, and invalid ports", async () => {
  await assert.rejects(checkLedger9LocalStack({ fetchImpl: fixture({ nodeProtocol: 1 }).fetchImpl }),
    /protocol version/u);
  await assert.rejects(checkLedger9LocalStack({ fetchImpl: fixture({ indexerProtocol: 1 }).fetchImpl }),
    /Ledger 9 protocol/u);
  await assert.rejects(checkLedger9LocalStack({ fetchImpl: fixture({ indexedHeight: 0 }).fetchImpl }),
    /no current block/u);
  await assert.rejects(checkLedger9LocalStack({ fetchImpl: fixture({ proofStatus: 503 }).fetchImpl }),
    /Proof server is unavailable/u);
  await assert.rejects(checkLedger9LocalStack({ fetchImpl: fixture({ proofVersion: "9.0.0" }).fetchImpl }),
    /Unexpected proof server version/u);
  await assert.rejects(checkLedger9LocalStack({ nodePort: "99999" }), /port must be/u);
});

test("accepts explicitly isolated ports and proof version", async () => {
  const { fetchImpl, calls } = fixture({ proofVersion: "9.0.0" });
  await checkLedger9LocalStack({ fetchImpl, nodePort: 29944, indexerPort: 28088,
    proofPort: 26300, expectedProofVersion: "9.0.0" });
  assert.ok(calls.some(({ url }) => url === "http://127.0.0.1:29944"));
  assert.ok(calls.some(({ url }) => url === "http://127.0.0.1:28088/api/v4/graphql"));
  assert.ok(calls.some(({ url }) => url === "http://127.0.0.1:26300/version"));
});

test("identifies the unavailable local service", async () => {
  const healthy = fixture().fetchImpl;
  for (const [service, failingUrl] of [
    ["Node RPC system_version", ":9944"],
    ["Indexer GraphQL", "/api/v4/graphql"],
    ["Proof server", ":6300/version"],
  ]) {
    const fetchImpl = (url, options) => url.endsWith(failingUrl)
      ? Promise.reject(new DOMException("The operation timed out", "TimeoutError"))
      : healthy(url, options);
    await assert.rejects(checkLedger9LocalStack({ fetchImpl }),
      new RegExp(`${service} timed out after 5 seconds`, "u"));
  }
});

test("failed attach directs ownership handoff, never a shared-stack restart", () => {
  const message = localnetAttachFailure(new Error("Node RPC timed out after 5 seconds"));
  assert.match(message, /Node RPC timed out after 5 seconds/u);
  assert.match(message, /Ask the designated owner/u);
  assert.match(message, /Continue offline work/u);
  assert.match(message, /separately named isolated project and Docker-assigned loopback ports/u);
  assert.doesNotMatch(message, /docker compose .*up/u);
});

test("CLI and workload wrapper share the selected localnet endpoints", () => {
  assert.deepEqual(localnetInputFromEnvironment({ TR_NODE_PORT: "1", TR_INDEXER_PORT: "2",
    TR_PROOF_PORT: "3", TR_EXPECTED_GENESIS_HASH: "pin", TR_EXPECTED_CHECKPOINT_HEIGHT: "12",
    TR_EXPECTED_CHECKPOINT_HASH: "hash", TR_EXPECTED_PROOF_VERSION: "9.0.0" }), {
    nodePort: "1", indexerPort: "2", proofPort: "3",
    expectedGenesisHash: "pin", expectedCheckpointHeight: "12", expectedCheckpointHash: "hash",
    expectedProofVersion: "9.0.0",
  });
});
