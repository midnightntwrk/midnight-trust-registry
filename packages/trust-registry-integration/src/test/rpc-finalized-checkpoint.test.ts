import { describe, expect, it } from "vitest";

import { createRpcFinalizedCheckpointSource } from "../rpc-finalized-checkpoint.js";

const GENESIS = `0x${"a".repeat(64)}`;
const FINALIZED = `0x${"b".repeat(64)}`;

const response = (value: unknown, status = 200): Response =>
  new Response(JSON.stringify(value), {
    status,
    headers: { "content-type": "application/json" },
  });

function fixture(responses: readonly Response[] = [
  response({ jsonrpc: "2.0", id: 1, result: GENESIS }),
  response({ jsonrpc: "2.0", id: 1, result: FINALIZED }),
]) {
  const calls: Array<{ url: string; method: string; params: unknown }> = [];
  let next = 0;
  const fetchImpl: typeof fetch = async (url, init) => {
    const body = JSON.parse(String(init?.body)) as { method: string; params: unknown };
    calls.push({ url: String(url), method: body.method, params: body.params });
    return responses[next++] ?? response({ jsonrpc: "2.0", id: 1, result: null });
  };
  return { calls, fetchImpl };
}

describe("RPC finalized checkpoint source", () => {
  it("checks an out-of-band genesis pin before returning the finalized head", async () => {
    const { calls, fetchImpl } = fixture();
    const source = createRpcFinalizedCheckpointSource({
      networkId: "preview",
      rpcUrl: "https://rpc.preview.midnight.network",
      expectedGenesisHash: GENESIS.toUpperCase().replace("0X", "0x"),
      fetchImpl,
    });
    await expect(source.readCurrentFinalizedCheckpoint()).resolves.toEqual({
      networkId: "preview", blockHash: FINALIZED.slice(2),
    });
    expect(calls).toEqual([
      { url: "https://rpc.preview.midnight.network/", method: "chain_getBlockHash", params: [0] },
      { url: "https://rpc.preview.midnight.network/", method: "chain_getFinalizedHead", params: [] },
    ]);
  });

  it("never reads a finalized head after a wrong genesis", async () => {
    const { calls, fetchImpl } = fixture();
    const source = createRpcFinalizedCheckpointSource({
      networkId: "preprod",
      rpcUrl: "https://rpc.midnight-preprod.blockfrost.io?project_id=secret-token",
      expectedGenesisHash: `0x${"c".repeat(64)}`,
      fetchImpl,
    });
    await expect(source.readCurrentFinalizedCheckpoint()).rejects.toThrow(/genesis hash mismatch/u);
    expect(calls).toHaveLength(1);
  });

  it("rejects unsafe URLs and malformed pins before making a request", () => {
    const base = { networkId: "preview" as const, expectedGenesisHash: GENESIS };
    expect(() => createRpcFinalizedCheckpointSource({
      ...base, rpcUrl: "http://remote.example/rpc",
    })).toThrow(/HTTPS or loopback/u);
    expect(() => createRpcFinalizedCheckpointSource({
      ...base, rpcUrl: "https://user:password@remote.example/rpc",
    })).toThrow(/credentials/u);
    expect(() => createRpcFinalizedCheckpointSource({
      ...base, rpcUrl: "https://remote.example/rpc", expectedGenesisHash: "not-a-hash",
    })).toThrow(/genesis hash/u);
  });

  it.each([
    ["HTTP failure", response({ error: "private diagnostic" }, 502)],
    ["RPC error", response({ jsonrpc: "2.0", id: 1, error: { code: -1, message: "secret" } })],
    ["wrong response ID", response({ jsonrpc: "2.0", id: 2, result: GENESIS })],
    ["missing hash", response({ jsonrpc: "2.0", id: 1, result: null })],
  ])("fails closed on %s", async (_label, badResponse) => {
    const { fetchImpl } = fixture([badResponse]);
    const source = createRpcFinalizedCheckpointSource({
      networkId: "preview",
      rpcUrl: "https://rpc.preview.midnight.network",
      expectedGenesisHash: GENESIS,
      fetchImpl,
    });
    await expect(source.readCurrentFinalizedCheckpoint()).rejects.toThrow();
  });
});
