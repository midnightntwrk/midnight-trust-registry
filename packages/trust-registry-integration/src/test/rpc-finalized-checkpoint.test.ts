import { describe, expect, it } from "vitest";

import {
  createLocalRpcFinalizedCheckpointSource,
  createRpcFinalizedCheckpointSource,
} from "../rpc-finalized-checkpoint.js";

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
  const calls: Array<{ url: string; method: string; params: unknown; redirect: RequestRedirect | undefined }> = [];
  let next = 0;
  const fetchImpl: typeof fetch = async (url, init) => {
    const body = JSON.parse(String(init?.body)) as { method: string; params: unknown };
    calls.push({ url: String(url), method: body.method, params: body.params, redirect: init?.redirect });
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
      { url: "https://rpc.preview.midnight.network/", method: "chain_getBlockHash", params: [0], redirect: "error" },
      { url: "https://rpc.preview.midnight.network/", method: "chain_getFinalizedHead", params: [], redirect: "error" },
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

  it("rejects oversized RPC responses even when the server omits or understates Content-Length", async () => {
    const oversized = JSON.stringify({ jsonrpc: "2.0", id: 1, result: GENESIS,
      padding: "x".repeat(8 * 1024) });
    for (const badResponse of [
      new Response(oversized, { headers: { "content-length": "1" } }),
      new Response(new ReadableStream({ start(controller) {
        controller.enqueue(new TextEncoder().encode(oversized));
        controller.close();
      } }), { headers: { "content-type": "application/json" } }),
    ]) {
      const source = createLocalRpcFinalizedCheckpointSource({
        rpcUrl: "http://node:9944", allowedHosts: ["node"],
        expectedGenesisHash: GENESIS, fetchImpl: fixture([badResponse]).fetchImpl,
      });
      await expect(source.readCurrentFinalizedCheckpoint()).rejects.toThrow(/size limit/u);
    }
  });

  it("rejects a declared oversized response before reading its body", async () => {
    let pulled = false;
    const body = new ReadableStream({ pull() { pulled = true; } }, { highWaterMark: 0 });
    const source = createLocalRpcFinalizedCheckpointSource({
      rpcUrl: "http://node:9944", allowedHosts: ["node"],
      expectedGenesisHash: GENESIS,
      fetchImpl: fixture([new Response(body, { headers: { "content-length": "8193" } })]).fetchImpl,
    });
    await expect(source.readCurrentFinalizedCheckpoint()).rejects.toThrow(/size limit/u);
    expect(pulled).toBe(false);
  });

  it("rejects malformed UTF-8 and invalid JSON from the finality endpoint", async () => {
    for (const bytes of [new Uint8Array([0xff]), new TextEncoder().encode("{not json")]) {
      const source = createLocalRpcFinalizedCheckpointSource({
        rpcUrl: "http://node:9944", allowedHosts: ["node"],
        expectedGenesisHash: GENESIS,
        fetchImpl: fixture([new Response(bytes)]).fetchImpl,
      });
      await expect(source.readCurrentFinalizedCheckpoint()).rejects.toThrow(/invalid JSON or UTF-8/u);
    }
  });

  it("pins the isolated local genesis before reading a finalized head", async () => {
    const { calls, fetchImpl } = fixture();
    const source = createLocalRpcFinalizedCheckpointSource({
      rpcUrl: "http://midnight-node:9944",
      allowedHosts: ["midnight-node", "midnight-indexer"],
      expectedGenesisHash: GENESIS,
      fetchImpl,
    });
    await expect(source.readCurrentFinalizedCheckpoint()).resolves.toEqual({
      networkId: "undeployed", blockHash: FINALIZED.slice(2),
    });
    expect(calls.map((call) => call.method)).toEqual(["chain_getBlockHash", "chain_getFinalizedHead"]);
    expect(calls.map((call) => call.redirect)).toEqual(["error", "error"]);
    const wrong = createLocalRpcFinalizedCheckpointSource({
      rpcUrl: "http://midnight-node:9944", allowedHosts: ["midnight-node"],
      expectedGenesisHash: `0x${"c".repeat(64)}`, fetchImpl: fixture().fetchImpl,
    });
    await expect(wrong.readCurrentFinalizedCheckpoint()).rejects.toThrow(/genesis hash mismatch/u);
  });

  it("refuses an RPC redirect instead of following it outside the local allowlist", async () => {
    const redirectedFetch: typeof fetch = async (_url, init) => {
      expect(init?.redirect).toBe("error");
      return new Response(null, { status: 307, headers: { location: "https://public.example/rpc" } });
    };
    const source = createLocalRpcFinalizedCheckpointSource({
      rpcUrl: "http://node:9944", allowedHosts: ["node"],
      expectedGenesisHash: GENESIS, fetchImpl: redirectedFetch,
    });
    await expect(source.readCurrentFinalizedCheckpoint()).rejects.toThrow(/request failed/u);
  });
});
