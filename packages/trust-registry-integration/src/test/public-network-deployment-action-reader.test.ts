import { beforeEach, describe, expect, it, vi } from "vitest";

import { createPublicNetworkDeploymentActionReader } from "../public-network-deployment-action-reader.js";

const mocks = vi.hoisted(() => ({
  indexerPublicDataProvider: vi.fn(),
  queryContractState: vi.fn(),
}));

vi.mock("@midnight-ntwrk/midnight-js-indexer-public-data-provider", () => ({
  indexerPublicDataProvider: mocks.indexerPublicDataProvider,
}));

const genesis = `0x${"a".repeat(64)}`;
const head = `0x${"b".repeat(64)}`;
const address = `0x${"c".repeat(64)}`;
const config = {
  networkId: "preview" as const,
  rpcUrl: "https://rpc.example.test/",
  indexerHttpUrl: "https://indexer.example.test/api/v4/graphql",
  indexerWsUrl: "wss://indexer.example.test/api/v4/graphql/ws",
  expectedGenesisHash: genesis,
};

describe("public network deployment action reader", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.indexerPublicDataProvider.mockReturnValue({ queryContractState: mocks.queryContractState });
    mocks.queryContractState.mockResolvedValue(null);
  });

  it("checks the pinned node before querying the indexer at its finalized hash", async () => {
    const fetchImpl = vi.fn(async (_url: URL, init: RequestInit) => {
      const request = JSON.parse(init.body as string) as { method: string };
      return new Response(JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        result: request.method === "chain_getBlockHash" ? genesis : head,
      }), { status: 200 });
    }) as unknown as typeof fetch;
    const reader = await createPublicNetworkDeploymentActionReader({ ...config, fetchImpl });

    expect(await reader.readCurrentFinalizedActionState(address)).toBeNull();
    expect(mocks.indexerPublicDataProvider).toHaveBeenCalledWith(
      config.indexerHttpUrl,
      config.indexerWsUrl,
    );
    expect(fetchImpl).toHaveBeenCalledTimes(2);
    expect(mocks.queryContractState).toHaveBeenCalledWith(
      address.slice(2),
      { type: "blockHash", blockHash: head.slice(2) },
    );
  });

  it("never queries the indexer when the genesis pin does not match", async () => {
    const fetchImpl = vi.fn(async () => new Response(JSON.stringify({
      jsonrpc: "2.0", id: 1, result: head,
    }), { status: 200 })) as unknown as typeof fetch;
    const reader = await createPublicNetworkDeploymentActionReader({ ...config, fetchImpl });

    await expect(reader.readCurrentFinalizedActionState(address))
      .rejects.toThrow("genesis hash mismatch");
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(mocks.queryContractState).not.toHaveBeenCalled();
  });

  it("rejects remote plaintext and credential-bearing indexer endpoints", async () => {
    await expect(createPublicNetworkDeploymentActionReader({
      ...config, indexerHttpUrl: "http://indexer.example.test/graphql",
    })).rejects.toThrow("Indexer endpoint must use https:");
    await expect(createPublicNetworkDeploymentActionReader({
      ...config, indexerWsUrl: "ws://indexer.example.test/graphql",
    })).rejects.toThrow("Indexer endpoint must use wss:");
    await expect(createPublicNetworkDeploymentActionReader({
      ...config, indexerHttpUrl: "https://user:password@indexer.example.test/graphql",
    })).rejects.toThrow("must not contain credentials");
    expect(mocks.indexerPublicDataProvider).not.toHaveBeenCalled();
  });
});
