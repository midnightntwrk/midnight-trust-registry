import { beforeEach, describe, expect, it, vi } from "vitest";

import type { FinalizedTransaction } from "@midnight-ntwrk/midnight-js-protocol/ledger";
import { Duration, Effect, Stream } from "effect";

import { createPinnedLocalSubmissionProvider } from "../local-pinned-submission-provider.js";

const mocks = vi.hoisted(() => ({ make: vi.fn(), indexer: vi.fn() }));
vi.mock("@midnight-ntwrk/wallet-sdk-node-client/effect", () => ({
  PolkadotNodeClient: { make: mocks.make },
}));
vi.mock("@midnight-ntwrk/midnight-js-indexer-public-data-provider", () => ({
  indexerPublicDataProvider: mocks.indexer,
}));

const contractAddress = `0x${"a".repeat(64)}`;
const genesisHash = `0x${"b".repeat(64)}`;
const config = {
  nodeWsUrl: "ws://node:9944", indexerHttpUrl: "http://node:8088/graphql",
  indexerWsUrl: "ws://node:8088/graphql/ws", allowedHosts: ["node"],
  contractAddress, expectedGenesisHash: genesisHash,
};

describe("pinned local submission provider", () => {
  let observedGenesis: string;
  let sendMidnightTransaction: ReturnType<typeof vi.fn>;
  let getBlockHash: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    observedGenesis = genesisHash;
    mocks.indexer.mockReset();
    mocks.indexer.mockReturnValue({ queryContractState: vi.fn() });
    getBlockHash = vi.fn(async () => ({ toHex: () => observedGenesis }));
    sendMidnightTransaction = vi.fn(() => Stream.make({ _tag: "Finalized", txHash: "0x1234" }));
    mocks.make.mockReset();
    mocks.make.mockImplementation(() => Effect.succeed({
      ensureConnection: () => Effect.succeed(undefined),
      api: { rpc: { chain: { getBlockHash } } },
      sendMidnightTransaction,
    }));
  });

  it("rejects nonlocal endpoints and malformed deployment pins", () => {
    expect(() => createPinnedLocalSubmissionProvider({
      ...config, nodeWsUrl: "wss://public.example:9944",
    })).toThrow(/approved private host/u);
    expect(() => createPinnedLocalSubmissionProvider({
      ...config, indexerHttpUrl: "https://public.example/graphql",
    })).toThrow(/approved private host/u);
    expect(() => createPinnedLocalSubmissionProvider({
      ...config, expectedGenesisHash: `0x${"0".repeat(64)}`,
    })).toThrow(/nonzero genesis/u);
  });

  it("authenticates the exact provider instance against the live node genesis", async () => {
    const pinned = createPinnedLocalSubmissionProvider(config);
    await expect(pinned.readSubmissionProviderIdentity({
      midnightProvider: pinned.midnightProvider, publicDataProvider: pinned.publicDataProvider,
    } as never)).resolves.toEqual({ contractAddress, genesisHash });
    expect(mocks.indexer).toHaveBeenCalledWith(config.indexerHttpUrl, config.indexerWsUrl);
    expect(mocks.make).toHaveBeenCalledWith({
      nodeURL: new URL(config.nodeWsUrl), reconnectionTimeout: Duration.seconds(15),
    });
    expect(getBlockHash).toHaveBeenCalledWith(0);
    await expect(pinned.readSubmissionProviderIdentity({
      midnightProvider: { submitTx: vi.fn() }, publicDataProvider: pinned.publicDataProvider,
    } as never)).rejects.toThrow(/not using the pinned/u);
    await expect(pinned.readSubmissionProviderIdentity({
      midnightProvider: pinned.midnightProvider, publicDataProvider: { queryContractState: vi.fn() },
    } as never)).rejects.toThrow(/not using the pinned/u);
    expect(mocks.make).toHaveBeenCalledOnce();
  });

  it("rechecks genesis on the node connection used for submission", async () => {
    const pinned = createPinnedLocalSubmissionProvider(config);
    await pinned.readSubmissionProviderIdentity({
      midnightProvider: pinned.midnightProvider, publicDataProvider: pinned.publicDataProvider,
    } as never);
    observedGenesis = `0x${"c".repeat(64)}`;
    const tx = {
      identifiers: () => ["tx-issuer"], serialize: () => new Uint8Array([1, 2, 3]),
    } as unknown as FinalizedTransaction;
    await expect(pinned.midnightProvider.submitTx(tx)).rejects.toThrow(/genesis does not match/u);
    expect(sendMidnightTransaction).not.toHaveBeenCalled();
  });

  it("returns a Midnight identifier only after the node reports finality", async () => {
    const pinned = createPinnedLocalSubmissionProvider(config);
    const tx = {
      identifiers: () => ["tx-issuer"], serialize: () => new Uint8Array([1, 2, 3]),
    } as unknown as FinalizedTransaction;
    await expect(pinned.midnightProvider.submitTx(tx)).resolves.toBe("tx-issuer");
    expect(sendMidnightTransaction).toHaveBeenCalledOnce();
    expect(sendMidnightTransaction.mock.calls[0]?.[0]).toEqual(new Uint8Array([1, 2, 3]));
    sendMidnightTransaction.mockReturnValue(Stream.make({ _tag: "Submitted", txHash: "0x1234" }));
    await expect(pinned.midnightProvider.submitTx(tx)).rejects.toThrow(/did not finalize/u);
    expect(getBlockHash).toHaveBeenCalledTimes(2);
  });

  it("rejects transactions without an identifier before connecting", async () => {
    const pinned = createPinnedLocalSubmissionProvider(config);
    const tx = {
      identifiers: () => [], serialize: () => new Uint8Array([1]),
    } as unknown as FinalizedTransaction;
    await expect(pinned.midnightProvider.submitTx(tx)).rejects.toThrow(/no identifier/u);
    expect(mocks.make).not.toHaveBeenCalled();
  });
});
