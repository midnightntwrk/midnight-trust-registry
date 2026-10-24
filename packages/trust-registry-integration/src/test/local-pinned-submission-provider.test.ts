import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import type { FinalizedTransaction } from "@midnight-ntwrk/midnight-js-protocol/ledger";

import { createPinnedLocalSubmissionProvider } from "../local-pinned-submission-provider.js";

const mocks = vi.hoisted(() => ({
  create: vi.fn(), connect: vi.fn(), disconnect: vi.fn(), indexer: vi.fn(),
}));
vi.mock("@polkadot/api", () => ({
  ApiPromise: { create: mocks.create },
  WsProvider: class {
    isConnected = true;
    constructor(readonly endpoint: string, readonly autoConnectMs: number | false) {}
    connect = mocks.connect;
    disconnect = mocks.disconnect;
  },
}));
vi.mock("@midnight-ntwrk/midnight-js-indexer-public-data-provider", () => ({
  indexerPublicDataProvider: mocks.indexer,
}));

const contractAddress = `0x${"a".repeat(64)}`;
let genesisHash = `0x${"b".repeat(64)}`;
let config = {
  nodeWsUrl: "ws://node:9944", indexerHttpUrl: "http://node:8088/graphql",
  indexerWsUrl: "ws://node:8088/graphql/ws", allowedHosts: ["node"],
  contractAddress, expectedGenesisHash: genesisHash,
};
let setupNumber = 0;
const transaction = {
  identifiers: () => ["tx-issuer"], serialize: () => new Uint8Array([1, 2, 3]),
} as unknown as FinalizedTransaction;

describe("pinned local submission provider", () => {
  let observedGenesis: string;
  let indexedGenesis: string;
  let sendMnTransaction: ReturnType<typeof vi.fn>;
  let getBlockHash: ReturnType<typeof vi.fn>;
  let watchForTxData: ReturnType<typeof vi.fn>;
  let queryContractState: ReturnType<typeof vi.fn>;
  let connected: boolean;

  beforeEach(() => {
    genesisHash = `0x${(++setupNumber).toString(16).padStart(64, "b")}`;
    config = { ...config, expectedGenesisHash: genesisHash };
    observedGenesis = genesisHash;
    indexedGenesis = genesisHash.slice(2);
    connected = true;
    vi.stubGlobal("fetch", vi.fn(async () => Response.json({
      data: { block: { height: 0, hash: indexedGenesis } },
    })));
    watchForTxData = vi.fn(async () => ({ txId: "tx-issuer", status: "SucceedEntirely" }));
    queryContractState = vi.fn(async () => null);
    mocks.indexer.mockReset().mockReturnValue({ queryContractState, watchForTxData });
    mocks.connect.mockReset().mockResolvedValue(undefined);
    mocks.disconnect.mockReset().mockResolvedValue(undefined);
    getBlockHash = vi.fn(async () => ({ toHex: () => observedGenesis }));
    sendMnTransaction = vi.fn(() => ({ send: async (callback: (result: unknown) => void) => {
      callback({ status: { isFinalized: true } });
      return vi.fn();
    } }));
    mocks.create.mockReset().mockImplementation(async () => ({
      get isConnected() { return connected; },
      rpc: { chain: { getBlockHash } },
      tx: { midnight: { sendMnTransaction } },
      disconnect: mocks.disconnect,
    }));
  });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("rejects nonlocal endpoints and malformed pins", () => {
    expect(() => createPinnedLocalSubmissionProvider({
      ...config, nodeWsUrl: "wss://public.example:9944",
    })).toThrow(/approved private host/u);
    expect(() => createPinnedLocalSubmissionProvider({
      ...config, expectedGenesisHash: `0x${"0".repeat(64)}`,
    })).toThrow(/nonzero genesis/u);
    expect(() => createPinnedLocalSubmissionProvider({
      ...config, contractAddress: `0x${"0".repeat(64)}`,
    })).toThrow(/contract address/u);
  });

  it("authenticates the exact provider pair against node and indexer genesis", async () => {
    const pinned = createPinnedLocalSubmissionProvider(config);
    await expect(pinned.readSubmissionProviderIdentity({
      midnightProvider: pinned.midnightProvider, publicDataProvider: pinned.publicDataProvider,
    } as never)).resolves.toEqual({ contractAddress, genesisHash });
    expect(mocks.create).toHaveBeenCalledWith(expect.objectContaining({
      provider: expect.objectContaining({ endpoint: new URL(config.nodeWsUrl).toString(), autoConnectMs: false }),
    }));
    expect(getBlockHash).toHaveBeenCalledWith(0);
    expect(mocks.disconnect).toHaveBeenCalled();
    await expect(pinned.readSubmissionProviderIdentity({
      midnightProvider: { submitTx: vi.fn() }, publicDataProvider: pinned.publicDataProvider,
    } as never)).rejects.toThrow(/not using the pinned/u);
  });

  it("bounds the SDK indexer wait while preserving other provider methods", async () => {
    const pinned = createPinnedLocalSubmissionProvider({ ...config, indexerWatchDeadlineMs: 10 });
    const sibling = createPinnedLocalSubmissionProvider(config);
    await expect(pinned.publicDataProvider.queryContractState(contractAddress)).resolves.toBeNull();
    expect(queryContractState).toHaveBeenCalledWith(contractAddress);
    await expect(pinned.publicDataProvider.watchForTxData("tx-issuer"))
      .resolves.toMatchObject({ txId: "tx-issuer" });
    expect(watchForTxData).toHaveBeenCalledWith("tx-issuer");
    watchForTxData.mockImplementation(() => new Promise(() => undefined));
    await expect(pinned.publicDataProvider.watchForTxData("tx-stuck"))
      .rejects.toThrow(/reconcile before retry/u);
    expect(watchForTxData).toHaveBeenCalledWith("tx-stuck");
    expect(() => pinned.publicDataProvider.queryContractState(contractAddress)).toThrow(/restart/u);
    expect(() => sibling.publicDataProvider.queryContractState(contractAddress)).toThrow(/restart/u);
    expect(() => createPinnedLocalSubmissionProvider({ ...config, nodeWsUrl: "ws://node:9945" }))
      .toThrow(/restart/u);
    expect(() => createPinnedLocalSubmissionProvider({
      ...config, contractAddress: `0x${"d".repeat(64)}`,
    })).not.toThrow();
    await expect(pinned.publicDataProvider.watchForTxData("tx-other")).rejects.toThrow(/restart/u);
    await expect(pinned.midnightProvider.submitTx(transaction)).rejects.toThrow(/restart/u);
    expect(() => createPinnedLocalSubmissionProvider(config)).toThrow(/restart/u);
    await expect(pinned.readSubmissionProviderIdentity({
      midnightProvider: pinned.midnightProvider, publicDataProvider: pinned.publicDataProvider,
    } as never)).rejects.toThrow(/restart/u);
    expect(watchForTxData).toHaveBeenCalledTimes(2);
    expect(sendMnTransaction).not.toHaveBeenCalled();
    expect(() => createPinnedLocalSubmissionProvider({ ...config, indexerWatchDeadlineMs: 120_001 }))
      .toThrow(/deadline is invalid/u);
  });

  it("refuses an indexer or node on another genesis", async () => {
    const pinned = createPinnedLocalSubmissionProvider(config);
    indexedGenesis = "c".repeat(64);
    await expect(pinned.readSubmissionProviderIdentity({
      midnightProvider: pinned.midnightProvider, publicDataProvider: pinned.publicDataProvider,
    } as never)).rejects.toThrow(/indexer genesis does not match/u);
    observedGenesis = `0x${"c".repeat(64)}`;
    await expect(pinned.midnightProvider.submitTx(transaction)).rejects.toThrow(/genesis does not match/u);
    expect(sendMnTransaction).not.toHaveBeenCalled();
    observedGenesis = genesisHash;
    await expect(pinned.midnightProvider.submitTx(transaction)).resolves.toBe("tx-issuer");
  });

  it("returns the Midnight identifier only after successful finality", async () => {
    const pinned = createPinnedLocalSubmissionProvider(config);
    await expect(pinned.midnightProvider.submitTx(transaction)).resolves.toBe("tx-issuer");
    expect(sendMnTransaction).toHaveBeenCalledWith("0x010203");
    sendMnTransaction.mockImplementation(() => ({ send: async (callback: (result: unknown) => void) => {
      callback({ status: { isFinalized: true }, dispatchError: "bad origin" });
      return vi.fn();
    } }));
    await expect(pinned.midnightProvider.submitTx(transaction)).rejects.toThrow(/dispatch error/u);
  });

  it("disconnects on a hung connection without broadcasting later", async () => {
    mocks.connect.mockImplementation(() => new Promise(() => undefined));
    const pinned = createPinnedLocalSubmissionProvider({ ...config, submissionDeadlineMs: 10 });
    await expect(pinned.midnightProvider.submitTx(transaction)).rejects.toThrow(/deadline/u);
    expect(mocks.disconnect).toHaveBeenCalled();
    expect(sendMnTransaction).not.toHaveBeenCalled();
  });

  it("treats a broadcast without a finality callback as ambiguous", async () => {
    sendMnTransaction.mockImplementation(() => ({ send: async () => vi.fn() }));
    const pinned = createPinnedLocalSubmissionProvider({ ...config, submissionDeadlineMs: 10 });
    const sibling = createPinnedLocalSubmissionProvider(config);
    await expect(pinned.midnightProvider.submitTx(transaction)).rejects.toThrow(/deadline/u);
    expect(sendMnTransaction).toHaveBeenCalledOnce();
    expect(mocks.disconnect).toHaveBeenCalled();
    await expect(pinned.midnightProvider.submitTx(transaction)).rejects.toThrow(/restart/u);
    await expect(sibling.midnightProvider.submitTx(transaction)).rejects.toThrow(/restart/u);
    expect(() => createPinnedLocalSubmissionProvider(config)).toThrow(/restart/u);
    expect(sendMnTransaction).toHaveBeenCalledOnce();
  });

  it("does not broadcast a connecting submission after another call poisons the instance", async () => {
    let releaseGenesis: (() => void) | undefined;
    const genesisGate = new Promise<void>((resolve) => { releaseGenesis = resolve; });
    getBlockHash.mockImplementation(async () => {
      await genesisGate;
      return { toHex: () => genesisHash };
    });
    watchForTxData.mockImplementation(() => new Promise(() => undefined));
    const pinned = createPinnedLocalSubmissionProvider({
      ...config, indexerWatchDeadlineMs: 10, submissionDeadlineMs: 1_000,
    });
    const pendingSubmission = pinned.midnightProvider.submitTx(transaction);
    await vi.waitFor(() => { expect(getBlockHash).toHaveBeenCalledOnce(); });
    await expect(pinned.publicDataProvider.watchForTxData("tx-stuck"))
      .rejects.toThrow(/reconcile before retry/u);
    releaseGenesis?.();
    await expect(pendingSubmission).rejects.toThrow(/restart/u);
    expect(sendMnTransaction).not.toHaveBeenCalled();
  });

  it("does not broadcast after connection loss or a missing identifier", async () => {
    const pinned = createPinnedLocalSubmissionProvider(config);
    connected = false;
    await expect(pinned.midnightProvider.submitTx(transaction)).rejects.toThrow(/disconnected/u);
    expect(sendMnTransaction).not.toHaveBeenCalled();
    await expect(pinned.midnightProvider.submitTx({
      identifiers: () => [], serialize: () => new Uint8Array([1]),
    } as unknown as FinalizedTransaction)).rejects.toThrow(/no identifier/u);
  });
});
