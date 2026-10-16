import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { sampleSigningKey } from "@midnight-ntwrk/compact-runtime";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { bytes32Commitment, bytes32Hex } from "@midnight-ntwrk/trust-registry-client";
import { deriveJubjubPublicKeyFromSeed } from "@midnight-ntwrk/trust-registry-contract";
import { TrustRegistrySimulator } from "@midnight-ntwrk/trust-registry-contract/testing";

import { deployPublicTrustRegistry } from "../public-network-deployment.js";

const mocks = vi.hoisted(() => ({
  deployContract: vi.fn(),
  indexerPublicDataProvider: vi.fn(),
  queryContractState: vi.fn(),
}));

vi.mock("@midnight-ntwrk/midnight-js-contracts", () => ({ deployContract: mocks.deployContract }));
vi.mock("@midnight-ntwrk/midnight-js-indexer-public-data-provider", () => ({
  indexerPublicDataProvider: mocks.indexerPublicDataProvider,
}));

const address = "a".repeat(64);
const genesis = `0x${"b".repeat(64)}`;
const finalized = `0x${"c".repeat(64)}`;
const registryId = "registry:midnight:deployment-test";
const bootstrap = {
  registryId,
  registryDidCommitment: bytes32Commitment("did:midnight:preview:registry"),
  governancePolicyCommitment: bytes32Commitment("policy:deployment-test"),
  maintainerId: bytes32Commitment("maintainer:deployment-test"),
  maintainerDidCommitment: bytes32Commitment("did:midnight:preview:maintainer"),
  maintainerKeyId: bytes32Commitment("maintainer:deployment-test#key-1"),
  maintainerPublicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(19)),
  maintainerThreshold: 1n,
};
const fetchImpl = vi.fn(async (_url: URL, init: RequestInit) => {
  const request = JSON.parse(init.body as string) as { method: string };
  return new Response(JSON.stringify({
    jsonrpc: "2.0", id: 1,
    result: request.method === "chain_getBlockHash" ? genesis : finalized,
  }), { status: 200 });
}) as unknown as typeof fetch;
const network = {
  networkId: "preview" as const,
  rpcUrl: "https://rpc.example.test/",
  indexerHttpUrl: "https://indexer.example.test/graphql",
  indexerWsUrl: "wss://indexer.example.test/graphql/ws",
  expectedGenesisHash: genesis,
  fetchImpl,
};
const receipt = {
  contractAddress: address,
  txId: "deploy-tx-id",
  blockHash: finalized.slice(2),
  blockHeight: 12,
};
let observedPolicyOverride: Uint8Array | null = null;
let observedRegistryDidOverride: Uint8Array | null = null;
let observedMaintainerDidOverride: Uint8Array | null = null;

beforeEach(() => {
  vi.clearAllMocks();
  observedPolicyOverride = null;
  observedRegistryDidOverride = null;
  observedMaintainerDidOverride = null;
  setNetworkId("preview");
  mocks.indexerPublicDataProvider.mockReturnValue({ queryContractState: mocks.queryContractState });
  mocks.deployContract.mockImplementation(async (_providers, options) => {
    const simulator = new TrustRegistrySimulator({
      registryId: options.args[0],
      registryDidCommitment: observedRegistryDidOverride ?? options.args[1],
      governancePolicyCommitment: observedPolicyOverride ?? options.args[2],
      maintainerId: options.args[3],
      maintainerDidCommitment: observedMaintainerDidOverride ?? options.args[4],
      maintainerKeyId: options.args[5],
      maintainerPublicKey: options.args[6],
      maintainerThreshold: options.args[7],
      networkIdCommitment: options.args[8],
      contractAddress: address,
    });
    mocks.queryContractState.mockResolvedValue({ data: simulator.circuitContext.currentQueryContext.state });
    return { deployTxData: { public: receipt, private: { neverSerialize: true } } };
  });
});

afterEach(() => setNetworkId("undeployed"));

const deploy = (overrides: Partial<typeof network> = {}, input = bootstrap) =>
  deployPublicTrustRegistry({
    network: { ...network, ...overrides },
    bootstrap: input,
    providers: {} as never,
    contractMaintenanceSigningKey: sampleSigningKey(),
  });

describe("public Trust Registry deployment", () => {
  it("submits constructor-bound inputs and verifies finalized readback without leaking private deploy data", async () => {
    const result = await deploy();
    expect(mocks.deployContract).toHaveBeenCalledTimes(1);
    expect(mocks.deployContract.mock.calls[0]?.[1]).toMatchObject({
      privateStateId: "trustRegistryPrivateState",
      initialPrivateState: {},
      args: [
        bytes32Commitment(registryId),
        bootstrap.registryDidCommitment,
        bootstrap.governancePolicyCommitment,
        bootstrap.maintainerId,
        bootstrap.maintainerDidCommitment,
        bootstrap.maintainerKeyId,
        bootstrap.maintainerPublicKey,
        1n,
        bytes32Commitment("preview"),
      ],
    });
    expect(mocks.queryContractState).toHaveBeenCalledWith(address, {
      type: "blockHash", blockHash: finalized.slice(2),
    });
    expect(result.receipt).toEqual({
      networkId: "preview", contractAddress: `0x${address}`,
      txId: receipt.txId, blockHash: finalized, blockHeight: 12,
    });
    expect(result.readback.status).toBe("verified");
    expect(JSON.stringify(result, (_key, value: unknown) =>
      typeof value === "bigint" ? value.toString() : value,
    )).not.toContain("neverSerialize");
    if (result.readback.status === "verified") {
      expect(result.readback.state.registryIdCommitment).toBe(bytes32Hex(bytes32Commitment(registryId)));
      expect(result.readback.state.finalizedBlockHash).toBe(finalized);
      expect(result.readback.state.registryDidCommitment).toBe(bytes32Hex(bootstrap.registryDidCommitment));
      expect(result.readback.state.bootstrapMaintainer?.didCommitment)
        .toBe(bytes32Hex(bootstrap.maintainerDidCommitment));
    }
  });

  it("refuses wrong SDK network, genesis, or indexer endpoint before deployment", async () => {
    setNetworkId("preprod");
    await expect(deploy()).rejects.toThrow("network does not match");
    setNetworkId("preview");
    await expect(deploy({ expectedGenesisHash: `0x${"d".repeat(64)}` }))
      .rejects.toThrow("genesis hash mismatch");
    await expect(deploy({ indexerHttpUrl: "http://indexer.example.test/graphql" }))
      .rejects.toThrow("Indexer endpoint must use https:");
    expect(mocks.deployContract).not.toHaveBeenCalled();
  });

  it("returns a public receipt when the indexer has not caught up, without suggesting redeployment", async () => {
    mocks.queryContractState.mockResolvedValueOnce(null);
    const result = await deploy();
    expect(result.receipt.txId).toBe(receipt.txId);
    expect(result.readback).toEqual({ status: "pending" });
  });

  it("retains the receipt when finalized readback fails after submission", async () => {
    mocks.queryContractState.mockRejectedValueOnce(new Error("indexer unavailable"));
    const result = await deploy();
    expect(result.receipt.txId).toBe(receipt.txId);
    expect(result.readback).toEqual({ status: "unavailable" });
  });

  it("does not mark substituted finalized constructor state as verified", async () => {
    observedPolicyOverride = bytes32Commitment("different-policy");
    const result = await deploy();
    expect(result.receipt.txId).toBe(receipt.txId);
    expect(result.readback.status).toBe("mismatch");
  });

  it("rejects a substituted registry DID or bootstrap maintainer DID in finalized state", async () => {
    observedRegistryDidOverride = bytes32Commitment("did:midnight:preview:other-registry");
    expect((await deploy()).readback.status).toBe("mismatch");
    observedRegistryDidOverride = null;
    observedMaintainerDidOverride = bytes32Commitment("did:midnight:preview:other-maintainer");
    expect((await deploy()).readback.status).toBe("mismatch");
  });
});
