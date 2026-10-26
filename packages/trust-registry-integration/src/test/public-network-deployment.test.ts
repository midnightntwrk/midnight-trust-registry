import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";

import { sampleSigningKey, signatureVerifyingKey } from "@midnight-ntwrk/compact-runtime";
import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { bytes32Commitment, bytes32Hex } from "@midnight-ntwrk/trust-registry-client";
import { deriveJubjubPublicKeyFromSeed, TrustRegistryContract, trustRegistryWitnesses } from "@midnight-ntwrk/trust-registry-contract";
import { TrustRegistrySimulator } from "@midnight-ntwrk/trust-registry-contract/testing";

import {
  deployLocalTrustRegistry,
  deployLocalTrustRegistryStaged,
  deployPublicTrustRegistry,
  readPostDeploymentLocalTrustRegistry,
  readPostDeploymentPublicTrustRegistry,
  stagedBootstrapContract,
} from "../public-network-deployment.js";

const mocks = vi.hoisted(() => ({
  deployContract: vi.fn(),
  indexerPublicDataProvider: vi.fn(),
  queryContractState: vi.fn(),
  verifyInstalledVerifierKeyAssets: vi.fn(),
}));

vi.mock("@midnight-ntwrk/midnight-js-contracts", () => ({ deployContract: mocks.deployContract }));
vi.mock("@midnight-ntwrk/midnight-js-indexer-public-data-provider", () => ({
  indexerPublicDataProvider: mocks.indexerPublicDataProvider,
}));
vi.mock("../verifier-asset-preflight.js", () => ({
  verifyInstalledVerifierKeyAssets: mocks.verifyInstalledVerifierKeyAssets,
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
const maintenanceSigningKey = sampleSigningKey();
const circuitNames = Object.keys(new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits);
const verifierKeys = Object.fromEntries(circuitNames.map((name) => [name, Buffer.from(`verifier:${name}`)]));
const releaseManifest = {
  format: "tr-release-candidate-manifest-v2" as const,
  verifierKeySha256: Object.fromEntries(circuitNames.map((name) => [
    name, createHash("sha256").update(verifierKeys[name]!).digest("hex"),
  ])),
};
let observedPolicyOverride: Uint8Array | null = null;
let observedRegistryDidOverride: Uint8Array | null = null;
let observedMaintainerDidOverride: Uint8Array | null = null;
let observedVerifierKeyOverride: Uint8Array | null = null;
let observedMissingOperation = false;
let observedExtraOperation = false;
let observedDuplicateOperation = false;
let observedEmptyVerifierKey = false;
let observedAuthorityOverride: string | null = null;
let observedAuthorityCommittee: string[] | null = null;
let observedAuthorityThreshold = 1;
let observedAuthorityCounter = 0n;
let observedCircuitNames = circuitNames;

beforeEach(() => {
  vi.clearAllMocks();
  observedPolicyOverride = null;
  observedRegistryDidOverride = null;
  observedMaintainerDidOverride = null;
  observedVerifierKeyOverride = null;
  observedMissingOperation = false;
  observedExtraOperation = false;
  observedDuplicateOperation = false;
  observedEmptyVerifierKey = false;
  observedAuthorityOverride = null;
  observedAuthorityCommittee = null;
  observedAuthorityThreshold = 1;
  observedAuthorityCounter = 0n;
  observedCircuitNames = circuitNames;
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
    mocks.queryContractState.mockImplementation(async () => ({
      data: simulator.circuitContext.currentQueryContext.state,
      operations: () => observedMissingOperation ? observedCircuitNames.slice(1)
        : observedExtraOperation ? [...observedCircuitNames, "__proto__"]
          : observedDuplicateOperation ? [...observedCircuitNames, observedCircuitNames[0]] : observedCircuitNames,
      operation: (name: string) => ({
        verifierKey: name === circuitNames[0] && observedEmptyVerifierKey ? Buffer.alloc(0)
          : name === "__proto__" ? Buffer.from("unexpected-verifier-key")
          : name === circuitNames[0] && observedVerifierKeyOverride !== null
            ? observedVerifierKeyOverride : verifierKeys[name],
      }),
      maintenanceAuthority: {
        committee: observedAuthorityCommittee
          ?? [observedAuthorityOverride ?? signatureVerifyingKey(options.signingKey)],
        threshold: observedAuthorityThreshold,
        counter: observedAuthorityCounter,
      },
    }));
    return { deployTxData: { public: receipt, private: { neverSerialize: true } } };
  });
});

afterEach(() => setNetworkId("undeployed"));

const deploy = (overrides: Partial<typeof network> = {}, input = bootstrap, manifest = releaseManifest) =>
  deployPublicTrustRegistry({
    network: { ...network, ...overrides },
    bootstrap: input,
    releaseManifest: manifest,
    providers: {} as never,
    contractMaintenanceSigningKey: maintenanceSigningKey,
  });

const localNetwork = {
  networkId: "undeployed" as const,
  rpcUrl: "http://node:9944",
  indexerHttpUrl: "http://indexer:8080/graphql",
  indexerWsUrl: "ws://indexer:8080/graphql/ws",
  expectedGenesisHash: genesis,
  allowedHosts: ["node", "indexer"],
  fetchImpl,
};
const deployLocal = (overrides: Partial<typeof localNetwork> = {}) => deployLocalTrustRegistry({
  network: { ...localNetwork, ...overrides },
  bootstrap: {
    ...bootstrap,
    registryDidCommitment: bytes32Commitment("did:midnight:undeployed:registry"),
    maintainerDidCommitment: bytes32Commitment("did:midnight:undeployed:maintainer"),
  },
  releaseManifest,
  providers: {} as never,
  contractMaintenanceSigningKey: maintenanceSigningKey,
});

describe("isolated local Trust Registry deployment", () => {
  it("stages only the approved initial verifier key and leaves release gates pending", async () => {
    setNetworkId("undeployed");
    const initialVerifierKeyName = circuitNames[0]!;
    observedCircuitNames = [initialVerifierKeyName];
    const staged = stagedBootstrapContract(initialVerifierKeyName);
    expect(Object.keys(new staged(trustRegistryWitnesses).provableCircuits)).toEqual([initialVerifierKeyName]);
    expect(Object.keys(new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits))
      .toHaveLength(circuitNames.length);
    const result = await deployLocalTrustRegistryStaged({
      network: localNetwork,
      bootstrap: {
        ...bootstrap,
        registryDidCommitment: bytes32Commitment("did:midnight:undeployed:registry"),
        maintainerDidCommitment: bytes32Commitment("did:midnight:undeployed:maintainer"),
      },
      releaseManifest,
      providers: {} as never,
      contractMaintenanceSigningKey: maintenanceSigningKey,
      initialVerifierKeyName,
    });
    expect(result.readback.status).toBe("staged-bootstrap-pending");
    if (result.readback.status === "staged-bootstrap-pending") {
      expect(result.readback.state.verifierKeySha256).toEqual({
        [initialVerifierKeyName]: releaseManifest.verifierKeySha256[initialVerifierKeyName],
      });
    }
    expect(() => stagedBootstrapContract("notAReleaseCircuit"))
      .toThrow(/release-catalog circuit/u);
  });

  it("rejects changed installed verifier assets before submitting", async () => {
    setNetworkId("undeployed");
    mocks.verifyInstalledVerifierKeyAssets.mockRejectedValueOnce(new Error("verifier mismatch"));
    await expect(deployLocal()).rejects.toThrow(/verifier mismatch/u);
    expect(mocks.deployContract).not.toHaveBeenCalled();
  });
  it("deploys with the undeployed domain and reads back finalized constructor and key hashes", async () => {
    setNetworkId("undeployed");
    const result = await deployLocal();
    expect(mocks.deployContract).toHaveBeenCalledOnce();
    expect(mocks.deployContract.mock.calls[0]?.[1].args[8]).toEqual(bytes32Commitment("undeployed"));
    expect(result.receipt.networkId).toBe("undeployed");
    expect(result.readback.status).toBe("unsafe-maintenance-authority");
    if (result.readback.status === "unsafe-maintenance-authority") {
      expect(result.readback.state.networkId).toBe("undeployed");
      expect(result.readback.state.verifierKeySha256).toEqual(releaseManifest.verifierKeySha256);
    }
    expect(mocks.indexerPublicDataProvider).toHaveBeenCalledWith(
      "http://indexer:8080/graphql", "ws://indexer:8080/graphql/ws",
    );
  });

  it("rejects wrong genesis, unsafe endpoints, and public network relabeling before submit", async () => {
    setNetworkId("undeployed");
    await expect(deployLocal({ expectedGenesisHash: `0x${"d".repeat(64)}` }))
      .rejects.toThrow(/genesis hash mismatch/u);
    await expect(deployLocal({ rpcUrl: "http://public.example:9944" }))
      .rejects.toThrow(/allowlist/u);
    await expect(deployLocal({ indexerHttpUrl: "http://public.example/graphql" }))
      .rejects.toThrow(/allowlist/u);
    await expect(deployLocal({ indexerWsUrl: "ws://public.example/graphql/ws" }))
      .rejects.toThrow(/allowlist/u);
    await expect(deployLocal({ rpcUrl: "ws://node:9944" }))
      .rejects.toThrow(/allowlist/u);
    await expect(deployLocal({ networkId: "preprod" as never }))
      .rejects.toThrow(/standalone network profile/u);
    setNetworkId("preprod");
    await expect(deployLocal()).rejects.toThrow(/network does not match/u);
    await expect(deploy({ networkId: "undeployed" as never }))
      .rejects.toThrow(/Unsupported public Midnight network/u);
    expect(mocks.deployContract).not.toHaveBeenCalled();
  });

  it("keeps local post-deployment readback on the local reader and rejects SDK relabeling", async () => {
    setNetworkId("undeployed");
    const deployed = await deployLocal();
    const localBootstrap = {
      ...bootstrap,
      registryDidCommitment: bytes32Commitment("did:midnight:undeployed:registry"),
      maintainerDidCommitment: bytes32Commitment("did:midnight:undeployed:maintainer"),
    };
    const readback = () => readPostDeploymentLocalTrustRegistry({
      network: localNetwork,
      receipt: deployed.receipt,
      bootstrap: localBootstrap,
      releaseManifest,
      governance: {
        policyCommitment: localBootstrap.governancePolicyCommitment,
        policyVersion: 1n, actionSequence: 1n,
        maintainerThreshold: 1n, activeMaintainerCount: 1n,
      },
      maintenancePolicy: { mode: "immutable" },
    });
    expect((await readback()).status).toBe("unsafe-maintenance-authority");
    observedAuthorityCommittee = [];
    observedAuthorityCounter = 1n;
    expect((await readback()).status).toBe("verified");
    setNetworkId("preprod");
    await expect(readback()).rejects.toThrow(/standalone network profile/u);
    await expect(readPostDeploymentPublicTrustRegistry({
      network: { ...network, networkId: "preprod" },
      receipt: deployed.receipt,
      bootstrap: localBootstrap,
      releaseManifest,
      governance: {
        policyCommitment: localBootstrap.governancePolicyCommitment,
        policyVersion: 1n, actionSequence: 1n,
        maintainerThreshold: 1n, activeMaintainerCount: 1n,
      },
      maintenancePolicy: { mode: "immutable" },
    })).rejects.toThrow(/receipt does not match/u);
  });
});

describe("public Trust Registry deployment", () => {
  it("submits constructor-bound inputs but does not approve the initial single-key authority", async () => {
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
    expect(mocks.queryContractState).toHaveBeenCalledTimes(1);
    expect(result.receipt).toEqual({
      networkId: "preview", contractAddress: `0x${address}`,
      txId: receipt.txId, blockHash: finalized, blockHeight: 12,
    });
    expect(result.readback.status).toBe("unsafe-maintenance-authority");
    expect(JSON.stringify(result, (_key, value: unknown) =>
      typeof value === "bigint" ? value.toString() : value,
    )).not.toContain("neverSerialize");
    if (result.readback.status === "unsafe-maintenance-authority") {
      expect(result.readback.state.registryIdCommitment).toBe(bytes32Hex(bytes32Commitment(registryId)));
      expect(result.readback.state.finalizedBlockHash).toBe(finalized);
      expect(result.readback.state.registryDidCommitment).toBe(bytes32Hex(bootstrap.registryDidCommitment));
      expect(result.readback.state.bootstrapMaintainer?.didCommitment)
        .toBe(bytes32Hex(bootstrap.maintainerDidCommitment));
      expect(result.readback.state.verifierKeySha256).toEqual(releaseManifest.verifierKeySha256);
      expect(result.readback.state.maintenanceAuthority).toEqual({
        committee: [`0x${signatureVerifyingKey(maintenanceSigningKey)}`], threshold: 1, counter: 0n,
      });
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

  it("rejects an unsatisfiable bootstrap quorum before contacting the network", async () => {
    await expect(deploy({}, { ...bootstrap, maintainerThreshold: 2n }))
      .rejects.toThrow("Bootstrap maintainer threshold must be one");
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(mocks.deployContract).not.toHaveBeenCalled();
  });

  it("rejects an incomplete release verifier-key catalog before contacting the network", async () => {
    const incomplete = { ...releaseManifest, verifierKeySha256: { [circuitNames[0]!]: releaseManifest.verifierKeySha256[circuitNames[0]!]! } };
    await expect(deploy({}, bootstrap, incomplete)).rejects.toThrow(/invalid or incomplete verifier-key catalog/u);
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(mocks.deployContract).not.toHaveBeenCalled();
  });

  it.each([
    { format: "wrong", verifierKeySha256: releaseManifest.verifierKeySha256 },
    { format: releaseManifest.format, verifierKeySha256: null },
    { format: releaseManifest.format, verifierKeySha256: [] },
    { format: releaseManifest.format, verifierKeySha256: { ...releaseManifest.verifierKeySha256, extra: "a".repeat(64) } },
    { format: releaseManifest.format, verifierKeySha256: {
      ...releaseManifest.verifierKeySha256, [circuitNames[0]!]: "A".repeat(64),
    } },
    { format: releaseManifest.format, verifierKeySha256: {
      ...releaseManifest.verifierKeySha256, [circuitNames[0]!]: "a".repeat(63),
    } },
  ])("rejects malformed release manifest %# before contacting the network", async (manifest) => {
    await expect(deploy({}, bootstrap, manifest as typeof releaseManifest))
      .rejects.toThrow(/invalid or incomplete verifier-key catalog/u);
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(mocks.deployContract).not.toHaveBeenCalled();
  });

  it("does not verify against a release manifest with a substituted key hash", async () => {
    const name = circuitNames[0]!;
    const substituted = {
      ...releaseManifest,
      verifierKeySha256: { ...releaseManifest.verifierKeySha256, [name]: "a".repeat(64) },
    };
    expect((await deploy({}, bootstrap, substituted)).readback.status).toBe("mismatch");
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

  it("does not verify a replaced or missing finalized verifier key", async () => {
    observedVerifierKeyOverride = Buffer.from("substituted-verifier-key");
    expect((await deploy()).readback.status).toBe("mismatch");
    observedVerifierKeyOverride = null;
    observedMissingOperation = true;
    expect((await deploy()).readback.status).toBe("mismatch");
    observedMissingOperation = false;
    observedExtraOperation = true;
    expect((await deploy()).readback.status).toBe("mismatch");
  });

  it("does not verify a replaced maintenance key or threshold", async () => {
    observedAuthorityOverride = signatureVerifyingKey(sampleSigningKey());
    expect((await deploy()).readback.status).toBe("mismatch");
    observedAuthorityOverride = null;
    observedAuthorityThreshold = 2;
    expect((await deploy()).readback.status).toBe("mismatch");
    observedAuthorityThreshold = 1;
    observedAuthorityCounter = 1n;
    expect((await deploy()).readback.status).toBe("mismatch");
  });

  it("verifies only a finalized, explicitly pinned post-deployment maintenance policy", async () => {
    const deployed = await deploy();
    expect(deployed.readback.status).toBe("unsafe-maintenance-authority");
    const readback = () => readPostDeploymentPublicTrustRegistry({
      network,
      receipt: deployed.receipt,
      bootstrap,
      releaseManifest,
      governance: {
        policyCommitment: bootstrap.governancePolicyCommitment,
        policyVersion: 1n,
        actionSequence: 1n,
        maintainerThreshold: 1n,
        activeMaintainerCount: 1n,
      },
      maintenancePolicy: { mode: "immutable" },
    });
    expect((await readback()).status).toBe("unsafe-maintenance-authority");
    observedAuthorityCommittee = [];
    observedAuthorityThreshold = 0;
    observedAuthorityCounter = 1n;
    expect((await readback()).status).toBe("unsafe-maintenance-authority");
    observedAuthorityThreshold = 1;
    expect((await readback()).status).toBe("verified");
    observedAuthorityCommittee = [`0x${"1".repeat(64)}`];
    observedAuthorityThreshold = 1;
    expect((await readback()).status).toBe("unsafe-maintenance-authority");
    observedAuthorityCommittee = [];
    observedAuthorityThreshold = 1;
    observedVerifierKeyOverride = Buffer.from("replacement-verifier-key");
    expect((await readback()).status).toBe("mismatch");
    observedVerifierKeyOverride = null;
    observedAuthorityCounter = 0n;
    expect((await readback()).status).toBe("mismatch");
  });

  it("rejects a stale governance image despite a matching multi-party authority", async () => {
    const deployed = await deploy();
    const verifyingKeys = [
      `0x${"1".repeat(64)}`, `0x${"2".repeat(64)}`, `0x${"3".repeat(64)}`,
    ];
    const governance = {
      policyCommitment: bootstrap.governancePolicyCommitment,
      policyVersion: 1n, actionSequence: 1n,
      maintainerThreshold: 2n, activeMaintainerCount: 3n,
    };
    const readback = (pin = governance) => readPostDeploymentPublicTrustRegistry({
      network, receipt: deployed.receipt, bootstrap, releaseManifest,
      governance: pin,
      maintenancePolicy: { mode: "committee", verifyingKeys, threshold: 2 },
    });
    observedAuthorityCommittee = verifyingKeys;
    observedAuthorityThreshold = 2;
    observedAuthorityCounter = 1n;
    expect((await readback()).status).toBe("mismatch");
    expect((await readback({ ...governance, actionSequence: 2n })).status).toBe("mismatch");
  });

  it("rejects a single-party committee policy before readback", async () => {
    const deployed = await deploy();
    const common = {
      network, receipt: deployed.receipt, bootstrap, releaseManifest,
      governance: {
        policyCommitment: bootstrap.governancePolicyCommitment,
        policyVersion: 1n, actionSequence: 1n,
        maintainerThreshold: 1n, activeMaintainerCount: 1n,
      },
    };
    await expect(readPostDeploymentPublicTrustRegistry({
      ...common,
      maintenancePolicy: { mode: "committee", verifyingKeys: [
        `0x${"1".repeat(64)}`, `0x${"2".repeat(64)}`, `0x${"3".repeat(64)}`,
      ], threshold: 1 },
    })).rejects.toThrow(/multi-party threshold/u);
    await expect(readPostDeploymentPublicTrustRegistry({
      ...common,
      maintenancePolicy: { mode: "committee", verifyingKeys: [
        `0x${"1".repeat(64)}`, `0x${"2".repeat(64)}`, `0x${"3".repeat(64)}`,
      ], threshold: 2 },
    })).rejects.toThrow(/multi-party governance pin/u);
  });

  it("reports malformed finalized operations as an invalid image, not indexer unavailability", async () => {
    observedEmptyVerifierKey = true;
    expect((await deploy()).readback).toEqual({ status: "invalid-image" });
    observedEmptyVerifierKey = false;
    observedDuplicateOperation = true;
    expect((await deploy()).readback).toEqual({ status: "invalid-image" });
  });
});
