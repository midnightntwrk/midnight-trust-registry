import { createHash } from "node:crypto";

import { beforeEach, describe, expect, it, vi } from "vitest";

import { setNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { bytes32Commitment, bytes32Hex } from "@midnight-ntwrk/trust-registry-client";
import {
  deriveJubjubPublicKeyFromSeed, MaintainerStatus,
  TrustRegistryContract, trustRegistryWitnesses,
} from "@midnight-ntwrk/trust-registry-contract";

import { FinalizedDeploymentImageInvalidError } from "../finalized-deployment-action-reader.js";
import type { FinalizedRegistryDeploymentImage } from "../finalized-deployment-action-reader.js";
import { reconcileLocalStagedDeployment } from "../local-staged-deployment-reconciliation.js";

const mocks = vi.hoisted(() => ({ readImage: vi.fn() }));
vi.mock("../local-network-deployment-action-reader.js", async (importOriginal) => ({
  ...await importOriginal<typeof import("../local-network-deployment-action-reader.js")>(),
  createLocalNetworkDeploymentActionReader: vi.fn(async () => ({
    readCurrentFinalizedDeploymentImage: mocks.readImage,
  })),
}));

const address = `0x${"c".repeat(64)}`;
const authority = `0x${"d".repeat(64)}`;
const network = {
  networkId: "undeployed" as const,
  rpcUrl: "http://127.0.0.1:29944",
  indexerHttpUrl: "http://127.0.0.1:28088/graphql",
  indexerWsUrl: "ws://127.0.0.1:28088/graphql/ws",
  expectedGenesisHash: `0x${"b".repeat(64)}`,
  allowedHosts: ["127.0.0.1"],
};
const bootstrap = {
  registryId: "registry:staged-reconciliation",
  registryDidCommitment: bytes32Commitment("did:midnight:undeployed:registry"),
  governancePolicyCommitment: bytes32Commitment("policy:staged-reconciliation"),
  maintainerId: bytes32Commitment("maintainer:staged-reconciliation"),
  maintainerDidCommitment: bytes32Commitment("did:midnight:undeployed:maintainer"),
  maintainerKeyId: bytes32Commitment("maintainer:staged-reconciliation#key-1"),
  maintainerPublicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(31)),
  maintainerThreshold: 1n,
};
const initialVerifierKeyName = Object.keys(
  new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits,
).sort()[0]!;
const releaseManifest = {
  format: "tr-release-candidate-manifest-v2" as const,
  verifierKeySha256: Object.fromEntries(Object.keys(
    new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits,
  ).map((name) => [name, createHash("sha256").update(`key:${name}`).digest("hex")])),
};
const receipt = {
  networkId: "undeployed", contractAddress: address,
  txId: "deploy-tx", blockHash: `0x${"e".repeat(64)}`, blockHeight: 10,
};
const input = () => ({ network, receipt, bootstrap, releaseManifest,
  initialVerifierKeyName, bootstrapMaintenanceVerifyingKey: authority });
const image = (): FinalizedRegistryDeploymentImage => ({
  networkId: "undeployed", finalizedBlockHash: `0x${"f".repeat(64)}`,
  contractAddress: address,
  registryIdCommitment: bytes32Hex(bytes32Commitment(bootstrap.registryId)),
  deploymentNetworkIdCommitment: bytes32Hex(bytes32Commitment("undeployed")),
  governancePolicyCommitment: bytes32Hex(bootstrap.governancePolicyCommitment),
  governancePolicyVersion: 1n, governanceActionSequence: 1n,
  contractVersion: 1n, registryDidCommitment: bytes32Hex(bootstrap.registryDidCommitment),
  maintainerThreshold: 1n, emergencyMaintainerThreshold: 1n,
  archivalMaintainerThreshold: 1n, activeMaintainerCount: 1n,
  bootstrapMaintainer: {
    maintainerId: bytes32Hex(bootstrap.maintainerId),
    didCommitment: bytes32Hex(bootstrap.maintainerDidCommitment),
    keyId: bytes32Hex(bootstrap.maintainerKeyId),
    publicKey: bootstrap.maintainerPublicKey,
    status: MaintainerStatus.active, joinedAtSequence: 0n,
  },
  verifierKeySha256: {
    [initialVerifierKeyName]: releaseManifest.verifierKeySha256[initialVerifierKeyName]!,
  },
  maintenanceAuthority: { committee: [authority], threshold: 1, counter: 0n },
});

beforeEach(() => {
  setNetworkId("undeployed");
  vi.clearAllMocks();
});

describe("local staged deployment reconciliation", () => {
  it("recognizes only the exact one-key bootstrap image", async () => {
    mocks.readImage.mockResolvedValueOnce(image());
    expect(await reconcileLocalStagedDeployment(input())).toEqual({
      status: "staged-bootstrap-pending", finalizedBlockHash: `0x${"f".repeat(64)}`,
    });
    expect(mocks.readImage).toHaveBeenCalledWith(address, bootstrap.maintainerKeyId);
    mocks.readImage.mockResolvedValueOnce({ ...image(),
      verifierKeySha256: { [initialVerifierKeyName]: "0".repeat(64) },
    });
    expect((await reconcileLocalStagedDeployment(input())).status).toBe("mismatch");
    mocks.readImage.mockResolvedValueOnce({ ...image(),
      maintenanceAuthority: { committee: [authority], threshold: 1, counter: 1n },
    });
    expect((await reconcileLocalStagedDeployment(input())).status).toBe("mismatch");
  });

  it("reports pending and distinguishes invalid images from unavailable reads", async () => {
    mocks.readImage.mockResolvedValueOnce(null);
    expect((await reconcileLocalStagedDeployment(input())).status).toBe("pending");
    mocks.readImage.mockRejectedValueOnce(new FinalizedDeploymentImageInvalidError("bad operation"));
    expect((await reconcileLocalStagedDeployment(input())).status).toBe("invalid-image");
    mocks.readImage.mockRejectedValueOnce(new Error("indexer unavailable"));
    expect((await reconcileLocalStagedDeployment(input())).status).toBe("unavailable");
  });

  it("rejects public-network or malformed authority pins before querying", async () => {
    await expect(reconcileLocalStagedDeployment({ ...input(), receipt: { ...receipt, networkId: "preprod" } }))
      .rejects.toThrow(/canonical local/u);
    await expect(reconcileLocalStagedDeployment({ ...input(), bootstrapMaintenanceVerifyingKey: "bad" }))
      .rejects.toThrow(/canonical local/u);
    expect(mocks.readImage).not.toHaveBeenCalled();
  });
});
