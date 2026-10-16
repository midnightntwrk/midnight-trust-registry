import { describe, expect, it, vi } from "vitest";
import type { PublicDataProvider } from "@midnight-ntwrk/midnight-js-types";
import {
  bytes32Hex,
  prepareFinalizedDeploymentActionDigest,
} from "@midnight-ntwrk/trust-registry-client";
import {
  deriveJubjubPublicKeyFromSeed,
  encodeCompactActionKind,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  TrustRegistrySimulator,
} from "@midnight-ntwrk/trust-registry-contract/testing";

import { bytes32Commitment } from "../fixtures.js";
import { createCheckpointedDeploymentActionReader } from "../finalized-deployment-action-reader.js";

const blockHash = "d".repeat(64);
const address = "a".repeat(64);
const registryId = "registry:midnight:qualification";
const policy = bytes32Commitment("policy:qualification");

function fixture() {
  const seed = new Uint8Array(32).fill(13);
  const simulator = new TrustRegistrySimulator({
    registryId: bytes32Commitment(registryId),
    networkIdCommitment: bytes32Commitment("preprod"),
    contractAddress: address,
    registryDidCommitment: bytes32Commitment("did:midnight:preprod:qualification"),
    governancePolicyCommitment: policy,
    maintainerId: bytes32Commitment("maintainer:qualification"),
    maintainerDidCommitment: bytes32Commitment("did:midnight:preprod:maintainer"),
    maintainerKeyId: bytes32Commitment("maintainer:qualification#key-1"),
    maintainerPublicKey: deriveJubjubPublicKeyFromSeed(seed),
    maintainerThreshold: 1n,
  });
  const queryContractState = vi.fn(async () => ({ data: simulator.circuitContext.currentQueryContext.state }));
  const readCurrentFinalizedCheckpoint = vi.fn(async () => ({ networkId: "preprod", blockHash }));
  const reader = createCheckpointedDeploymentActionReader({
    publicDataProvider: { queryContractState } as unknown as Pick<PublicDataProvider, "queryContractState">,
    checkpointSource: { readCurrentFinalizedCheckpoint },
  });
  return { simulator, reader, queryContractState, readCurrentFinalizedCheckpoint };
}

describe("checkpointed deployment action reader", () => {
  it("decodes real Compact ledger state at the selected finalized block", async () => {
    const { simulator, reader, queryContractState } = fixture();
    const actionState = await reader.readCurrentFinalizedActionState(`0x${address}`);
    expect(queryContractState).toHaveBeenCalledWith(address, { type: "blockHash", blockHash });
    expect(actionState).toEqual({
      networkId: "preprod",
      contractAddress: `0x${address}`,
      registryIdCommitment: bytes32Hex(simulator.getLedger().registryId),
      deploymentNetworkIdCommitment: bytes32Hex(simulator.getLedger().deploymentNetworkIdCommitment),
      governancePolicyCommitment: bytes32Hex(simulator.getLedger().governancePolicyCommitment),
      governanceActionSequence: simulator.getLedger().governanceActionCount,
    });
    await expect(prepareFinalizedDeploymentActionDigest({
      networkId: "preprod",
      contractAddress: `0x${address}`,
      registryId,
      expectedPolicyCommitment: bytes32Hex(policy),
      expectedActionSequence: simulator.getLedger().governanceActionCount,
      actionKind: encodeCompactActionKind("tr:epoch:publish"),
      actionPayloadHash: bytes32Commitment("epoch:qualification"),
    }, reader)).resolves.toBeDefined();
  });

  it("fails closed when the checkpoint is absent or malformed", async () => {
    const { reader, readCurrentFinalizedCheckpoint, queryContractState } = fixture();
    readCurrentFinalizedCheckpoint.mockResolvedValueOnce(null as never);
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`)).resolves.toBeNull();
    readCurrentFinalizedCheckpoint.mockResolvedValueOnce({ networkId: "undeployed", blockHash });
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`)).rejects.toThrow(/malformed/u);
    expect(queryContractState).not.toHaveBeenCalled();
  });

  it("returns no action context when no state exists at the finalized checkpoint", async () => {
    const { reader, queryContractState } = fixture();
    queryContractState.mockResolvedValueOnce(null as never);
    await expect(reader.readCurrentFinalizedActionState(`0x${address}`)).resolves.toBeNull();
  });
});
