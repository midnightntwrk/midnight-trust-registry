import { describe, expect, it } from "vitest";
import {
  computeDeploymentBoundMaintainerActionDigest,
  encodeCompactActionKind,
} from "@midnight-ntwrk/trust-registry-contract";

import {
  prepareFinalizedDeploymentActionDigest,
  type DeploymentActionSelection,
  type FinalizedDeploymentActionState,
} from "../deployment-action.js";
import { bytes32Commitment, bytes32Hex, hashHexToBytes32 } from "../utils.js";

const address = `0x${"a".repeat(64)}`;
const policy = `0x${"b".repeat(64)}`;
const selection: DeploymentActionSelection = {
  networkId: "preprod",
  contractAddress: address,
  registryId: "registry:midnight:qualification",
  expectedPolicyCommitment: policy,
  expectedActionSequence: 7n,
  actionKind: encodeCompactActionKind("tr:epoch:publish"),
  actionPayloadHash: bytes32Commitment("epoch:qualification"),
};
const observed: FinalizedDeploymentActionState = {
  networkId: selection.networkId,
  contractAddress: address,
  registryIdCommitment: bytes32Hex(bytes32Commitment(selection.registryId)),
  deploymentNetworkIdCommitment: bytes32Hex(bytes32Commitment(selection.networkId)),
  governancePolicyCommitment: policy,
  governanceActionSequence: 7n,
};

const prepare = (
  expected: DeploymentActionSelection = selection,
  actual: FinalizedDeploymentActionState | null = observed,
) => prepareFinalizedDeploymentActionDigest(expected, {
  readCurrentFinalizedActionState: async (requestedAddress) => {
    expect(requestedAddress).toBe(expected.contractAddress.toLowerCase());
    return actual;
  },
});

describe("finalized deployment action preparation", () => {
  it("derives the same domain-bound digest as the Compact signing helper", async () => {
    const digest = await prepare();
    expect(digest).toEqual(computeDeploymentBoundMaintainerActionDigest(
      bytes32Commitment(selection.registryId), bytes32Commitment(selection.networkId),
      hashHexToBytes32(address), hashHexToBytes32(policy),
      selection.actionKind, selection.actionPayloadHash, selection.expectedActionSequence,
    ));
  });

  it("refuses unavailable, wrong-network, and wrong-address observations", async () => {
    await expect(prepare(selection, null)).rejects.toThrow(/unavailable/u);
    await expect(prepare(selection, { ...observed, networkId: "testnet" })).rejects.toThrow(/network mismatch/u);
    await expect(prepare(selection, { ...observed, contractAddress: `0x${"c".repeat(64)}` }))
      .rejects.toThrow(/address mismatch/u);
    await expect(prepare({ ...selection, networkId: "undeployed" })).rejects.toThrow(/concrete public/u);
  });

  it("refuses substituted registry, network commitment, policy, or sequence", async () => {
    await expect(prepare(selection, { ...observed, registryIdCommitment: `0x${"c".repeat(64)}` }))
      .rejects.toThrow(/registry id mismatch/u);
    await expect(prepare(selection, { ...observed, deploymentNetworkIdCommitment: `0x${"c".repeat(64)}` }))
      .rejects.toThrow(/network commitment mismatch/u);
    await expect(prepare(selection, { ...observed, governancePolicyCommitment: `0x${"c".repeat(64)}` }))
      .rejects.toThrow(/policy commitment mismatch/u);
    await expect(prepare(selection, { ...observed, governanceActionSequence: 8n }))
      .rejects.toThrow(/action sequence mismatch/u);
  });

  it("refuses malformed or placeholder domains before reading the ledger", async () => {
    await expect(prepare({ ...selection, contractAddress: `0x${"0".repeat(64)}` }))
      .rejects.toThrow(/nonzero/u);
    await expect(prepare({ ...selection, expectedPolicyCommitment: "not-hex" }))
      .rejects.toThrow(/32-byte/u);
    await expect(prepare({ ...selection, expectedActionSequence: -1n }))
      .rejects.toThrow(/nonnegative/u);
  });
});
