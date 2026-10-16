import { computeDeploymentBoundMaintainerActionDigest } from "@midnight-ntwrk/trust-registry-contract";

import { bytes32Commitment, bytes32Hex, hashHexToBytes32 } from "./utils.js";

export type FinalizedDeploymentActionState = {
  networkId: string;
  contractAddress: string;
  registryIdCommitment: string;
  deploymentNetworkIdCommitment: string;
  governancePolicyCommitment: string;
  governanceActionSequence: bigint;
};

/** The implementation must authenticate network identity, ledger state, address, and finality independently. */
export type TrustedDeploymentActionReader = {
  readCurrentFinalizedActionState(contractAddress: string): Promise<FinalizedDeploymentActionState | null>;
};

export type DeploymentActionSelection = {
  networkId: string;
  contractAddress: string;
  registryId: string;
  expectedPolicyCommitment: string;
  expectedActionSequence: bigint;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
};

const canonicalHex32 = (value: string, label: string): string => {
  if (!/^0x[0-9a-fA-F]{64}$/u.test(value) || /^0x0{64}$/u.test(value)) {
    throw new Error(`${label} must be a nonzero 32-byte hex value`);
  }
  return value.toLowerCase();
};

/** Returns a digest for an external signer; it never handles the maintainer's private key. */
export async function prepareFinalizedDeploymentActionDigest(
  selection: DeploymentActionSelection,
  reader: TrustedDeploymentActionReader,
): Promise<ReturnType<typeof computeDeploymentBoundMaintainerActionDigest>> {
  if (!/^[a-z][a-z0-9-]*$/u.test(selection.networkId)
    || selection.networkId === "undeployed") {
    throw new Error("A concrete public Midnight network is required");
  }
  if (selection.registryId.length === 0) throw new Error("Registry id is required");
  const address = canonicalHex32(selection.contractAddress, "Contract address");
  const expectedPolicy = canonicalHex32(selection.expectedPolicyCommitment, "Policy commitment");
  if (selection.expectedActionSequence < 0n) throw new Error("Action sequence must be nonnegative");

  const observed = await reader.readCurrentFinalizedActionState(address);
  if (observed === null) throw new Error("Finalized deployment action state is unavailable");
  if (observed.networkId !== selection.networkId) throw new Error("Deployment network mismatch");
  if (canonicalHex32(observed.contractAddress, "Observed contract address") !== address) {
    throw new Error("Deployment contract address mismatch");
  }
  const registryId = bytes32Commitment(selection.registryId);
  const networkId = bytes32Commitment(selection.networkId);
  if (canonicalHex32(observed.registryIdCommitment, "Observed registry id")
      !== bytes32Hex(registryId)) {
    throw new Error("Deployment registry id mismatch");
  }
  if (canonicalHex32(observed.deploymentNetworkIdCommitment, "Observed network id")
      !== bytes32Hex(networkId)) {
    throw new Error("Deployment network commitment mismatch");
  }
  if (canonicalHex32(observed.governancePolicyCommitment, "Observed policy commitment") !== expectedPolicy) {
    throw new Error("Deployment policy commitment mismatch");
  }
  if (observed.governanceActionSequence !== selection.expectedActionSequence) {
    throw new Error("Deployment action sequence mismatch");
  }
  return computeDeploymentBoundMaintainerActionDigest(
    registryId,
    networkId,
    hashHexToBytes32(address),
    hashHexToBytes32(expectedPolicy),
    selection.actionKind,
    selection.actionPayloadHash,
    selection.expectedActionSequence,
  );
}
