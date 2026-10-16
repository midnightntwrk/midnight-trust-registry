import { Buffer } from "node:buffer";

import type { PublicDataProvider } from "@midnight-ntwrk/midnight-js-types";
import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import type {
  FinalizedDeploymentActionState,
  TrustedDeploymentActionReader,
} from "@midnight-ntwrk/trust-registry-client";
import { TrustRegistryContract, type MaintainerStatus } from "@midnight-ntwrk/trust-registry-contract/contract";

export type FinalizedNetworkCheckpoint = {
  networkId: string;
  blockHash: string;
};

/** Must authenticate network identity and finality independently of the indexer response. */
export type TrustedFinalizedCheckpointSource = {
  readCurrentFinalizedCheckpoint(): Promise<FinalizedNetworkCheckpoint | null>;
};

export type FinalizedRegistryBootstrapState = FinalizedDeploymentActionState & {
  contractVersion: bigint;
  registryDidCommitment: string;
  governancePolicyVersion: bigint;
  maintainerThreshold: bigint;
  emergencyMaintainerThreshold: bigint;
  archivalMaintainerThreshold: bigint;
  activeMaintainerCount: bigint;
  bootstrapMaintainer: {
    maintainerId: string;
    didCommitment: string;
    keyId: string;
    publicKey: JubjubPoint;
    status: MaintainerStatus;
    joinedAtSequence: bigint;
  } | null;
};

export type FinalizedRegistryBootstrapReader = TrustedDeploymentActionReader & {
  readCurrentFinalizedBootstrapState(
    contractAddress: string,
    bootstrapMaintainerKeyId: Uint8Array,
  ): Promise<FinalizedRegistryBootstrapState | null>;
};

const bytes32Hex = (value: Uint8Array): string =>
  `0x${Buffer.from(value).toString("hex")}`;

const canonicalAddress = (value: string): string => {
  if (!/^0x[0-9a-fA-F]{64}$/u.test(value) || /^0x0{64}$/u.test(value)) {
    throw new Error("A nonzero 32-byte deployed contract address is required");
  }
  return value.toLowerCase();
};

/** Reads actual Compact ledger fields at a trusted finalized checkpoint, not an indexed evidence claim. */
export function createCheckpointedDeploymentActionReader(input: {
  publicDataProvider: Pick<PublicDataProvider, "queryContractState">;
  checkpointSource: TrustedFinalizedCheckpointSource;
}): FinalizedRegistryBootstrapReader {
  const readState = async (contractAddress: string) => {
    const address = canonicalAddress(contractAddress);
    const checkpoint = await input.checkpointSource.readCurrentFinalizedCheckpoint();
    if (checkpoint === null) return null;
    if (!/^[a-z][a-z0-9-]*$/u.test(checkpoint.networkId)
      || checkpoint.networkId === "undeployed"
      || !/^[0-9a-fA-F]{64}$/u.test(checkpoint.blockHash)
      || /^0{64}$/u.test(checkpoint.blockHash)) {
      throw new Error("Trusted finalized checkpoint is malformed");
    }
    const state = await input.publicDataProvider.queryContractState(
      address.slice(2) as Parameters<PublicDataProvider["queryContractState"]>[0],
      { type: "blockHash", blockHash: checkpoint.blockHash.toLowerCase() },
    );
    if (state === null) return null;
    const ledger = TrustRegistryContract.ledger(state.data);
    if (!ledger.initialized || ledger.contractVersion === 0n) {
      throw new Error("Finalized Trust Registry deployment is not initialized");
    }
    const actionState: FinalizedDeploymentActionState = {
      networkId: checkpoint.networkId,
      finalizedBlockHash: `0x${checkpoint.blockHash.toLowerCase()}`,
      contractAddress: address,
      registryIdCommitment: bytes32Hex(ledger.registryId),
      deploymentNetworkIdCommitment: bytes32Hex(ledger.deploymentNetworkIdCommitment),
      governancePolicyCommitment: bytes32Hex(ledger.governancePolicyCommitment),
      governanceActionSequence: ledger.governanceActionCount,
    };
    return { actionState, ledger };
  };
  return {
    async readCurrentFinalizedActionState(contractAddress): Promise<FinalizedDeploymentActionState | null> {
      return (await readState(contractAddress))?.actionState ?? null;
    },
    async readCurrentFinalizedBootstrapState(contractAddress, bootstrapMaintainerKeyId) {
      if (bootstrapMaintainerKeyId.length !== 32) {
        throw new Error("Bootstrap maintainer key id must be 32 bytes");
      }
      const observed = await readState(contractAddress);
      if (observed === null) return null;
      const { ledger, actionState } = observed;
      const maintainer = ledger.maintainerRecords.member(bootstrapMaintainerKeyId)
        ? ledger.maintainerRecords.lookup(bootstrapMaintainerKeyId)
        : null;
      return {
        ...actionState,
        contractVersion: ledger.contractVersion,
        registryDidCommitment: bytes32Hex(ledger.registryDidCommitment),
        governancePolicyVersion: ledger.governancePolicyVersion,
        maintainerThreshold: ledger.maintainerThreshold,
        emergencyMaintainerThreshold: ledger.emergencyMaintainerThreshold,
        archivalMaintainerThreshold: ledger.archivalMaintainerThreshold,
        activeMaintainerCount: ledger.activeMaintainerCount,
        bootstrapMaintainer: maintainer === null ? null : {
          maintainerId: bytes32Hex(maintainer.maintainerId),
          didCommitment: bytes32Hex(maintainer.didCommitment),
          keyId: bytes32Hex(maintainer.keyId),
          publicKey: maintainer.publicKey,
          status: maintainer.status,
          joinedAtSequence: maintainer.joinedAtSequence,
        },
      };
    },
  };
}
