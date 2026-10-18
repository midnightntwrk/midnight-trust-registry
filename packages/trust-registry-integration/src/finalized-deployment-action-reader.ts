import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";

import type { PublicDataProvider } from "@midnight-ntwrk/midnight-js-types";
import type { ContractState, JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import type { Ledger } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";
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

export type FinalizedRegistryDeploymentImage = FinalizedRegistryBootstrapState & {
  verifierKeySha256: Readonly<Record<string, string>>;
  maintenanceAuthority: {
    committee: readonly string[];
    threshold: number;
    counter: bigint;
  };
};

export type FinalizedRegistryBootstrapReader = TrustedDeploymentActionReader & {
  readCurrentFinalizedLedger(contractAddress: string): Promise<FinalizedRegistryLedgerView | null>;
  readCurrentFinalizedBootstrapState(
    contractAddress: string,
    bootstrapMaintainerKeyId: Uint8Array,
  ): Promise<FinalizedRegistryBootstrapState | null>;
  readCurrentFinalizedDeploymentImage(
    contractAddress: string,
    bootstrapMaintainerKeyId: Uint8Array,
  ): Promise<FinalizedRegistryDeploymentImage | null>;
};

export type FinalizedRegistryLedgerView = {
  networkId: string;
  finalizedBlockHash: string;
  contractAddress: string;
  ledger: Ledger;
};

export class FinalizedDeploymentImageInvalidError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "FinalizedDeploymentImageInvalidError";
  }
}

const bytes32Hex = (value: Uint8Array): string =>
  `0x${Buffer.from(value).toString("hex")}`;

const canonicalAddress = (value: string): string => {
  if (!/^0x[0-9a-fA-F]{64}$/u.test(value) || /^0x0{64}$/u.test(value)) {
    throw new Error("A nonzero 32-byte deployed contract address is required");
  }
  return value.toLowerCase();
};

const deploymentImage = (state: ContractState) => {
  const entries: Array<readonly [string, string]> = [];
  const seen = new Set<string>();
  for (const name of state.operations()) {
    if (typeof name !== "string" || name.length === 0 || seen.has(name)) {
      throw new FinalizedDeploymentImageInvalidError("Finalized contract has an invalid operation catalog");
    }
    seen.add(name);
    const key = state.operation(name)?.verifierKey;
    if (key === undefined || key.length === 0) {
      throw new FinalizedDeploymentImageInvalidError(`Finalized contract operation has no verifier key: ${name}`);
    }
    entries.push([name, createHash("sha256").update(key).digest("hex")]);
  }
  const authority = state.maintenanceAuthority;
  return {
    verifierKeySha256: Object.fromEntries(entries),
    maintenanceAuthority: {
      committee: authority.committee.map((key) => `0x${key.toLowerCase()}`),
      threshold: authority.threshold,
      counter: authority.counter,
    },
  };
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
    return { actionState, ledger, contractState: state };
  };
  const readBootstrapState = async (contractAddress: string, bootstrapMaintainerKeyId: Uint8Array) => {
    if (bootstrapMaintainerKeyId.length !== 32) {
      throw new Error("Bootstrap maintainer key id must be 32 bytes");
    }
    const observed = await readState(contractAddress);
    if (observed === null) return null;
    const { ledger, actionState } = observed;
    const maintainer = ledger.maintainerRecords.member(bootstrapMaintainerKeyId)
      ? ledger.maintainerRecords.lookup(bootstrapMaintainerKeyId)
      : null;
    const bootstrap: FinalizedRegistryBootstrapState = {
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
    return { bootstrap, contractState: observed.contractState };
  };
  return {
    async readCurrentFinalizedLedger(contractAddress) {
      const observed = await readState(contractAddress);
      return observed === null ? null : {
        networkId: observed.actionState.networkId,
        finalizedBlockHash: observed.actionState.finalizedBlockHash,
        contractAddress: observed.actionState.contractAddress,
        ledger: observed.ledger,
      };
    },
    async readCurrentFinalizedActionState(contractAddress): Promise<FinalizedDeploymentActionState | null> {
      return (await readState(contractAddress))?.actionState ?? null;
    },
    async readCurrentFinalizedBootstrapState(contractAddress, bootstrapMaintainerKeyId) {
      return (await readBootstrapState(contractAddress, bootstrapMaintainerKeyId))?.bootstrap ?? null;
    },
    async readCurrentFinalizedDeploymentImage(contractAddress, bootstrapMaintainerKeyId) {
      const observed = await readBootstrapState(contractAddress, bootstrapMaintainerKeyId);
      return observed === null ? null : {
        ...observed.bootstrap,
        ...deploymentImage(observed.contractState),
      };
    },
  };
}
