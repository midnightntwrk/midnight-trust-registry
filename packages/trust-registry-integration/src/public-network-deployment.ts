import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { CompiledContract } from "@midnight-ntwrk/compact-js";
import type { JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import { deployContract, type ContractProviders } from "@midnight-ntwrk/midnight-js-contracts";
import { getNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import type { SigningKey } from "@midnight-ntwrk/midnight-js-protocol/compact-runtime";
import { bytes32Commitment, bytes32Hex, type FinalizedDeploymentActionState } from "@midnight-ntwrk/trust-registry-client";
import { TrustRegistryContract, trustRegistryWitnesses, type TrustRegistryPrivateState } from "@midnight-ntwrk/trust-registry-contract";

import { createRpcFinalizedCheckpointSource } from "./rpc-finalized-checkpoint.js";
import {
  createPublicNetworkDeploymentActionReader,
  type PublicNetworkDeploymentActionReaderConfig,
} from "./public-network-deployment-action-reader.js";

type RegistryContract = TrustRegistryContract.Contract<TrustRegistryPrivateState>;

export type PublicRegistryBootstrap = {
  registryId: string;
  registryDidCommitment: Uint8Array;
  governancePolicyCommitment: Uint8Array;
  maintainerId: Uint8Array;
  maintainerDidCommitment: Uint8Array;
  maintainerKeyId: Uint8Array;
  maintainerPublicKey: JubjubPoint;
  maintainerThreshold: bigint;
};

export type PublicRegistryDeploymentReceipt = {
  networkId: string;
  contractAddress: string;
  txId: string;
  blockHash: string;
  blockHeight: number;
};

export type PublicRegistryDeploymentResult = {
  receipt: PublicRegistryDeploymentReceipt;
  readback: { status: "verified"; state: FinalizedDeploymentActionState }
    | { status: "pending" }
    | { status: "unavailable" }
    | { status: "mismatch"; state: FinalizedDeploymentActionState };
};

const commitment = (value: Uint8Array, label: string): Uint8Array => {
  if (value.length !== 32 || value.every((byte) => byte === 0)) {
    throw new Error(`${label} must be a nonzero 32-byte commitment`);
  }
  return value;
};

const contractAssetsPath = resolve(
  dirname(fileURLToPath(import.meta.resolve("@midnight-ntwrk/trust-registry-contract/contract"))),
  "managed/trust-registry",
);

/** Deploys using host-owned providers and maintenance key, then checks finalized constructor state. */
export async function deployPublicTrustRegistry(input: {
  network: PublicNetworkDeploymentActionReaderConfig;
  bootstrap: PublicRegistryBootstrap;
  providers: ContractProviders<RegistryContract>;
  contractMaintenanceSigningKey: SigningKey;
}): Promise<PublicRegistryDeploymentResult> {
  const { network, bootstrap } = input;
  if (getNetworkId() !== network.networkId) {
    throw new Error("Midnight.js network does not match the pinned deployment network");
  }
  if (bootstrap.registryId.length === 0 || bootstrap.registryId.includes("\0")) {
    throw new Error("Registry id must be a nonempty canonical string");
  }
  if (bootstrap.maintainerThreshold < 1n || bootstrap.maintainerThreshold > 5n) {
    throw new Error("Bootstrap maintainer threshold must be between one and five");
  }
  const registryId = bytes32Commitment(bootstrap.registryId);
  const networkId = bytes32Commitment(network.networkId);
  const registryDid = commitment(bootstrap.registryDidCommitment, "Registry DID");
  const policy = commitment(bootstrap.governancePolicyCommitment, "Governance policy");
  const maintainerId = commitment(bootstrap.maintainerId, "Maintainer id");
  const maintainerDid = commitment(bootstrap.maintainerDidCommitment, "Maintainer DID");
  const maintainerKeyId = commitment(bootstrap.maintainerKeyId, "Maintainer key id");

  const checkpoint = await createRpcFinalizedCheckpointSource(network).readCurrentFinalizedCheckpoint();
  if (checkpoint === null || checkpoint.networkId !== network.networkId) {
    throw new Error("Pinned network finality checkpoint is unavailable");
  }
  const reader = await createPublicNetworkDeploymentActionReader(network);
  const compiled = CompiledContract.make(
    "trust-registry",
    TrustRegistryContract.Contract<TrustRegistryPrivateState>,
  ).pipe(
    CompiledContract.withWitnesses(trustRegistryWitnesses),
    CompiledContract.withCompiledFileAssets(contractAssetsPath),
  );
  const deployed = await deployContract(input.providers, {
    compiledContract: compiled,
    privateStateId: "trustRegistryPrivateState",
    initialPrivateState: {},
    signingKey: input.contractMaintenanceSigningKey,
    args: [
      registryId, registryDid, policy, maintainerId, maintainerDid,
      maintainerKeyId, bootstrap.maintainerPublicKey, bootstrap.maintainerThreshold, networkId,
    ],
  });
  // Never spread deployTxData: its private field contains sensitive wallet material.
  const publicTx = deployed.deployTxData.public;
  const receipt = {
    networkId: network.networkId,
    contractAddress: `0x${publicTx.contractAddress}`,
    txId: publicTx.txId,
    blockHash: `0x${publicTx.blockHash}`,
    blockHeight: publicTx.blockHeight,
  };
  let state: FinalizedDeploymentActionState | null;
  try {
    state = await reader.readCurrentFinalizedActionState(receipt.contractAddress);
  } catch {
    // The transaction has already been submitted; preserve its public receipt for later inspection.
    return { receipt, readback: { status: "unavailable" } };
  }
  if (state === null) return { receipt, readback: { status: "pending" } };
  const verified = state.networkId === network.networkId
    && state.contractAddress === receipt.contractAddress.toLowerCase()
    && state.registryIdCommitment === bytes32Hex(registryId)
    && state.deploymentNetworkIdCommitment === bytes32Hex(networkId)
    && state.governancePolicyCommitment === bytes32Hex(policy)
    && state.governanceActionSequence === 1n;
  return { receipt, readback: verified ? { status: "verified", state } : { status: "mismatch", state } };
}
