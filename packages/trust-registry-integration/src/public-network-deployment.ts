import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { CompiledContract } from "@midnight-ntwrk/compact-js";
import { signatureVerifyingKey, type JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import { deployContract, type ContractProviders } from "@midnight-ntwrk/midnight-js-contracts";
import { getNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import type { SigningKey } from "@midnight-ntwrk/midnight-js-protocol/compact-runtime";
import { bytes32Commitment, bytes32Hex } from "@midnight-ntwrk/trust-registry-client";
import { MaintainerStatus, TrustRegistryContract, trustRegistryWitnesses, type TrustRegistryPrivateState } from "@midnight-ntwrk/trust-registry-contract";

import type { FinalizedRegistryDeploymentImage } from "./finalized-deployment-action-reader.js";
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
  readback: { status: "verified"; state: FinalizedRegistryDeploymentImage }
    | { status: "pending" }
    | { status: "unavailable" }
    | { status: "mismatch"; state: FinalizedRegistryDeploymentImage };
};

export type ReleaseVerifierKeyManifest = {
  format: "tr-release-candidate-manifest-v2";
  verifierKeySha256: Readonly<Record<string, string>>;
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
  releaseManifest: ReleaseVerifierKeyManifest;
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
  if (bootstrap.maintainerThreshold !== 1n) {
    throw new Error("Bootstrap maintainer threshold must be one until more maintainers are active");
  }
  const registryId = bytes32Commitment(bootstrap.registryId);
  const networkId = bytes32Commitment(network.networkId);
  const registryDid = commitment(bootstrap.registryDidCommitment, "Registry DID");
  const policy = commitment(bootstrap.governancePolicyCommitment, "Governance policy");
  const maintainerId = commitment(bootstrap.maintainerId, "Maintainer id");
  const maintainerDid = commitment(bootstrap.maintainerDidCommitment, "Maintainer DID");
  const maintainerKeyId = commitment(bootstrap.maintainerKeyId, "Maintainer key id");
  const expectedKeys = input.releaseManifest?.verifierKeySha256;
  const circuitNames = Object.keys(new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits).sort();
  if (input.releaseManifest?.format !== "tr-release-candidate-manifest-v2"
    || expectedKeys === null || typeof expectedKeys !== "object" || Array.isArray(expectedKeys)
    || Object.keys(expectedKeys).sort().join("\0") !== circuitNames.join("\0")
    || circuitNames.some((name) => !/^[0-9a-f]{64}$/u.test(expectedKeys[name] ?? ""))) {
    throw new Error("Release manifest has an invalid or incomplete verifier-key catalog");
  }
  const expectedAuthorityKey = `0x${signatureVerifyingKey(input.contractMaintenanceSigningKey).toLowerCase()}`;

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
  let state: FinalizedRegistryDeploymentImage | null;
  try {
    state = await reader.readCurrentFinalizedDeploymentImage(receipt.contractAddress, maintainerKeyId);
  } catch {
    // The transaction has already been submitted; preserve its public receipt for later inspection.
    return { receipt, readback: { status: "unavailable" } };
  }
  if (state === null) return { receipt, readback: { status: "pending" } };
  const verified = state.networkId === network.networkId
    && state.contractAddress === receipt.contractAddress.toLowerCase()
    && state.registryIdCommitment === bytes32Hex(registryId)
    && state.deploymentNetworkIdCommitment === bytes32Hex(networkId)
    && state.contractVersion === 1n
    && state.registryDidCommitment === bytes32Hex(registryDid)
    && state.governancePolicyCommitment === bytes32Hex(policy)
    && state.governancePolicyVersion === 1n
    && state.governanceActionSequence === 1n
    && state.maintainerThreshold === bootstrap.maintainerThreshold
    && state.emergencyMaintainerThreshold === bootstrap.maintainerThreshold
    && state.archivalMaintainerThreshold === bootstrap.maintainerThreshold
    && state.activeMaintainerCount === 1n
    && state.bootstrapMaintainer !== null
    && state.bootstrapMaintainer.maintainerId === bytes32Hex(maintainerId)
    && state.bootstrapMaintainer.didCommitment === bytes32Hex(maintainerDid)
    && state.bootstrapMaintainer.keyId === bytes32Hex(maintainerKeyId)
    && state.bootstrapMaintainer.publicKey.x === bootstrap.maintainerPublicKey.x
    && state.bootstrapMaintainer.publicKey.y === bootstrap.maintainerPublicKey.y
    && state.bootstrapMaintainer.status === MaintainerStatus.active
    && state.bootstrapMaintainer.joinedAtSequence === 0n
    && Object.keys(state.verifierKeySha256).sort().join("\0") === circuitNames.join("\0")
    && circuitNames.every((name) => state.verifierKeySha256[name] === expectedKeys[name])
    && state.maintenanceAuthority.committee.length === 1
    && state.maintenanceAuthority.committee[0] === expectedAuthorityKey
    && state.maintenanceAuthority.threshold === 1
    && state.maintenanceAuthority.counter === 0n;
  return { receipt, readback: verified ? { status: "verified", state } : { status: "mismatch", state } };
}
