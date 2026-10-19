import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { CompiledContract } from "@midnight-ntwrk/compact-js";
import { signatureVerifyingKey, type JubjubPoint } from "@midnight-ntwrk/compact-runtime";
import { deployContract, type ContractProviders } from "@midnight-ntwrk/midnight-js-contracts";
import { getNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import type { SigningKey } from "@midnight-ntwrk/midnight-js-protocol/compact-runtime";
import { bytes32Commitment, bytes32Hex } from "@midnight-ntwrk/trust-registry-client";
import { MaintainerStatus, TrustRegistryContract, trustRegistryWitnesses, type TrustRegistryPrivateState } from "@midnight-ntwrk/trust-registry-contract";

import {
  FinalizedDeploymentImageInvalidError,
  type FinalizedRegistryBootstrapReader,
  type FinalizedRegistryDeploymentImage,
  type TrustedFinalizedCheckpointSource,
} from "./finalized-deployment-action-reader.js";
import {
  createLocalNetworkDeploymentActionReader,
  type LocalNetworkDeploymentActionReaderConfig,
} from "./local-network-deployment-action-reader.js";
import { createLocalRpcFinalizedCheckpointSource, createRpcFinalizedCheckpointSource } from "./rpc-finalized-checkpoint.js";
import {
  createPublicNetworkDeploymentActionReader,
  type PublicNetworkDeploymentActionReaderConfig,
} from "./public-network-deployment-action-reader.js";
import { verifyInstalledVerifierKeyAssets } from "./verifier-asset-preflight.js";

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
  readback: PublicRegistryDeploymentReadback;
};

export type PublicRegistryDeploymentReadback =
  | { status: "verified"; state: FinalizedRegistryDeploymentImage }
  | { status: "unsafe-maintenance-authority"; state: FinalizedRegistryDeploymentImage }
  | { status: "pending" }
  | { status: "unavailable" }
  | { status: "invalid-image" }
  | { status: "mismatch"; state: FinalizedRegistryDeploymentImage };

export type PublicRegistryMaintenancePolicy =
  | { mode: "immutable" }
  | { mode: "committee"; verifyingKeys: readonly string[]; threshold: number };

export type PublicRegistryGovernancePin = {
  policyCommitment: Uint8Array;
  policyVersion: bigint;
  actionSequence: bigint;
  maintainerThreshold: bigint;
  activeMaintainerCount: bigint;
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

const verifierKeyCatalog = (manifest: ReleaseVerifierKeyManifest): {
  names: string[];
  hashes: Readonly<Record<string, string>>;
} => {
  const hashes = manifest?.verifierKeySha256;
  const names = Object.keys(new TrustRegistryContract.Contract(trustRegistryWitnesses).provableCircuits).sort();
  if (manifest?.format !== "tr-release-candidate-manifest-v2"
    || hashes === null || typeof hashes !== "object" || Array.isArray(hashes)
    || Object.keys(hashes).sort().join("\0") !== names.join("\0")
    || names.some((name) => !/^[0-9a-f]{64}$/u.test(hashes[name] ?? ""))) {
    throw new Error("Release manifest has an invalid or incomplete verifier-key catalog");
  }
  return { names, hashes };
};

const authorityIsUnsafe = (state: FinalizedRegistryDeploymentImage): boolean =>
  state.maintenanceAuthority.threshold === 0
  || (state.maintenanceAuthority.committee.length > 0
    && (state.maintenanceAuthority.threshold < 2 || state.maintenanceAuthority.committee.length < 3));

export const validateMaintenancePolicy = (policy: PublicRegistryMaintenancePolicy): void => {
  if (policy.mode === "immutable") return;
  const { verifyingKeys, threshold } = policy;
  if (verifyingKeys.length < 3 || !Number.isSafeInteger(threshold)
    || threshold < 2 || threshold > verifyingKeys.length
    || new Set(verifyingKeys).size !== verifyingKeys.length
    || verifyingKeys.some((key) => !/^0x[0-9a-f]{64}$/u.test(key) || /^0x0{64}$/u.test(key))) {
    throw new Error("Maintenance committee policy requires distinct canonical keys and a multi-party threshold");
  }
};

const matchesMaintenancePolicy = (
  state: FinalizedRegistryDeploymentImage,
  policy: PublicRegistryMaintenancePolicy,
): boolean => {
  const authority = state.maintenanceAuthority;
  if (authority.counter < 1n) return false;
  if (policy.mode === "immutable") {
    return authority.committee.length === 0 && authority.threshold === 1;
  }
  return authority.threshold === policy.threshold
    && authority.committee.length === policy.verifyingKeys.length
    && authority.committee.every((key, index) => key === policy.verifyingKeys[index]);
};

const matchesVerifierKeys = (
  state: FinalizedRegistryDeploymentImage,
  catalog: ReturnType<typeof verifierKeyCatalog>,
): boolean => Object.keys(state.verifierKeySha256).sort().join("\0") === catalog.names.join("\0")
  && catalog.names.every((name) => state.verifierKeySha256[name] === catalog.hashes[name]);

export const matchesPinnedRegistryImage = (input: {
  networkId: string;
  receipt: PublicRegistryDeploymentReceipt;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  governance: PublicRegistryGovernancePin;
}, state: FinalizedRegistryDeploymentImage): boolean => {
  const { networkId, receipt, bootstrap, governance } = input;
  const catalog = verifierKeyCatalog(input.releaseManifest);
  return state.networkId === networkId
    && state.contractAddress === receipt.contractAddress
    && state.registryIdCommitment === bytes32Hex(bytes32Commitment(bootstrap.registryId))
    && state.deploymentNetworkIdCommitment === bytes32Hex(bytes32Commitment(networkId))
    && state.contractVersion === 1n
    && state.registryDidCommitment === bytes32Hex(bootstrap.registryDidCommitment)
    && state.governancePolicyCommitment === bytes32Hex(governance.policyCommitment)
    && state.governancePolicyVersion === governance.policyVersion
    && state.governanceActionSequence === governance.actionSequence
    && state.maintainerThreshold === governance.maintainerThreshold
    && state.activeMaintainerCount === governance.activeMaintainerCount
    && state.bootstrapMaintainer !== null
    && state.bootstrapMaintainer.maintainerId === bytes32Hex(bootstrap.maintainerId)
    && state.bootstrapMaintainer.didCommitment === bytes32Hex(bootstrap.maintainerDidCommitment)
    && state.bootstrapMaintainer.keyId === bytes32Hex(bootstrap.maintainerKeyId)
    && state.bootstrapMaintainer.publicKey.x === bootstrap.maintainerPublicKey.x
    && state.bootstrapMaintainer.publicKey.y === bootstrap.maintainerPublicKey.y
    && state.bootstrapMaintainer.status === MaintainerStatus.active
    && state.bootstrapMaintainer.joinedAtSequence === 0n
    && matchesVerifierKeys(state, catalog);
};

const contractAssetsPath = resolve(
  dirname(fileURLToPath(import.meta.resolve("@midnight-ntwrk/trust-registry-contract/contract"))),
  "managed/trust-registry",
);

/** Deploys with a temporary single-key maintenance authority; never marks that authority release-verified. */
export async function deployPublicTrustRegistry(input: {
  network: PublicNetworkDeploymentActionReaderConfig;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  providers: ContractProviders<RegistryContract>;
  contractMaintenanceSigningKey: SigningKey;
}): Promise<PublicRegistryDeploymentResult> {
  return deployPinnedTrustRegistry({
    ...input,
    checkpointSource: createRpcFinalizedCheckpointSource(input.network),
    readerFactory: () => createPublicNetworkDeploymentActionReader(input.network),
  });
}

/** Deploys only to an isolated local network with a separately approved genesis pin. */
export async function deployLocalTrustRegistry(input: {
  network: LocalNetworkDeploymentActionReaderConfig;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  providers: ContractProviders<RegistryContract>;
  contractMaintenanceSigningKey: SigningKey;
}): Promise<PublicRegistryDeploymentResult> {
  if (input.network.networkId !== "undeployed") throw new Error("Local deployment requires the undeployed network");
  return deployPinnedTrustRegistry({
    ...input,
    checkpointSource: createLocalRpcFinalizedCheckpointSource(input.network),
    readerFactory: () => createLocalNetworkDeploymentActionReader(input.network),
  });
}

async function deployPinnedTrustRegistry(input: {
  network: { networkId: string };
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  providers: ContractProviders<RegistryContract>;
  contractMaintenanceSigningKey: SigningKey;
  checkpointSource: TrustedFinalizedCheckpointSource;
  readerFactory: () => Promise<FinalizedRegistryBootstrapReader>;
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
  const catalog = verifierKeyCatalog(input.releaseManifest);
  await verifyInstalledVerifierKeyAssets(input.releaseManifest);
  const expectedAuthorityKey = `0x${signatureVerifyingKey(input.contractMaintenanceSigningKey).toLowerCase()}`;

  const checkpoint = await input.checkpointSource.readCurrentFinalizedCheckpoint();
  if (checkpoint === null || checkpoint.networkId !== network.networkId) {
    throw new Error("Pinned network finality checkpoint is unavailable");
  }
  const reader = await input.readerFactory();
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
  } catch (error) {
    // The transaction has already been submitted; preserve its public receipt for later inspection.
    return { receipt, readback: { status: error instanceof FinalizedDeploymentImageInvalidError
      ? "invalid-image" : "unavailable" } };
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
    && matchesVerifierKeys(state, catalog)
    && state.maintenanceAuthority.committee.length === 1
    && state.maintenanceAuthority.committee[0] === expectedAuthorityKey
    && state.maintenanceAuthority.threshold === 1
    && state.maintenanceAuthority.counter === 0n;
  return { receipt, readback: verified
    ? { status: "unsafe-maintenance-authority", state }
    : { status: "mismatch", state } };
}

/** Rechecks current finalized state only after an operator-approved maintenance transition. */
export async function readPostDeploymentPublicTrustRegistry(input: {
  network: PublicNetworkDeploymentActionReaderConfig;
  receipt: PublicRegistryDeploymentReceipt;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  governance: PublicRegistryGovernancePin;
  maintenancePolicy: PublicRegistryMaintenancePolicy;
}): Promise<PublicRegistryDeploymentReadback> {
  return readPostDeploymentPinnedTrustRegistry({
    ...input,
    readerFactory: () => createPublicNetworkDeploymentActionReader(input.network),
  });
}

/** Rechecks the local committee only at a genesis-pinned `undeployed` finalized checkpoint. */
export async function readPostDeploymentLocalTrustRegistry(input: {
  network: LocalNetworkDeploymentActionReaderConfig;
  receipt: PublicRegistryDeploymentReceipt;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  governance: PublicRegistryGovernancePin;
  maintenancePolicy: PublicRegistryMaintenancePolicy;
}): Promise<PublicRegistryDeploymentReadback> {
  if (input.network.networkId !== "undeployed" || getNetworkId() !== "undeployed") {
    throw new Error("Local post-deployment readback requires the undeployed network");
  }
  return readPostDeploymentPinnedTrustRegistry({
    ...input,
    readerFactory: () => createLocalNetworkDeploymentActionReader(input.network),
  });
}

async function readPostDeploymentPinnedTrustRegistry(input: {
  network: { networkId: string };
  receipt: PublicRegistryDeploymentReceipt;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  governance: PublicRegistryGovernancePin;
  maintenancePolicy: PublicRegistryMaintenancePolicy;
  readerFactory: () => Promise<FinalizedRegistryBootstrapReader>;
}): Promise<PublicRegistryDeploymentReadback> {
  const { network, receipt, bootstrap, governance, maintenancePolicy } = input;
  validateMaintenancePolicy(maintenancePolicy);
  commitment(governance.policyCommitment, "Governance policy");
  if (governance.policyVersion < 1n || governance.actionSequence < 1n
    || governance.maintainerThreshold < 1n || governance.activeMaintainerCount < 1n) {
    throw new Error("Post-deployment governance pin is invalid");
  }
  if (maintenancePolicy.mode === "committee"
    && (governance.maintainerThreshold < 2n || governance.activeMaintainerCount < 3n)) {
    throw new Error("Maintenance committee requires a multi-party governance pin");
  }
  if (receipt.networkId !== network.networkId || !/^0x[0-9a-f]{64}$/u.test(receipt.contractAddress)) {
    throw new Error("Deployment receipt does not match the pinned network or address format");
  }
  const reader = await input.readerFactory();
  let state: FinalizedRegistryDeploymentImage | null;
  try {
    state = await reader.readCurrentFinalizedDeploymentImage(receipt.contractAddress, bootstrap.maintainerKeyId);
  } catch (error) {
    return { status: error instanceof FinalizedDeploymentImageInvalidError ? "invalid-image" : "unavailable" };
  }
  if (state === null) return { status: "pending" };
  const identityMatches = matchesPinnedRegistryImage({
    networkId: network.networkId, receipt, bootstrap, releaseManifest: input.releaseManifest, governance,
  }, state);
  if (!identityMatches) return { status: "mismatch", state };
  if (authorityIsUnsafe(state)) return { status: "unsafe-maintenance-authority", state };
  return matchesMaintenancePolicy(state, maintenancePolicy)
    ? { status: "verified", state } : { status: "mismatch", state };
}
