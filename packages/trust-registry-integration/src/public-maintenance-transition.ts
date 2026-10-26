import { getNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import {
  ContractMaintenanceAuthority,
  Intent,
  MaintenanceUpdate,
  ReplaceAuthority,
  verifySignature,
  type Signature,
  type UnprovenTransaction,
} from "@midnight-ntwrk/midnight-js-protocol/ledger";
import { Transaction } from "@midnight-ntwrk/midnight-js-types";

import type { FinalizedRegistryDeploymentImage } from "./finalized-deployment-action-reader.js";
import {
  createLocalNetworkDeploymentActionReader,
  type LocalNetworkDeploymentActionReaderConfig,
} from "./local-network-deployment-action-reader.js";
import {
  matchesPinnedRegistryImage,
  validateMaintenancePolicy,
  type PublicRegistryBootstrap,
  type PublicRegistryDeploymentReceipt,
  type PublicRegistryGovernancePin,
  type PublicRegistryMaintenancePolicy,
  type ReleaseVerifierKeyManifest,
} from "./public-network-deployment.js";
import {
  createPublicNetworkDeploymentActionReader,
  type PublicNetworkDeploymentActionReaderConfig,
} from "./public-network-deployment-action-reader.js";

export type CommitteeTransitionApproval<Network extends { networkId: string } = PublicNetworkDeploymentActionReaderConfig> = {
  network: Network;
  receipt: PublicRegistryDeploymentReceipt;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  governance: PublicRegistryGovernancePin;
  maintenancePolicy: Extract<PublicRegistryMaintenancePolicy, { mode: "committee" }>;
  bootstrapMaintenanceVerifyingKey: string;
  /** Explicit staged-key mode; absent means the full constructor installed every key at counter zero. */
  stagedVerifierKeyInstallation?: true;
  expiresAt: Date;
};

export type LocalCommitteeTransitionApproval = CommitteeTransitionApproval<LocalNetworkDeploymentActionReaderConfig>;

export type PreparedCommitteeTransition = {
  networkId: string;
  contractAddress: string;
  finalizedBlockHash: string;
  committeeVerifyingKeys: readonly string[];
  threshold: number;
  currentAuthorityCounter: bigint;
  nextAuthorityCounter: bigint;
  expiresAt: string;
  dataToSign: Uint8Array;
  /** Accepts one externally produced bootstrap signature; private keys never enter this helper. */
  authorize(signature: Signature): UnprovenTransaction;
};

const KEY = /^0x[0-9a-f]{64}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;

/** Builds a single-use committee transition from a separately pinned finalized image. */
export function prepareCommitteeTransitionFromFinalizedImage(
  input: CommitteeTransitionApproval<{ networkId: string }>,
  image: FinalizedRegistryDeploymentImage,
): PreparedCommitteeTransition {
  const { network, receipt, bootstrap, governance, maintenancePolicy } = input;
  if (getNetworkId() !== network.networkId || receipt.networkId !== network.networkId) {
    throw new Error("Midnight.js network does not match the approved transition network");
  }
  if (input.stagedVerifierKeyInstallation && network.networkId !== "undeployed") {
    throw new Error("Staged verifier-key transition is local-only");
  }
  if (!HASH.test(receipt.contractAddress) || /^0x0{64}$/u.test(receipt.contractAddress)
    || !HASH.test(image.finalizedBlockHash) || /^0x0{64}$/u.test(image.finalizedBlockHash)) {
    throw new Error("Committee transition requires a canonical address and finalized block hash");
  }
  if (!KEY.test(input.bootstrapMaintenanceVerifyingKey)
    || /^0x0{64}$/u.test(input.bootstrapMaintenanceVerifyingKey)) {
    throw new Error("Bootstrap maintenance verifying key must be canonical and nonzero");
  }
  validateMaintenancePolicy(maintenancePolicy);
  if (governance.policyVersion < 1n || governance.actionSequence < 1n
    || governance.maintainerThreshold < 2n || governance.activeMaintainerCount < 3n) {
    throw new Error("Committee transition requires approved multi-party governance pins");
  }
  if (!matchesPinnedRegistryImage({
    networkId: network.networkId, receipt, bootstrap, releaseManifest: input.releaseManifest, governance,
  }, image)) {
    throw new Error("Finalized deployment image disagrees with approved registry or verifier-key pins");
  }
  const current = image.maintenanceAuthority;
  const expectedCounter = input.stagedVerifierKeyInstallation
    ? BigInt(Object.keys(input.releaseManifest.verifierKeySha256).length - 1) : 0n;
  if (current.counter !== expectedCounter || current.threshold !== 1
    || current.committee.length !== 1
    || current.committee[0] !== input.bootstrapMaintenanceVerifyingKey) {
    throw new Error("Finalized maintenance authority is not the approved bootstrap key at the expected counter");
  }
  const expiresAt = new Date(input.expiresAt?.getTime());
  const remainingMs = expiresAt.getTime() - Date.now();
  if (!Number.isFinite(remainingMs) || remainingMs <= 0 || remainingMs > 10 * 60_000) {
    throw new Error("Committee transition expiry must be within the next ten minutes");
  }

  const nextAuthority = new ContractMaintenanceAuthority(
    maintenancePolicy.verifyingKeys.map((key) => key.slice(2)),
    maintenancePolicy.threshold,
    current.counter + 1n,
  );
  const update = new MaintenanceUpdate(
    receipt.contractAddress.slice(2),
    [new ReplaceAuthority(nextAuthority)],
    current.counter,
  );
  const dataToSign = Uint8Array.from(update.dataToSign);
  const networkId = network.networkId;
  const expectedKey = input.bootstrapMaintenanceVerifyingKey.slice(2);
  const committeeVerifyingKeys = Object.freeze([...maintenancePolicy.verifyingKeys]);

  return {
    networkId,
    contractAddress: receipt.contractAddress,
    finalizedBlockHash: image.finalizedBlockHash,
    committeeVerifyingKeys,
    threshold: maintenancePolicy.threshold,
    currentAuthorityCounter: current.counter,
    nextAuthorityCounter: nextAuthority.counter,
    expiresAt: expiresAt.toISOString(),
    dataToSign: Uint8Array.from(dataToSign),
    authorize(signature: Signature): UnprovenTransaction {
      if (getNetworkId() !== networkId || Date.now() >= expiresAt.getTime()) {
        throw new Error("Committee transition network changed or signing window expired");
      }
      let valid = false;
      try {
        valid = verifySignature(expectedKey, dataToSign, signature);
      } catch {
        // A malformed signature is an authorization failure, not a parsing detail to expose.
      }
      if (!valid) throw new Error("Bootstrap maintenance signature is invalid");
      const signedUpdate = update.addSignature(0n, signature);
      return Transaction.fromParts(
        networkId,
        undefined,
        undefined,
        Intent.new(expiresAt).addMaintenanceUpdate(signedUpdate),
      );
    },
  };
}

/** Obtains the image using a node-genesis-pinned finality checkpoint before preparing. */
export async function preparePublicNetworkCommitteeTransition(
  input: CommitteeTransitionApproval,
): Promise<PreparedCommitteeTransition> {
  if ((input.network.networkId as string) === "undeployed") {
    throw new Error("Public committee transition does not accept the undeployed network");
  }
  if (getNetworkId() !== input.network.networkId) {
    throw new Error("Midnight.js network does not match the approved transition network");
  }
  const reader = await createPublicNetworkDeploymentActionReader(input.network);
  const image = await reader.readCurrentFinalizedDeploymentImage(
    input.receipt.contractAddress,
    input.bootstrap.maintainerKeyId,
  );
  if (image === null) throw new Error("Finalized deployment image is unavailable");
  return prepareCommitteeTransitionFromFinalizedImage(input, image);
}

/** Prepares a local-only transition using a genesis-pinned `undeployed` finalized image. */
export async function prepareLocalNetworkCommitteeTransition(
  input: LocalCommitteeTransitionApproval,
): Promise<PreparedCommitteeTransition> {
  if (input.network.networkId !== "undeployed" || getNetworkId() !== "undeployed") {
    throw new Error("Local committee transition requires the undeployed network");
  }
  const reader = await createLocalNetworkDeploymentActionReader(input.network);
  const image = await reader.readCurrentFinalizedDeploymentImage(
    input.receipt.contractAddress,
    input.bootstrap.maintainerKeyId,
  );
  if (image === null) throw new Error("Finalized local deployment image is unavailable");
  return prepareCommitteeTransitionFromFinalizedImage(input, image);
}
