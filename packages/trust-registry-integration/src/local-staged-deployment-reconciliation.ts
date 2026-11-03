import { getNetworkId } from "@midnight-ntwrk/midnight-js-network-id";

import { FinalizedDeploymentImageInvalidError } from "./finalized-deployment-action-reader.js";
import {
  createLocalNetworkDeploymentActionReader,
  type LocalNetworkDeploymentActionReaderConfig,
} from "./local-network-deployment-action-reader.js";
import {
  matchesPinnedRegistryImageWithKeySubset,
  type PublicRegistryBootstrap,
  type PublicRegistryDeploymentReceipt,
  type ReleaseVerifierKeyManifest,
} from "./public-network-deployment.js";

export type LocalStagedDeploymentReconciliation = {
  status: "staged-bootstrap-pending" | "pending" | "invalid-image" | "unavailable" | "mismatch";
  finalizedBlockHash?: string;
};

/** Re-reads the one-key bootstrap at an independently pinned local finalized checkpoint. */
export async function reconcileLocalStagedDeployment(input: {
  network: LocalNetworkDeploymentActionReaderConfig;
  receipt: PublicRegistryDeploymentReceipt;
  bootstrap: PublicRegistryBootstrap;
  releaseManifest: ReleaseVerifierKeyManifest;
  initialVerifierKeyName: string;
  bootstrapMaintenanceVerifyingKey: string;
}): Promise<LocalStagedDeploymentReconciliation> {
  if (getNetworkId() !== "undeployed" || input.network.networkId !== "undeployed"
    || input.receipt.networkId !== "undeployed"
    || !/^0x[0-9a-f]{64}$/u.test(input.receipt.contractAddress)
    || /^0x0{64}$/u.test(input.receipt.contractAddress)
    || !/^0x[0-9a-f]{64}$/u.test(input.bootstrapMaintenanceVerifyingKey)
    || /^0x0{64}$/u.test(input.bootstrapMaintenanceVerifyingKey)) {
    throw new Error("Staged deployment reconciliation requires canonical local deployment pins");
  }
  const reader = await createLocalNetworkDeploymentActionReader(input.network);
  let image;
  try {
    image = await reader.readCurrentFinalizedDeploymentImage(
      input.receipt.contractAddress, input.bootstrap.maintainerKeyId,
    );
  } catch (error) {
    return { status: error instanceof FinalizedDeploymentImageInvalidError ? "invalid-image" : "unavailable" };
  }
  if (image === null) return { status: "pending" };
  const matches = matchesPinnedRegistryImageWithKeySubset({
    networkId: "undeployed",
    receipt: input.receipt,
    bootstrap: input.bootstrap,
    releaseManifest: input.releaseManifest,
    governance: {
      policyCommitment: input.bootstrap.governancePolicyCommitment,
      policyVersion: 1n,
      actionSequence: 1n,
      maintainerThreshold: 1n,
      activeMaintainerCount: 1n,
    },
  }, image, [input.initialVerifierKeyName]);
  return {
    status: matches
      && image.emergencyMaintainerThreshold === 1n
      && image.archivalMaintainerThreshold === 1n
      && image.maintenanceAuthority.threshold === 1
      && image.maintenanceAuthority.counter === 0n
      && image.maintenanceAuthority.committee.length === 1
      && image.maintenanceAuthority.committee[0] === input.bootstrapMaintenanceVerifyingKey
      ? "staged-bootstrap-pending" : "mismatch",
    finalizedBlockHash: image.finalizedBlockHash,
  };
}
