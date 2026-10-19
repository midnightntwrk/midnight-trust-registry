import { createHash } from "node:crypto";

import { getNetworkId } from "@midnight-ntwrk/midnight-js-network-id";
import { ContractMaintenanceAuthority, MaintenanceUpdate, ReplaceAuthority } from "@midnight-ntwrk/midnight-js-protocol/ledger";

import {
  readPostDeploymentLocalTrustRegistry,
  readPostDeploymentPublicTrustRegistry,
  validateMaintenancePolicy,
  type PublicRegistryDeploymentReadback,
} from "./public-network-deployment.js";
import type {
  CommitteeTransitionApproval,
  LocalCommitteeTransitionApproval,
} from "./public-maintenance-transition.js";
import { FileMaintenanceTransitionJournal } from "./public-maintenance-submission.js";

const HASH = /^[0-9a-f]{64}$/u;
const BLOCK = /^0x[0-9a-f]{64}$/u;

export type MaintenanceTransitionReconciliation =
  | { status: "not-reserved" }
  | { status: "unavailable" | "pending" | "invalid-image" | "stale-checkpoint" | "unresolved" | "conflict" | "observed";
      txId: string | null; finalizedBlockHash: string | null; };

type ReconciliationInput<Network extends { networkId: string }> = {
  approval: CommitteeTransitionApproval<Network>;
  journal: FileMaintenanceTransitionJournal;
  /** Independently retained from the exact plan shown to the maintenance custodian. */
  approvedUpdateSha256: string;
  approvedFinalizedBlockHash: string;
};

/** Reports finalized state only; no result from this function permits an automatic retry. */
export async function reconcilePublicNetworkCommitteeTransition(
  input: ReconciliationInput<CommitteeTransitionApproval["network"]>,
): Promise<MaintenanceTransitionReconciliation> {
  if ((input.approval.network.networkId as string) === "undeployed") {
    throw new Error("Public reconciliation does not accept the undeployed network");
  }
  return reconcilePinnedCommitteeTransition(input, () => readPostDeploymentPublicTrustRegistry({
    ...input.approval,
  }));
}

/** Uses only the local genesis-pinned readback; never authorizes a retry. */
export async function reconcileLocalNetworkCommitteeTransition(
  input: ReconciliationInput<LocalCommitteeTransitionApproval["network"]>,
): Promise<MaintenanceTransitionReconciliation> {
  if (input.approval.network.networkId !== "undeployed") {
    throw new Error("Local reconciliation requires the undeployed network");
  }
  return reconcilePinnedCommitteeTransition(input, () => readPostDeploymentLocalTrustRegistry({
    ...input.approval,
  }));
}

async function reconcilePinnedCommitteeTransition(
  input: ReconciliationInput<{ networkId: string }>,
  readPostDeployment: () => Promise<PublicRegistryDeploymentReadback>,
): Promise<MaintenanceTransitionReconciliation> {
  const { approval } = input;
  if (getNetworkId() !== approval.network.networkId || approval.receipt.networkId !== approval.network.networkId) {
    throw new Error("Midnight.js network does not match the approved transition network");
  }
  if (!HASH.test(input.approvedUpdateSha256) || !BLOCK.test(input.approvedFinalizedBlockHash)
    || /^0x0{64}$/u.test(input.approvedFinalizedBlockHash)
    || !BLOCK.test(approval.receipt.contractAddress)
    || /^0x0{64}$/u.test(approval.receipt.contractAddress)) {
    throw new Error("Approved maintenance transition evidence pins are invalid");
  }
  validateMaintenancePolicy(approval.maintenancePolicy);
  const authority = new ContractMaintenanceAuthority(
    approval.maintenancePolicy.verifyingKeys.map((key) => key.slice(2)),
    approval.maintenancePolicy.threshold,
    1n,
  );
  const update = new MaintenanceUpdate(
    approval.receipt.contractAddress.slice(2), [new ReplaceAuthority(authority)], 0n,
  );
  const computedUpdateSha256 = createHash("sha256").update(update.dataToSign).digest("hex");
  if (computedUpdateSha256 !== input.approvedUpdateSha256) {
    throw new Error("Approved maintenance update hash disagrees with the approved committee policy");
  }
  const entry = await input.journal.inspect();
  if (entry === null) return { status: "not-reserved" };
  const { reservation, submitted } = entry;
  if (reservation.networkId !== approval.network.networkId
    || reservation.contractAddress !== approval.receipt.contractAddress
    || reservation.finalizedBlockHash !== input.approvedFinalizedBlockHash
    || reservation.updateSha256 !== input.approvedUpdateSha256
    || reservation.currentAuthorityCounter !== "0"
    || reservation.nextAuthorityCounter !== "1"
    || reservation.expiresAt !== approval.expiresAt.toISOString()
    || reservation.threshold !== approval.maintenancePolicy.threshold
    || reservation.committeeVerifyingKeys.length !== approval.maintenancePolicy.verifyingKeys.length
    || reservation.committeeVerifyingKeys.some((key, index) => key !== approval.maintenancePolicy.verifyingKeys[index])) {
    throw new Error("Maintenance journal disagrees with independently approved transition evidence");
  }
  const txId = submitted?.txId ?? null;
  const readback = await readPostDeployment();
  if (readback.status === "pending" || readback.status === "unavailable" || readback.status === "invalid-image") {
    return { status: readback.status, txId, finalizedBlockHash: null };
  }
  const state = readback.state;
  if (state.finalizedBlockHash === input.approvedFinalizedBlockHash) {
    const current = state.maintenanceAuthority;
    return { status: readback.status === "unsafe-maintenance-authority"
      && current.counter === 0n && current.threshold === 1
      && current.committee.length === 1
      && current.committee[0] === approval.bootstrapMaintenanceVerifyingKey
      ? "stale-checkpoint" : "conflict", txId, finalizedBlockHash: state.finalizedBlockHash };
  }
  if (readback.status === "verified" && state.maintenanceAuthority.counter === 1n) {
    return { status: "observed", txId, finalizedBlockHash: state.finalizedBlockHash };
  }
  const current = state.maintenanceAuthority;
  if (readback.status === "unsafe-maintenance-authority"
    && current.counter === 0n && current.threshold === 1
    && current.committee.length === 1
    && current.committee[0] === approval.bootstrapMaintenanceVerifyingKey) {
    return { status: "unresolved", txId, finalizedBlockHash: state.finalizedBlockHash };
  }
  return { status: "conflict", txId, finalizedBlockHash: state.finalizedBlockHash };
}
