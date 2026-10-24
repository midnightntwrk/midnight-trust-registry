import { Buffer } from "node:buffer";

import { TrustRegistryContract } from "@midnight-ntwrk/trust-registry-contract";
import { MaintainerStatus } from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import type { FinalizedProposalLedgerReader } from "./compact-proposal-observation.js";
import type { GovernedMembershipSigner } from "./governed-membership-actions.js";

export class StaleProposalQuorumContextError extends Error {}
export class InvalidProposalQuorumError extends Error {}

type PreparedQuorumContext = {
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionSequence: bigint;
};

/** Reject only deterministic pre-broadcast failures; Compact still rechecks at execution. */
export async function assertCurrentProposalQuorum(
  readFinalizedLedger: FinalizedProposalLedgerReader,
  context: PreparedQuorumContext,
  signers: readonly GovernedMembershipSigner[],
): Promise<void> {
  const ledger = await readFinalizedLedger();
  if (!ledger.initialized || ledger.contractVersion !== 1n) {
    throw new Error("Finalized proposal ledger is not initialized");
  }
  if (context.actionSequence !== ledger.governanceActionCount
    || !Buffer.from(context.policyCommitment).equals(Buffer.from(ledger.governancePolicyCommitment))) {
    throw new StaleProposalQuorumContextError("Prepared proposal policy or sequence is stale");
  }
  const threshold = TrustRegistryContract.pureCircuits.actionScopedMaintainerThreshold(
    context.actionKind, ledger.maintainerThreshold,
    ledger.emergencyMaintainerThreshold, ledger.archivalMaintainerThreshold,
  );
  if (threshold < 1n || threshold > 5n) {
    throw new Error("Finalized maintainer threshold is invalid");
  }
  if (BigInt(signers.length) < threshold || signers.length > 5) {
    throw new InvalidProposalQuorumError("Maintainer signer count does not meet the action threshold");
  }
  const seen = new Set<string>();
  for (const signer of signers) {
    const key = Buffer.from(signer.keyId).toString("hex");
    if (seen.has(key) || !ledger.maintainerKeyIds.member(signer.keyId)) {
      throw new InvalidProposalQuorumError("Maintainer signer key is duplicated or unregistered");
    }
    seen.add(key);
    const record = ledger.maintainerRecords.lookup(signer.keyId);
    if (record.status !== MaintainerStatus.active
      || !Buffer.from(record.keyId).equals(Buffer.from(signer.keyId))
      || record.publicKey.x !== signer.publicKey.x
      || record.publicKey.y !== signer.publicKey.y) {
      throw new InvalidProposalQuorumError("Maintainer signer key is not current and active");
    }
  }
}
