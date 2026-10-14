import { withExclusiveWorkspaceWrite } from "@midnight-ntwrk/trust-registry-cli";
import {
  HashHexSchema,
  resolveGovernedRecognitionAccreditorAnchor,
  type GovernancePolicyRecord,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  RecognitionAdmissionReceiptSchema,
  type RecognitionAdmissionReceipt,
  type RecognitionAdmissionStore,
} from "./file-recognition-admission.js";
import {
  RecognitionAuthorityChallengeBindingSchema,
  recognitionAuthorityChallengeBindingHash,
  recognitionAuthorityChallengeIdentityHash,
  type RecognitionAuthorityChallengeBinding,
} from "./recognition-authority-challenges.js";

export type RecognitionProposalAdmissionInput<T> = {
  binding: RecognitionAuthorityChallengeBinding;
  receiptId: string;
  evidenceCommitment: string;
  governanceWorkspacePath: string;
  admissionStore: Pick<RecognitionAdmissionStore, "readAccepted">;
  readCurrentGovernance: () => Promise<{
    governancePolicy: GovernancePolicyRecord;
    activePolicyCommitment: string;
  }>;
  /** Must execute the current-ledger proposal, including its own signature, quorum and sequence checks. */
  execute: (receipt: RecognitionAdmissionReceipt) => Promise<T>;
  clock?: () => number;
};

/** Admission is private evidence, not authority: the governed proposal must run under this same lock. */
export async function withRecognitionProposalAdmission<T>(input: RecognitionProposalAdmissionInput<T>): Promise<T> {
  const binding = RecognitionAuthorityChallengeBindingSchema.parse(input.binding);
  const receiptId = HashHexSchema.parse(input.receiptId).toLowerCase();
  const evidenceCommitment = HashHexSchema.parse(input.evidenceCommitment).toLowerCase();
  if (input.governanceWorkspacePath.length === 0) throw new RangeError("Governance workspace path is required");

  return withExclusiveWorkspaceWrite(input.governanceWorkspacePath, async () => {
    const nowMs = (input.clock ?? Date.now)();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new RangeError("Recognition proposal clock is invalid");
    const candidate = await input.admissionStore.readAccepted(binding.recognitionId);
    if (candidate === null) throw new Error("Recognition proposal has no accepted accreditation evidence");
    const receipt = RecognitionAdmissionReceiptSchema.parse(candidate);
    if (receipt.receiptId !== receiptId
      || receipt.recognitionId !== binding.recognitionId
      || receipt.applicationHash !== recognitionAuthorityChallengeIdentityHash(binding)
      || receipt.bindingHash !== recognitionAuthorityChallengeBindingHash(binding)
      || receipt.evidenceCommitment !== evidenceCommitment
      || receipt.acceptedAtMs > nowMs || receipt.expiresAtMs <= nowMs) {
      throw new Error("Recognition proposal admission does not match current evidence and scope");
    }

    const governance = await input.readCurrentGovernance();
    const { commitment: anchorCommitment } = resolveGovernedRecognitionAccreditorAnchor({
      policy: governance.governancePolicy,
      activePolicyCommitment: governance.activePolicyCommitment,
      scope: {
        registryId: binding.targetRegistryId,
        recognizedRegistryId: binding.recognizedRegistryId,
        scopeResourceType: binding.scopeResourceType,
        scopeResourceId: binding.scopeResourceId,
      },
      evaluatedAtMs: nowMs,
    });
    if (receipt.policyCommitment !== HashHexSchema.parse(governance.activePolicyCommitment).toLowerCase()
      || receipt.anchorCommitment !== anchorCommitment
      || (input.clock ?? Date.now)() >= receipt.expiresAtMs) {
      throw new Error("Recognition proposal admission is stale");
    }
    return input.execute(receipt);
  });
}
