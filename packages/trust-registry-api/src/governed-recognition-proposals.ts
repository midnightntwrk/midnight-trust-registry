import { z } from "zod";

import {
  decodeCanonicalJubjubSignatureHex,
  type TrustRegistryJubjubSignature,
} from "@midnight-ntwrk/trust-registry-contract";
import type { GovernancePolicyRecord } from "@midnight-ntwrk/trust-registry-domain";

import {
  GovernedMembershipSignersSchema,
  type GovernedMembershipActionReceipt,
  type GovernedMembershipSigner,
} from "./governed-membership-actions.js";
import type { RecognitionAdmissionStore } from "./file-recognition-admission.js";
import type { RecognitionAuthorityChallengeBinding } from "./recognition-authority-challenges.js";

const Bytes32Schema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const ScalarSchema = z.string().regex(/^(0|[1-9][0-9]{0,78})$/u);

export const PreparedGovernedRecognitionProposalSchema = z.strictObject({
  registryId: Bytes32Schema,
  recognitionId: Bytes32Schema,
  policyCommitment: Bytes32Schema,
  actionKind: Bytes32Schema,
  actionPayloadHash: Bytes32Schema,
  actionSequence: ScalarSchema,
  evidenceHash: Bytes32Schema,
  evidenceVerifierAuthorizationId: Bytes32Schema,
  evidenceVerifierKeyIdCommitment: Bytes32Schema,
});
export type PreparedGovernedRecognitionProposal = z.infer<typeof PreparedGovernedRecognitionProposalSchema>;

export const GovernedRecognitionProposalPrepareRequestSchema = z.strictObject({
  receiptId: Bytes32Schema,
  evidenceCommitment: Bytes32Schema,
});
export const GovernedRecognitionProposalSubmitRequestSchema = GovernedRecognitionProposalPrepareRequestSchema.extend({
  prepared: PreparedGovernedRecognitionProposalSchema,
  signers: GovernedMembershipSignersSchema,
  evidenceVerifierSignature: z.string().regex(/^0x[0-9a-f]+$/u),
});

export type GovernedRecognitionProposalContext = {
  registryId: Uint8Array;
  recognitionId: Uint8Array;
  policyCommitment: Uint8Array;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  evidenceHash: Uint8Array;
  evidenceVerifierAuthorizationId: Uint8Array;
  evidenceVerifierKeyIdCommitment: Uint8Array;
};

export type GovernedRecognitionProposalPort = {
  governanceWorkspacePath: string;
  admissionStore: Pick<RecognitionAdmissionStore, "readAccepted">;
  /** Both binding and policy must come from server-controlled state, never the request. */
  readBinding(recognitionId: string): Promise<RecognitionAuthorityChallengeBinding>;
  readCurrentGovernance(): Promise<{
    governancePolicy: GovernancePolicyRecord;
    activePolicyCommitment: string;
  }>;
  /** Derive the current Compact context for this exact recognized scope and evidence hash. */
  prepare(binding: RecognitionAuthorityChallengeBinding, evidenceCommitment: string): Promise<GovernedRecognitionProposalContext>;
  /** Recheck current ledger state and Compact signatures/quorum/sequence before accepting. */
  execute(
    binding: RecognitionAuthorityChallengeBinding,
    evidenceCommitment: string,
    signers: readonly GovernedMembershipSigner[],
    evidenceVerifierSignature: TrustRegistryJubjubSignature,
    prepared: GovernedRecognitionProposalContext,
  ): Promise<GovernedMembershipActionReceipt>;
};

export class GovernedRecognitionProposalRejectedError extends Error {
  constructor(readonly reason: "unknown-recognition" | "invalid-evidence" | "invalid-signers") {
    super(`Governed recognition proposal rejected: ${reason}`);
    this.name = "GovernedRecognitionProposalRejectedError";
  }
}

const bytes32Hex = (value: Uint8Array): string => {
  if (value.length !== 32) throw new RangeError("Recognition proposal context must contain bytes32 values");
  return `0x${Buffer.from(value).toString("hex")}`;
};

export const serializeGovernedRecognitionProposal = (
  context: GovernedRecognitionProposalContext,
): PreparedGovernedRecognitionProposal => PreparedGovernedRecognitionProposalSchema.parse({
  registryId: bytes32Hex(context.registryId),
  recognitionId: bytes32Hex(context.recognitionId),
  policyCommitment: bytes32Hex(context.policyCommitment),
  actionKind: bytes32Hex(context.actionKind),
  actionPayloadHash: bytes32Hex(context.actionPayloadHash),
  actionSequence: context.actionSequence.toString(),
  evidenceHash: bytes32Hex(context.evidenceHash),
  evidenceVerifierAuthorizationId: bytes32Hex(context.evidenceVerifierAuthorizationId),
  evidenceVerifierKeyIdCommitment: bytes32Hex(context.evidenceVerifierKeyIdCommitment),
});

export const sameGovernedRecognitionProposal = (
  current: PreparedGovernedRecognitionProposal,
  submitted: PreparedGovernedRecognitionProposal,
): boolean => Object.keys(current).every((key) =>
  current[key as keyof PreparedGovernedRecognitionProposal]
    === submitted[key as keyof PreparedGovernedRecognitionProposal]);

export const decodeRecognitionEvidenceVerifierSignature = (
  signature: string,
): TrustRegistryJubjubSignature => decodeCanonicalJubjubSignatureHex(signature);
