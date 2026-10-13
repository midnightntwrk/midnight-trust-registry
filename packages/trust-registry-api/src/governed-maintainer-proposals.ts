import { z } from "zod";

import {
  decodeCanonicalJubjubSignatureHex,
  type TrustRegistryJubjubSignature,
} from "@midnight-ntwrk/trust-registry-contract";
import {
  ApplicationEvidenceSubmissionSchema,
  type ApplicationEvidenceSubmission,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  GovernedMembershipSignersSchema,
  type GovernedMembershipActionReceipt,
  type GovernedMembershipSigner,
} from "./governed-membership-actions.js";

const Bytes32Schema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const ScalarSchema = z.string().regex(/^(0|[1-9][0-9]{0,78})$/u);

export const PreparedGovernedMaintainerProposalSchema = z.strictObject({
  registryId: Bytes32Schema,
  maintainerId: Bytes32Schema,
  policyCommitment: Bytes32Schema,
  policyVersion: ScalarSchema,
  actionKind: Bytes32Schema,
  actionPayloadHash: Bytes32Schema,
  actionSequence: ScalarSchema,
  evidenceHash: Bytes32Schema,
  evidenceVerifierAuthorizationId: Bytes32Schema,
  evidenceVerifierKeyIdCommitment: Bytes32Schema,
});

export const GovernedMaintainerProposalPrepareRequestSchema = z.strictObject({
  evidence: ApplicationEvidenceSubmissionSchema,
});

export const GovernedMaintainerProposalSubmitRequestSchema = z.strictObject({
  evidence: ApplicationEvidenceSubmissionSchema,
  prepared: PreparedGovernedMaintainerProposalSchema,
  signers: GovernedMembershipSignersSchema,
  evidenceVerifierSignature: z.string().regex(/^0x[0-9a-f]+$/u),
});

export type PreparedGovernedMaintainerProposal = z.infer<typeof PreparedGovernedMaintainerProposalSchema>;
export type GovernedMaintainerProposalContext = {
  registryId: Uint8Array;
  maintainerId: Uint8Array;
  policyCommitment: Uint8Array;
  policyVersion: bigint;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  evidenceHash: Uint8Array;
  evidenceVerifierAuthorizationId: Uint8Array;
  evidenceVerifierKeyIdCommitment: Uint8Array;
};

export type GovernedMaintainerProposalPort = {
  prepare(maintainerId: string, evidence: ApplicationEvidenceSubmission): Promise<GovernedMaintainerProposalContext>;
  execute(
    maintainerId: string,
    evidence: ApplicationEvidenceSubmission,
    signers: readonly GovernedMembershipSigner[],
    evidenceVerifierSignature: TrustRegistryJubjubSignature,
  ): Promise<GovernedMembershipActionReceipt>;
};

export class GovernedMaintainerProposalRejectedError extends Error {
  constructor(readonly reason: "unknown-maintainer" | "invalid-evidence" | "invalid-signers") {
    super(`Governed maintainer proposal rejected: ${reason}`);
    this.name = "GovernedMaintainerProposalRejectedError";
  }
}

const bytes32Hex = (value: Uint8Array): string => {
  if (value.length !== 32) throw new RangeError("Proposal context must contain bytes32 values");
  return `0x${Buffer.from(value).toString("hex")}`;
};

export const serializeGovernedMaintainerProposal = (
  context: GovernedMaintainerProposalContext,
): PreparedGovernedMaintainerProposal => PreparedGovernedMaintainerProposalSchema.parse({
  registryId: bytes32Hex(context.registryId),
  maintainerId: bytes32Hex(context.maintainerId),
  policyCommitment: bytes32Hex(context.policyCommitment),
  policyVersion: context.policyVersion.toString(),
  actionKind: bytes32Hex(context.actionKind),
  actionPayloadHash: bytes32Hex(context.actionPayloadHash),
  actionSequence: context.actionSequence.toString(),
  evidenceHash: bytes32Hex(context.evidenceHash),
  evidenceVerifierAuthorizationId: bytes32Hex(context.evidenceVerifierAuthorizationId),
  evidenceVerifierKeyIdCommitment: bytes32Hex(context.evidenceVerifierKeyIdCommitment),
});

export const sameGovernedMaintainerProposal = (
  current: PreparedGovernedMaintainerProposal,
  submitted: PreparedGovernedMaintainerProposal,
): boolean => Object.keys(current).every((key) =>
  current[key as keyof PreparedGovernedMaintainerProposal] === submitted[key as keyof PreparedGovernedMaintainerProposal]);

export const decodeMaintainerEvidenceVerifierSignature = (
  signature: string,
): TrustRegistryJubjubSignature => decodeCanonicalJubjubSignatureHex(signature);
