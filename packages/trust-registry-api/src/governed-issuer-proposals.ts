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
import type { GovernedProposalObservation } from "./governed-proposal-observation.js";

const Bytes32Schema = z.string().regex(/^0x[0-9a-f]{64}$/u);
const ScalarSchema = z.string().regex(/^(0|[1-9][0-9]{0,78})$/u);

export const PreparedGovernedIssuerProposalSchema = z.strictObject({
  registryId: Bytes32Schema,
  networkIdCommitment: Bytes32Schema,
  contractAddress: Bytes32Schema,
  authorizationId: Bytes32Schema,
  policyCommitment: Bytes32Schema,
  policyVersion: ScalarSchema,
  actionKind: Bytes32Schema,
  actionPayloadHash: Bytes32Schema,
  actionSequence: ScalarSchema,
  evidenceHash: Bytes32Schema,
  statusPolicyBindingCommitment: Bytes32Schema,
  evidenceVerifierAuthorizationId: Bytes32Schema,
  evidenceVerifierKeyIdCommitment: Bytes32Schema,
});

export const GovernedIssuerProposalPrepareRequestSchema = z.strictObject({
  evidence: ApplicationEvidenceSubmissionSchema,
});

export const GovernedIssuerProposalSubmitRequestSchema = z.strictObject({
  evidence: ApplicationEvidenceSubmissionSchema,
  prepared: PreparedGovernedIssuerProposalSchema,
  signers: GovernedMembershipSignersSchema,
  evidenceVerifierSignature: z.string().regex(/^0x[0-9a-f]+$/u),
});

export type PreparedGovernedIssuerProposal = z.infer<typeof PreparedGovernedIssuerProposalSchema>;
export type GovernedIssuerProposalContext = {
  registryId: Uint8Array;
  networkIdCommitment: Uint8Array;
  contractAddress: Uint8Array;
  authorizationId: Uint8Array;
  policyCommitment: Uint8Array;
  policyVersion: bigint;
  actionKind: Uint8Array;
  actionPayloadHash: Uint8Array;
  actionSequence: bigint;
  evidenceHash: Uint8Array;
  statusPolicyBindingCommitment: Uint8Array;
  evidenceVerifierAuthorizationId: Uint8Array;
  evidenceVerifierKeyIdCommitment: Uint8Array;
};

export type GovernedIssuerProposalPort = {
  /** Verify the signed application evidence against the active policy and current Compact context. */
  prepare(authorizationId: string, evidence: ApplicationEvidenceSubmission): Promise<GovernedIssuerProposalContext>;
  /** Reject known-invalid submissions without broadcasting; required when a durable journal is configured. */
  preflightSubmission?(
    authorizationId: string, evidence: ApplicationEvidenceSubmission,
    signers: readonly GovernedMembershipSigner[],
    evidenceVerifierSignature: TrustRegistryJubjubSignature,
    context: GovernedIssuerProposalContext,
  ): Promise<void>;
  /** Recheck evidence, quorum, policy, and sequence in Compact before accepting. */
  execute(
    authorizationId: string,
    evidence: ApplicationEvidenceSubmission,
    signers: readonly GovernedMembershipSigner[],
    evidenceVerifierSignature: TrustRegistryJubjubSignature,
  ): Promise<GovernedMembershipActionReceipt>;
  /** Return only finalized, ledger-observed proposal evidence; null is not proof that submission failed. */
  resolve?(authorizationId: string): Promise<GovernedProposalObservation | null>;
};

export class GovernedIssuerProposalRejectedError extends Error {
  constructor(readonly reason: "unknown-authorization" | "invalid-evidence" | "invalid-signers") {
    super(`Governed issuer proposal rejected: ${reason}`);
    this.name = "GovernedIssuerProposalRejectedError";
  }
}

const bytes32Hex = (value: Uint8Array): string => {
  if (value.length !== 32) throw new RangeError("Proposal context must contain bytes32 values");
  return `0x${Buffer.from(value).toString("hex")}`;
};

export const serializeGovernedIssuerProposal = (
  context: GovernedIssuerProposalContext,
): PreparedGovernedIssuerProposal => PreparedGovernedIssuerProposalSchema.parse({
  registryId: bytes32Hex(context.registryId),
  networkIdCommitment: bytes32Hex(context.networkIdCommitment),
  contractAddress: bytes32Hex(context.contractAddress),
  authorizationId: bytes32Hex(context.authorizationId),
  policyCommitment: bytes32Hex(context.policyCommitment),
  policyVersion: context.policyVersion.toString(),
  actionKind: bytes32Hex(context.actionKind),
  actionPayloadHash: bytes32Hex(context.actionPayloadHash),
  actionSequence: context.actionSequence.toString(),
  evidenceHash: bytes32Hex(context.evidenceHash),
  statusPolicyBindingCommitment: bytes32Hex(context.statusPolicyBindingCommitment),
  evidenceVerifierAuthorizationId: bytes32Hex(context.evidenceVerifierAuthorizationId),
  evidenceVerifierKeyIdCommitment: bytes32Hex(context.evidenceVerifierKeyIdCommitment),
});

export const sameGovernedIssuerProposal = (
  current: PreparedGovernedIssuerProposal,
  submitted: PreparedGovernedIssuerProposal,
): boolean => Object.keys(current).every((key) =>
  current[key as keyof PreparedGovernedIssuerProposal] === submitted[key as keyof PreparedGovernedIssuerProposal]);

export const decodeIssuerEvidenceVerifierSignature = (
  signature: string,
): TrustRegistryJubjubSignature => decodeCanonicalJubjubSignatureHex(signature);
