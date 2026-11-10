import {
  GovernedVerifierProposalPrepareRequestSchema,
  GovernedVerifierProposalSubmitRequestSchema,
  PreparedGovernedVerifierProposalSchema,
  decodeVerifierEvidenceVerifierSignature,
  sameGovernedVerifierProposal,
  serializeGovernedVerifierProposal,
  type GovernedVerifierProposalContext,
  type GovernedVerifierProposalPort,
  type PreparedGovernedVerifierProposal,
} from "./governed-verifier-proposals.js";

// The wire context is shared; the auditor domain separator and signature check live in Compact.
export const GovernedAuditorProposalPrepareRequestSchema = GovernedVerifierProposalPrepareRequestSchema;
export const GovernedAuditorProposalSubmitRequestSchema = GovernedVerifierProposalSubmitRequestSchema;
export const PreparedGovernedAuditorProposalSchema = PreparedGovernedVerifierProposalSchema;
export const decodeAuditorEvidenceVerifierSignature = decodeVerifierEvidenceVerifierSignature;
export const sameGovernedAuditorProposal = sameGovernedVerifierProposal;
export const serializeGovernedAuditorProposal = serializeGovernedVerifierProposal;
export type GovernedAuditorProposalContext = GovernedVerifierProposalContext;
export type GovernedAuditorProposalPort = GovernedVerifierProposalPort;
export type PreparedGovernedAuditorProposal = PreparedGovernedVerifierProposal;

export class GovernedAuditorProposalRejectedError extends Error {
  constructor(readonly reason: "unknown-authorization" | "invalid-evidence" | "invalid-signers") {
    super(`Governed auditor proposal rejected: ${reason}`);
    this.name = "GovernedAuditorProposalRejectedError";
  }
}
