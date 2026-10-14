import { z } from "zod";
import { ApplicationEvidenceSubmissionSchema } from "@midnight-ntwrk/trust-registry-domain";

const Bytes32Schema = z.string().regex(/^0x[0-9a-f]{64}$/u);

export const GovernedProposalObservationSchema = z.strictObject({
  eventHash: Bytes32Schema,
  evidenceCommitment: Bytes32Schema,
});

export const GovernedProposalResolveRequestSchema = z.strictObject({
  evidence: ApplicationEvidenceSubmissionSchema,
});

export type GovernedProposalObservation = z.infer<typeof GovernedProposalObservationSchema>;
