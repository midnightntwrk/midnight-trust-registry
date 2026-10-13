import {
  ApplicationChallengeBindingSchema,
  ApplicationEvidenceSubmissionSchema,
  canonicalizeJson,
  computeApplicationEvidenceCommitment,
  type ApplicationChallengeBinding,
  type ApplicationEvidenceSubmission,
  type ApplicationEvidenceRole,
} from "@midnight-ntwrk/trust-registry-domain";

import { ApplicationVpReceiptSchema, type ApplicationVpReceipt } from "./application-vp-http.js";

export type AcceptedApplicationForProposal = {
  authorizationId: string;
  binding: ApplicationChallengeBinding;
  evidence: ApplicationEvidenceSubmission;
  receipt: ApplicationVpReceipt;
};

/** Resolve only committed, accepted VP intake records; never trust the proposal body as the source. */
export interface ProposalAdmissionPort {
  resolveAcceptedApplication(applicationId: string): Promise<AcceptedApplicationForProposal | null>;
}

export class ProposalAdmissionRejectedError extends Error {
  constructor() {
    super("The proposal is not backed by an accepted application VP");
    this.name = "ProposalAdmissionRejectedError";
  }
}

export async function assertProposalAdmission(
  port: ProposalAdmissionPort,
  role: ApplicationEvidenceRole,
  authorizationId: string,
  submittedEvidence: ApplicationEvidenceSubmission,
): Promise<void> {
  try {
    const submitted = ApplicationEvidenceSubmissionSchema.parse(submittedEvidence);
    const accepted = await port.resolveAcceptedApplication(submitted.envelope.applicationId);
    if (accepted === null) throw new ProposalAdmissionRejectedError();
    const binding = ApplicationChallengeBindingSchema.parse(accepted.binding);
    const evidence = ApplicationEvidenceSubmissionSchema.parse(accepted.evidence);
    const envelope = evidence.envelope;
    const receipt = ApplicationVpReceiptSchema.parse(accepted.receipt);
    if (accepted.authorizationId !== authorizationId || binding.role !== role || envelope.role !== role
      || binding.applicationId !== envelope.applicationId
      || binding.registryId !== envelope.registryId
      || binding.subjectDid !== envelope.subjectDid
      || binding.policyId !== envelope.policyId
      || binding.policyVersion !== envelope.policyVersion
      || binding.scopeCommitment !== envelope.scopeCommitment
      || binding.evidenceVerifierDid !== envelope.evidenceVerifierDid
      || binding.governedResource.type !== envelope.governedResource.type
      || binding.governedResource.id !== envelope.governedResource.id
      || receipt.evidenceCommitment !== evidence.commitment
      || computeApplicationEvidenceCommitment(envelope) !== evidence.commitment
      || canonicalizeJson(submitted) !== canonicalizeJson(evidence)) {
      throw new ProposalAdmissionRejectedError();
    }
  } catch {
    throw new ProposalAdmissionRejectedError();
  }
}
