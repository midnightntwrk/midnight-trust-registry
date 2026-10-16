import {
  ApplicationChallengeBindingSchema,
  ApplicationEvidenceSubmissionSchema,
  canonicalizeJson,
  computeApplicationEvidenceCommitment,
  type ApplicationEvidenceSubmission,
  type ApplicationEvidenceRole,
} from "@midnight-ntwrk/trust-registry-domain";

import { ApplicationVpReceiptSchema, type ApplicationVpReceipt } from "./application-vp-http.js";
import type { PendingApplicationRecord } from "./pending-application-registration.js";

export type AcceptedApplicationEvidence = {
  evidence: ApplicationEvidenceSubmission;
  receipt: ApplicationVpReceipt;
};

/** Join accepted VP evidence to the original DID-signed pending record in trusted storage. */
export interface ProposalAdmissionPort {
  resolvePendingApplication(applicationId: string): Promise<PendingApplicationRecord | null>;
  resolveAcceptedEvidence(applicationId: string): Promise<AcceptedApplicationEvidence | null>;
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
    const applicationId = submitted.envelope.applicationId;
    const [pending, accepted] = await Promise.all([
      port.resolvePendingApplication(applicationId),
      port.resolveAcceptedEvidence(applicationId),
    ]);
    if (pending === null || accepted === null) throw new ProposalAdmissionRejectedError();
    const binding = ApplicationChallengeBindingSchema.parse(pending.binding);
    const evidence = ApplicationEvidenceSubmissionSchema.parse(accepted.evidence);
    const envelope = evidence.envelope;
    const receipt = ApplicationVpReceiptSchema.parse(accepted.receipt);
    if (pending.status !== "pending" || pending.authorizationId !== authorizationId
      || binding.role !== role || envelope.role !== role
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
