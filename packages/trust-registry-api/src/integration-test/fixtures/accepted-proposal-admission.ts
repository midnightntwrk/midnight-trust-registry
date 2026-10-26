import {
  ApplicationChallengeBindingSchema,
  type ApplicationChallengeBinding,
  type ApplicationEvidenceSubmission,
} from "@midnight-ntwrk/trust-registry-domain";

import type { ProposalAdmissionPort } from "../../proposal-admission.js";

export const acceptedProposalAdmission = (
  authorizationId: string,
  scope: ApplicationChallengeBinding["scope"],
  evidence: ApplicationEvidenceSubmission,
): ProposalAdmissionPort => {
  const envelope = evidence.envelope;
  const binding = ApplicationChallengeBindingSchema.parse({
    registryId: envelope.registryId,
    applicationId: envelope.applicationId,
    subjectDid: envelope.subjectDid,
    evidenceVerifierDid: envelope.evidenceVerifierDid,
    role: envelope.role,
    policyId: envelope.policyId,
    policyVersion: envelope.policyVersion,
    scope,
    scopeCommitment: envelope.scopeCommitment,
    governedResource: envelope.governedResource,
  });
  return {
    resolvePendingApplication: async (applicationId) => applicationId === envelope.applicationId
      ? { authorizationId, binding, status: "pending", createdAt: "2026-05-20T00:00:00.000Z" }
      : null,
    resolveAcceptedEvidence: async (applicationId) => applicationId === envelope.applicationId
      ? { evidence, receipt: { receiptId: `0x${"b2".repeat(32)}`, evidenceCommitment: evidence.commitment,
        acceptedAt: "2026-05-20T00:01:00.000Z" } }
      : null,
  };
};
