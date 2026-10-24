import {
  ApplicationChallengeBindingSchema,
  type ApplicationChallengeBinding,
  type ApplicationEvidenceSubmission,
} from "@midnight-ntwrk/trust-registry-domain";

import type { ProposalAdmissionPort } from "../../proposal-admission.js";
import type { ProposalReservationContext, ProposalSubmissionJournal } from "../../proposal-submission-journal.js";

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

export const captureProposalJournalContexts = (): {
  journal: ProposalSubmissionJournal;
  contexts: Array<ProposalReservationContext | undefined>;
} => {
  const contexts: Array<ProposalReservationContext | undefined> = [];
  return {
    contexts,
    journal: {
      executeOnce: async (_role, _authorizationId, _evidenceCommitment, execute, context) => {
        contexts.push(context);
        return execute();
      },
      reconcile: async (role, authorizationId, readFinalized) => {
        const observation = await readFinalized(role, authorizationId);
        if (observation === null) throw new Error("Expected finalized proposal observation");
        return { role, authorizationId, evidenceCommitment: observation.evidenceCommitment,
          state: "observed", eventHash: observation.eventHash };
      },
    },
  };
};
