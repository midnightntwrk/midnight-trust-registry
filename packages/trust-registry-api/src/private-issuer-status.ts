import {
  assertValidApplicationEvidence,
  canonicalizeJson,
  type ApplicationEvidenceSignatureVerifier,
  type ApplicationEvidenceSubmission,
  type AuthorizedEvidenceVerifier,
  type IssuerStatusPolicyBinding,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  materialFromPrivateApplicationStatusWitness,
  refreshCapturedApplicationStatus,
} from "@midnight-ntwrk/trust-registry-integration";

import type { FileApplicationAdmissionStore } from "./file-application-admission.js";
import { assertProposalAdmissionRecords, type ProposalAdmissionPort } from "./proposal-admission.js";

type PrivateAdmission = NonNullable<Awaited<ReturnType<FileApplicationAdmissionStore["readCapturedPrivateAdmission"]>>>;
type PublicAdmission = Awaited<ReturnType<NonNullable<ProposalAdmissionPort["readCapturedAdmission"]>>>;

/** Read-only status check; the caller must authenticate the policy, resolver, time, and admission file. */
export async function verifyCapturedIssuerStatus(input: {
  captured: PrivateAdmission;
  expectedAdmission: PublicAdmission;
  submittedEvidence: ApplicationEvidenceSubmission;
  authorizationId: string;
  authorizedVerifiers: readonly AuthorizedEvidenceVerifier[];
  verifyEvidenceSignature: ApplicationEvidenceSignatureVerifier;
  statusPolicyBinding: IssuerStatusPolicyBinding;
  resolver: Parameters<typeof refreshCapturedApplicationStatus>[0]["resolver"];
  fetchFreshAttestation: Parameters<typeof refreshCapturedApplicationStatus>[0]["fetchFreshAttestation"];
  freshNonce: string;
  trustedTimeMs: number;
}): Promise<{ validUntilMs: number; statusDecisionCommitment: string }> {
  const { pending, accepted, privateStatusWitness } = input.captured;
  if (canonicalizeJson({ pending, accepted }) !== canonicalizeJson(input.expectedAdmission)) {
    throw new Error("Private issuer admission differs from the proposal's captured admission");
  }
  assertProposalAdmissionRecords(pending, accepted, "issuer", input.authorizationId, input.submittedEvidence);
  const binding = pending.binding;
  const evidence = accepted.evidence;
  assertValidApplicationEvidence(evidence, {
    registryId: binding.registryId,
    applicationId: binding.applicationId,
    subjectDid: binding.subjectDid,
    role: "issuer",
    policyId: binding.policyId,
    policyVersion: binding.policyVersion,
    scopeCommitment: binding.scopeCommitment,
    governedResource: binding.governedResource,
    challengeHash: evidence.envelope.challengeHash,
    evaluatedAt: new Date(input.trustedTimeMs).toISOString(),
  }, input.authorizedVerifiers, input.verifyEvidenceSignature);
  return refreshCapturedApplicationStatus({
    acceptedEnvelope: evidence.envelope,
    witness: {
      material: materialFromPrivateApplicationStatusWitness(privateStatusWitness),
      nonce: privateStatusWitness.nonce,
      signed: privateStatusWitness.signed,
    },
    binding: input.statusPolicyBinding,
    resolver: input.resolver,
    fetchFreshAttestation: input.fetchFreshAttestation,
    freshNonce: input.freshNonce,
    trustedTimeMs: input.trustedTimeMs,
  });
}
