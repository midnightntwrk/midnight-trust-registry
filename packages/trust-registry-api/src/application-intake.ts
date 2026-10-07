import {
  ApplicationChallengeBindingSchema,
  ApplicationEvidenceEnvelopeSchema,
  assertValidApplicationEvidence,
  computeApplicationChallengeBindingHash,
  computeApplicationEvidenceCommitment,
  type ApplicationChallengeBinding,
  type ApplicationEvidenceSignature,
  type ApplicationEvidenceSignatureVerifier,
  type ApplicationEvidenceSubmission,
  type AuthorizedEvidenceVerifier,
} from "@midnight-ntwrk/trust-registry-domain";

import { ApplicationChallengeService } from "./application-challenges.js";

export type VerifiedApplicationPresentation = {
  subjectDid: string;
  nonce: string;
  presentationHash: string;
  claimsCommitment: string;
  verifiedAt: string;
  expiresAt: string;
};

export type ApplicationProposalInput = {
  binding: ApplicationChallengeBinding;
  evidence: ApplicationEvidenceSubmission;
};

/** The caller supplies a policy-authorized VP verifier and evidence signer. */
export async function consumeChallengeAndSubmitApplication<Result>(input: {
  challengeService: ApplicationChallengeService;
  binding: ApplicationChallengeBinding;
  expectedBinding: ApplicationChallengeBinding;
  nonce: string;
  challengeHash: string;
  presentation: unknown;
  verifyPresentation: (presentation: unknown, nonce: string, subjectDid: string) => Promise<VerifiedApplicationPresentation>;
  signEvidence: (commitment: string) => Promise<ApplicationEvidenceSignature>;
  authorizedVerifiers: readonly AuthorizedEvidenceVerifier[];
  verifyEvidenceSignature: ApplicationEvidenceSignatureVerifier;
  evaluatedAt: string;
  propose: (proposal: ApplicationProposalInput) => Promise<Result>;
}): Promise<Result> {
  const binding = ApplicationChallengeBindingSchema.parse(input.binding);
  const expectedBinding = ApplicationChallengeBindingSchema.parse(input.expectedBinding);
  if (computeApplicationChallengeBindingHash(binding) !== computeApplicationChallengeBindingHash(expectedBinding)) {
    throw new Error("Application challenge binding does not match the governed proposal");
  }
  const verified = await input.verifyPresentation(input.presentation, input.nonce, binding.subjectDid);
  if (verified.nonce !== input.nonce || verified.subjectDid !== binding.subjectDid) {
    throw new Error("Presentation does not match the application challenge or subject DID");
  }

  const consumedHash = await input.challengeService.consume({
    binding,
    nonce: input.nonce,
    challengeHash: input.challengeHash,
  });
  if (consumedHash === null) throw new Error("Application challenge is invalid or already consumed");

  const envelope = ApplicationEvidenceEnvelopeSchema.parse({
    version: "tr-application-evidence-v1",
    registryId: binding.registryId,
    applicationId: binding.applicationId,
    subjectDid: binding.subjectDid,
    role: binding.role,
    policyId: binding.policyId,
    policyVersion: binding.policyVersion,
    scopeCommitment: binding.scopeCommitment.toLowerCase(),
    evidenceVerifierDid: binding.evidenceVerifierDid,
    verifiedAt: verified.verifiedAt,
    expiresAt: verified.expiresAt,
    challengeHash: consumedHash,
    presentationHash: verified.presentationHash,
    claimsCommitment: verified.claimsCommitment,
  });
  const commitment = computeApplicationEvidenceCommitment(envelope);
  const signature = await input.signEvidence(commitment);
  const evidence = assertValidApplicationEvidence(
    { envelope, commitment, signature },
    {
      registryId: binding.registryId,
      applicationId: binding.applicationId,
      subjectDid: binding.subjectDid,
      role: binding.role,
      policyId: binding.policyId,
      policyVersion: binding.policyVersion,
      scopeCommitment: binding.scopeCommitment,
      challengeHash: consumedHash,
      evaluatedAt: input.evaluatedAt,
    },
    input.authorizedVerifiers,
    input.verifyEvidenceSignature,
  );
  return input.propose({ binding: expectedBinding, evidence });
}
