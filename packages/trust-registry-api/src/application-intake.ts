import {
  ApplicationChallengeBindingSchema,
  ApplicationEvidenceEvaluationTimeSchema,
  ApplicationEvidenceEnvelopeSchema,
  AuthorizedEvidenceVerifierSchema,
  HashHexSchema,
  assertValidApplicationEvidence,
  computeApplicationChallengeBindingHash,
  computeApplicationEvidenceCommitment,
  type ApplicationChallengeBinding,
  type ApplicationEvidenceSignature,
  type ApplicationEvidenceSignatureVerifier,
  type ApplicationEvidenceSubmission,
  type AuthorizedEvidenceVerifier,
} from "@midnight-ntwrk/trust-registry-domain";

import { ApplicationChallengeService, hasMatchingApplicationChallengeHash } from "./application-challenges.js";

export type VerifiedApplicationPresentation = {
  subjectDid: string;
  nonce: string;
  scopeCommitment: string;
  presentationHash: string;
  claimsCommitment: string;
  verifiedAt: string;
  expiresAt: string;
};

export type ApplicationProposalInput = {
  binding: ApplicationChallengeBinding;
  evidence: ApplicationEvidenceSubmission;
};

export type ApplicationPresentationContext = {
  nonce: string;
  binding: ApplicationChallengeBinding;
  evaluatedAt: string;
};

/** The caller supplies a policy-authorized VP verifier that derives bindings from the verified proof, not expected inputs. */
export async function consumeChallengeAndSubmitApplication<Result>(input: {
  challengeService: ApplicationChallengeService;
  binding: ApplicationChallengeBinding;
  expectedBinding: ApplicationChallengeBinding;
  nonce: string;
  challengeHash: string;
  presentation: unknown;
  verifyPresentation: (presentation: unknown, context: ApplicationPresentationContext) => Promise<VerifiedApplicationPresentation>;
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
  ApplicationEvidenceEvaluationTimeSchema.parse(input.evaluatedAt);
  const authorizedVerifiers = input.authorizedVerifiers.map((verifier) => AuthorizedEvidenceVerifierSchema.parse(verifier));
  if (!authorizedVerifiers.some((verifier) => verifier.did === binding.evidenceVerifierDid)) {
    throw new Error("Application evidence verifier is not authorized by policy");
  }
  if (!hasMatchingApplicationChallengeHash(input.nonce, input.challengeHash)) {
    throw new Error("Application challenge nonce or hash is invalid");
  }
  const challengeInput = { binding, nonce: input.nonce, challengeHash: input.challengeHash };
  if (!(await input.challengeService.isLive(challengeInput))) {
    throw new Error("Application challenge is invalid or already consumed");
  }
  const verified = await input.verifyPresentation(input.presentation, {
    nonce: input.nonce,
    binding,
    evaluatedAt: input.evaluatedAt,
  });
  if (
    verified.nonce !== input.nonce ||
    verified.subjectDid !== binding.subjectDid ||
    HashHexSchema.parse(verified.scopeCommitment).toLowerCase() !== binding.scopeCommitment.toLowerCase()
  ) {
    throw new Error("Presentation does not match the application challenge, subject DID, or scope");
  }

  const envelope = ApplicationEvidenceEnvelopeSchema.parse({
    version: "tr-application-evidence-v1",
    registryId: binding.registryId,
    applicationId: binding.applicationId,
    subjectDid: binding.subjectDid,
    role: binding.role,
    policyId: binding.policyId,
    policyVersion: binding.policyVersion,
    scopeCommitment: binding.scopeCommitment.toLowerCase(),
    governedResource: binding.governedResource,
    evidenceVerifierDid: binding.evidenceVerifierDid,
    verifiedAt: verified.verifiedAt,
    expiresAt: verified.expiresAt,
    challengeHash: input.challengeHash,
    presentationHash: verified.presentationHash,
    claimsCommitment: verified.claimsCommitment,
  });
  const consumedHash = await input.challengeService.consume(challengeInput);
  if (consumedHash === null || consumedHash !== envelope.challengeHash) {
    throw new Error("Application challenge is invalid or already consumed");
  }
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
      governedResource: binding.governedResource,
      challengeHash: consumedHash,
      evaluatedAt: input.evaluatedAt,
    },
    authorizedVerifiers,
    input.verifyEvidenceSignature,
  );
  return input.propose({ binding: expectedBinding, evidence });
}
