import {
  ApplicationChallengeBindingSchema,
  ApplicationEvidenceEvaluationTimeSchema,
  ApplicationEvidenceEnvelopeSchema,
  AuthorizedEvidenceVerifierSchema,
  HashHexSchema,
  MAX_APPLICATION_EVIDENCE_LIFETIME_MS,
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
  const evaluatedAtMs = Date.parse(ApplicationEvidenceEvaluationTimeSchema.parse(input.evaluatedAt));
  const authorizedVerifiers = input.authorizedVerifiers.map((verifier) => AuthorizedEvidenceVerifierSchema.parse(verifier));
  if (!authorizedVerifiers.some((verifier) => verifier.did === binding.evidenceVerifierDid)) {
    throw new Error("Application evidence verifier is not authorized by policy");
  }
  if (!hasMatchingApplicationChallengeHash(input.nonce, input.challengeHash)) {
    throw new Error("Application challenge nonce or hash is invalid");
  }
  const challengeHash = input.challengeHash.toLowerCase();
  const challengeInput = { binding, nonce: input.nonce, challengeHash };
  const challengeWindow = await input.challengeService.liveWindow(challengeInput);
  if (challengeWindow === null) {
    throw new Error("Application challenge is invalid or already consumed");
  }
  if (evaluatedAtMs < challengeWindow.issuedAtMs || evaluatedAtMs >= challengeWindow.expiresAtMs) {
    throw new Error("Application evaluation time is outside the live challenge window");
  }
  const verified = await input.verifyPresentation(input.presentation, {
    nonce: input.nonce,
    binding,
    evaluatedAt: input.evaluatedAt,
  });
  const verifiedScopeCommitment = HashHexSchema.safeParse(verified.scopeCommitment);
  if (
    verified.nonce !== input.nonce ||
    verified.subjectDid !== binding.subjectDid ||
    !verifiedScopeCommitment.success ||
    verifiedScopeCommitment.data.toLowerCase() !== binding.scopeCommitment.toLowerCase()
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
    challengeHash,
    presentationHash: verified.presentationHash,
    claimsCommitment: verified.claimsCommitment,
  });
  const verifiedAtMs = Date.parse(envelope.verifiedAt);
  const expiresAtMs = Date.parse(envelope.expiresAt);
  if (
    verifiedAtMs < challengeWindow.issuedAtMs
    || verifiedAtMs >= challengeWindow.expiresAtMs
  ) {
    throw new Error("Presentation verification time is outside the challenge window");
  }
  if (verifiedAtMs > evaluatedAtMs) {
    throw new Error("Presentation verification time is not yet valid at the governed transition");
  }
  if (expiresAtMs - verifiedAtMs > MAX_APPLICATION_EVIDENCE_LIFETIME_MS) {
    throw new Error("Application evidence exceeds the maximum 24-hour lifetime");
  }
  if (expiresAtMs <= evaluatedAtMs) {
    throw new Error("Application evidence is expired at intake");
  }
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
