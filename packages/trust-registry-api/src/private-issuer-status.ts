import {
  assertValidApplicationEvidence,
  canonicalizeJson,
  computeIssuerStatusPolicyBindingCommitment,
  type ApplicationEvidenceSignatureVerifier,
  type ApplicationEvidenceSubmission,
  type AuthorizedEvidenceVerifier,
  type IssuerStatusPolicyBinding,
} from "@midnightntwrk/trust-registry-domain";
import {
  materialFromPrivateApplicationStatusWitness,
  refreshCapturedApplicationStatus,
} from "@midnightntwrk/trust-registry-integration";

import type { FileApplicationAdmissionStore } from "./file-application-admission.js";
import { assertProposalAdmissionRecords, type ProposalAdmissionPort } from "./proposal-admission.js";
import type { FinalizedIssuerSnapshot, LocalIssuerProposalPortDependencies } from "./local-issuer-proposal-port.js";

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

/** Compose the protected intake witness and fresh status check for the opt-in issuer writer. */
export function createCapturedIssuerLiveEvidenceVerifier(input: {
  sourceRevision: string;
  readCapturedPrivateAdmission: FileApplicationAdmissionStore["readCapturedPrivateAdmission"];
  readAuthorizedVerifiers(snapshot: FinalizedIssuerSnapshot): Promise<readonly AuthorizedEvidenceVerifier[]>;
  verifyEvidenceSignature: ApplicationEvidenceSignatureVerifier;
  resolver: Parameters<typeof refreshCapturedApplicationStatus>[0]["resolver"];
  fetchFreshAttestation: Parameters<typeof refreshCapturedApplicationStatus>[0]["fetchFreshAttestation"];
  readFreshNonce(): Promise<string>;
}): LocalIssuerProposalPortDependencies["verifyLiveEvidence"] {
  return async ({ terms, pending, accepted, submittedEvidence, snapshot, trustedTimeMs }) => {
    const captured = await input.readCapturedPrivateAdmission(terms.applicationId, submittedEvidence.commitment);
    if (captured === null) throw new Error("Issuer private status witness is unavailable");
    const verified = await verifyCapturedIssuerStatus({
      captured,
      expectedAdmission: { pending, accepted },
      submittedEvidence,
      authorizationId: terms.authorizationId,
      authorizedVerifiers: await input.readAuthorizedVerifiers(snapshot),
      verifyEvidenceSignature: input.verifyEvidenceSignature,
      statusPolicyBinding: terms.statusPolicyBinding,
      resolver: input.resolver,
      fetchFreshAttestation: input.fetchFreshAttestation,
      freshNonce: await input.readFreshNonce(),
      trustedTimeMs,
    });
    if (verified.validUntilMs <= trustedTimeMs) {
      throw new Error("Refreshed issuer status is not current at trusted time");
    }
    return {
      format: "tr-live-issuer-evidence-verification-v1",
      sourceRevision: input.sourceRevision,
      networkId: terms.networkId,
      contractAddress: terms.contractAddress,
      finalizedBlockHash: snapshot.finalizedBlockHash,
      applicationId: terms.applicationId,
      evidenceCommitment: submittedEvidence.commitment,
      statusPolicyBindingCommitment: computeIssuerStatusPolicyBindingCommitment(terms.statusPolicyBinding),
      statusRegistryId: terms.statusPolicyBinding.statusRegistryId,
      statusAuthorityVerificationMethod: terms.statusPolicyBinding.statusAuthorityVerificationMethod,
      trustedTimeMs,
    };
  };
}
