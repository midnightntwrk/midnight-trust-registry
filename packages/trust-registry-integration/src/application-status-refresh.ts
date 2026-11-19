import type { MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";
import {
  ApplicationEvidenceEvaluationTimeSchema,
  HashHexSchema,
  compareRfc3339Instants,
  type ApplicationEvidenceSubmission,
  type IssuerStatusPolicyBinding,
} from "@midnightntwrk/trust-registry-domain";

import {
  createAttestedApplicationStatusSource,
  verifyApplicationStatusDecisionWitness,
  type ApplicationStatusWitnessMaterial,
} from "./application-status-attestation.js";

const noncePattern = /^0x[0-9a-f]{64}$/u;

export type CapturedApplicationStatusWitness = {
  material: ApplicationStatusWitnessMaterial;
  nonce: string;
  signed: unknown;
};

/**
 * Rechecks a private intake witness before asking the status authority for a fresh decision.
 * The caller must independently authenticate the accepted evidence, governed binding,
 * resolver, trusted time, and private witness provenance, and generate the fresh nonce.
 */
export async function refreshCapturedApplicationStatus(input: {
  acceptedEnvelope: Pick<ApplicationEvidenceSubmission["envelope"],
    "challengeHash" | "statusDecisionCommitment" | "verifiedAt" | "expiresAt">;
  witness: CapturedApplicationStatusWitness;
  binding: IssuerStatusPolicyBinding;
  resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  fetchFreshAttestation: Parameters<typeof createAttestedApplicationStatusSource>[0]["fetchAttestation"];
  freshNonce: string;
  trustedTimeMs: number;
}): Promise<{ validUntilMs: number; statusDecisionCommitment: string }> {
  const { acceptedEnvelope, witness } = input;
  const challengeHash = HashHexSchema.parse(acceptedEnvelope.challengeHash);
  const statusDecisionCommitment = HashHexSchema.parse(acceptedEnvelope.statusDecisionCommitment);
  const verifiedAt = ApplicationEvidenceEvaluationTimeSchema.parse(acceptedEnvelope.verifiedAt);
  const expiresAt = ApplicationEvidenceEvaluationTimeSchema.parse(acceptedEnvelope.expiresAt);
  if (!noncePattern.test(witness.nonce) || !noncePattern.test(input.freshNonce)
    || witness.nonce === input.freshNonce
    || !Number.isSafeInteger(input.trustedTimeMs)
    || !Number.isFinite(new Date(input.trustedTimeMs).getTime())) {
    throw new Error("Application status refresh context is invalid");
  }
  const trustedTime = new Date(input.trustedTimeMs).toISOString();
  if (compareRfc3339Instants(trustedTime, verifiedAt) < 0
    || compareRfc3339Instants(trustedTime, expiresAt) >= 0) {
    throw new Error("Accepted application evidence is not current at trusted time");
  }
  await verifyApplicationStatusDecisionWitness({
    signed: witness.signed,
    expectedCommitment: statusDecisionCommitment,
    expectedChallengeHash: challengeHash,
    material: witness.material,
    binding: input.binding,
    nonce: witness.nonce,
    evaluatedAtMs: Date.parse(verifiedAt),
    resolver: input.resolver,
  });
  const current = await createAttestedApplicationStatusSource({
    resolver: input.resolver,
    fetchAttestation: input.fetchFreshAttestation,
  })({
    material: witness.material,
    binding: input.binding,
    nonce: input.freshNonce,
    evaluatedAtMs: input.trustedTimeMs,
  });
  return {
    validUntilMs: Math.min(current.validUntilMs, Date.parse(expiresAt)),
    statusDecisionCommitment: current.statusDecisionCommitment,
  };
}
