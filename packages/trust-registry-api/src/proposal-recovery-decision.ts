import { createHash } from "node:crypto";

import { canonicalizeJson } from "@midnight-ntwrk/trust-registry-domain";
import { z } from "zod";

import { readBoundedLocalApprovalFile, verifyDetachedLocalReviewerSignature } from "./local-reviewer-signature.js";
import type { assessProposalRecoveryCandidate } from "./proposal-recovery-candidate.js";

type RecoveryCandidate = Awaited<ReturnType<typeof assessProposalRecoveryCandidate>>;
const SHA256 = /^[0-9a-f]{64}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]{0,19})$/u;
const DecisionSchema = z.strictObject({
  format: z.literal("tr-local-proposal-recovery-decision-v1"),
  decision: z.literal("abandon-invalidated-action"),
  candidateSha256: z.string().regex(SHA256),
  finalityEvidenceSha256: z.string().regex(SHA256),
  evidenceReference: z.string().min(1).max(512).regex(/^[A-Za-z0-9][A-Za-z0-9._:/#-]*$/u),
  decidedAt: z.string(),
  reviewerFingerprint: z.string().regex(/^[0-9A-F]{40}$/u),
  registryId: z.string().min(1).max(256),
  contractAddress: z.string().regex(HASH),
  role: z.enum(["issuer", "verifier", "auditor", "maintainer", "recognition"]),
  authorizationId: z.string().min(1).max(256),
  evidenceCommitment: z.string().regex(HASH),
  attemptDigest: z.string().regex(HASH),
  journalBindingDigest: z.string().regex(HASH),
  reservationActionSequence: z.string().regex(DECIMAL),
  finalizedGovernanceActionCount: z.string().regex(DECIMAL),
  finalizedBlockHash: z.string().regex(HASH),
  approvedPlanSha256: z.string().regex(SHA256),
});

export type ProposalRecoveryDecision = z.infer<typeof DecisionSchema>;

export function proposalRecoveryCandidateDigest(candidate: RecoveryCandidate): string {
  return createHash("sha256").update(canonicalizeJson(candidate)).digest("hex");
}

function parseCanonicalDecision(bytes: Buffer): ProposalRecoveryDecision {
  const raw = bytes.toString("utf8");
  const value: unknown = JSON.parse(raw);
  if (!Buffer.from(raw, "utf8").equals(bytes)
    || raw !== `${canonicalizeJson(value)}\n`) {
    throw new Error("Recovery decision must use canonical signed JSON without duplicate keys");
  }
  return DecisionSchema.parse(value);
}

/** Signature and exact-byte validation only; finality and journal release remain unverified. */
export async function loadApprovedProposalRecoveryDecision(input: {
  decisionPath: string;
  signaturePath: string;
  finalityEvidencePath: string;
  keyringDirectory: string;
  reviewerFingerprint: string;
  candidate: RecoveryCandidate;
  now?: number;
}): Promise<{ decision: ProposalRecoveryDecision; decisionSha256: string;
  finalityAuthenticated: false; releaseQualified: false; retryPermitted: false }> {
  const candidate = input.candidate;
  if (candidate.format !== "tr-local-proposal-recovery-candidate-v2"
    || candidate.networkId !== "undeployed"
    || candidate.reason !== "sequence-invalidated-record-absent"
    || candidate.reservationState !== "reserved"
    || candidate.reviewCandidate !== true || candidate.retryPermitted !== false
    || candidate.releaseQualified !== false
    || candidate.reservationActionSequence === null
    || candidate.observedEventHash !== null
    || !DECIMAL.test(candidate.reservationActionSequence)
    || !DECIMAL.test(candidate.finalizedGovernanceActionCount)
    || BigInt(candidate.finalizedGovernanceActionCount) <= BigInt(candidate.reservationActionSequence)) {
    throw new Error("Recovery decision requires an invalidated, unobserved reserved action candidate");
  }
  const bytes = await readBoundedLocalApprovalFile(input.decisionPath, 32 * 1024);
  await verifyDetachedLocalReviewerSignature({
    documentBytes: bytes,
    signaturePath: input.signaturePath,
    keyringDirectory: input.keyringDirectory,
    reviewerFingerprint: input.reviewerFingerprint,
    description: "Local proposal recovery decision",
  });
  const decision = parseCanonicalDecision(bytes);
  const now = input.now ?? Date.now();
  const decidedAt = Date.parse(decision.decidedAt);
  if (!Number.isFinite(decidedAt) || new Date(decidedAt).toISOString() !== decision.decidedAt
    || decidedAt < now - 24 * 60 * 60 * 1000
    || decidedAt > now + 300_000
    || decision.reviewerFingerprint !== input.reviewerFingerprint
    || decision.candidateSha256 !== proposalRecoveryCandidateDigest(candidate)
    || decision.registryId !== candidate.registryId
    || decision.contractAddress !== candidate.contractAddress
    || decision.role !== candidate.role
    || decision.authorizationId !== candidate.authorizationId
    || decision.evidenceCommitment !== candidate.evidenceCommitment
    || decision.attemptDigest !== candidate.attemptDigest
    || decision.journalBindingDigest !== candidate.journalBindingDigest
    || decision.reservationActionSequence !== candidate.reservationActionSequence
    || decision.finalizedGovernanceActionCount !== candidate.finalizedGovernanceActionCount
    || decision.finalizedBlockHash !== candidate.finalizedBlockHash
    || decision.approvedPlanSha256 !== candidate.approvedPlanSha256) {
    throw new Error("Signed recovery decision does not match the exact candidate and reviewer");
  }
  const evidence = await readBoundedLocalApprovalFile(input.finalityEvidencePath, 1024 * 1024);
  const digest = (buffer: Buffer): string => createHash("sha256").update(buffer).digest("hex");
  if (digest(evidence) !== decision.finalityEvidenceSha256) {
    throw new Error("Finality evidence bytes differ from the reviewer-hashed bytes");
  }
  return { decision, decisionSha256: digest(bytes),
    finalityAuthenticated: false, releaseQualified: false, retryPermitted: false };
}
