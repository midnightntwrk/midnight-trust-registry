import { createHash } from "node:crypto";

import { canonicalizeJson } from "@midnight-ntwrk/trust-registry-domain";
import { getLocalNetworkProfile } from "@midnight-ntwrk/trust-registry-integration";
import { z } from "zod";

import { readBoundedLocalApprovalFile, verifyDetachedLocalReviewerSignature } from "./local-reviewer-signature.js";
import type { assessProposalRecoveryCandidate } from "./proposal-recovery-candidate.js";

type RecoveryCandidate = Awaited<ReturnType<typeof assessProposalRecoveryCandidate>>;
const SHA256 = /^[0-9a-f]{64}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]{0,19})$/u;
const DecisionSchema = z.strictObject({
  format: z.literal("tr-local-proposal-recovery-decision-v3"),
  decision: z.literal("abandon-invalidated-action"),
  candidateSha256: z.string().regex(SHA256),
  finalityEvidenceSha256: z.string().regex(SHA256),
  evidenceReference: z.string().min(1).max(512).regex(/^[A-Za-z0-9][A-Za-z0-9._:/#-]*$/u)
    .refine((value) => !value.toLowerCase().startsWith("demo:")),
  draftedAt: z.string(),
  reviewerFingerprint: z.string().regex(/^[0-9A-F]{40}$/u),
  registryId: z.string().min(1).max(256),
  contractAddress: z.string().regex(HASH),
  role: z.enum(["issuer", "verifier", "auditor", "maintainer", "recognition"]),
  authorizationId: z.string().min(1).max(256),
  evidenceCommitment: z.string().regex(HASH),
  attemptDigest: z.string().regex(HASH),
  journalBindingDigest: z.string().regex(HASH),
  reservationActionSequence: z.string().regex(DECIMAL),
  reservationActionKind: z.string().regex(HASH),
  reservationActionPayloadHash: z.string().regex(HASH),
  finalizedGovernanceActionCount: z.string().regex(DECIMAL),
  finalizedLastActionKind: z.string().regex(HASH),
  finalizedLastActionPayloadHash: z.string().regex(HASH),
  finalizedBlockHash: z.string().regex(HASH),
  approvedPlanSha256: z.string().regex(SHA256),
});

export type ProposalRecoveryDecision = z.infer<typeof DecisionSchema>;

export function proposalRecoveryCandidateDigest(candidate: RecoveryCandidate): string {
  return createHash("sha256").update(canonicalizeJson(candidate)).digest("hex");
}

function assertReviewCandidate(candidate: RecoveryCandidate): void {
  if (candidate.format !== "tr-local-proposal-recovery-candidate-v3"
    || candidate.networkId !== getLocalNetworkProfile().networkId
    || candidate.reason !== "sequence-invalidated-record-absent"
    || candidate.reservationState !== "reserved"
    || candidate.reviewCandidate !== true || candidate.retryPermitted !== false
    || candidate.releaseQualified !== false
    || candidate.reservationActionSequence === null
    || candidate.reservationActionKind === null
    || candidate.reservationActionPayloadHash === null
    || candidate.observedEventHash !== null
    || !DECIMAL.test(candidate.reservationActionSequence)
    || !HASH.test(candidate.reservationActionKind)
    || !HASH.test(candidate.reservationActionPayloadHash)
    || !DECIMAL.test(candidate.finalizedGovernanceActionCount)
    || BigInt(candidate.finalizedGovernanceActionCount) !== BigInt(candidate.reservationActionSequence) + 1n
    || !HASH.test(candidate.finalizedLastActionKind ?? "")
    || !HASH.test(candidate.finalizedLastActionPayloadHash ?? "")
    || (candidate.finalizedLastActionKind === candidate.reservationActionKind
      && candidate.finalizedLastActionPayloadHash === candidate.reservationActionPayloadHash)) {
    throw new Error("Recovery decision requires an invalidated, unobserved reserved action candidate");
  }
}

function assertDistinctRecoveryReviewer(reviewerFingerprint: string, planReviewerFingerprint: string): void {
  if (!/^[0-9A-F]{40}$/u.test(planReviewerFingerprint)
    || !/^[0-9A-F]{40}$/u.test(reviewerFingerprint)
    || reviewerFingerprint === planReviewerFingerprint) {
    throw new Error("Recovery decision requires a reviewer distinct from the API-plan reviewer");
  }
}

/** Draft only. The operator must independently review evidence and sign these exact bytes. */
export async function draftProposalRecoveryDecision(input: {
  candidate: RecoveryCandidate;
  finalityEvidencePath: string;
  evidenceReference: string;
  reviewerFingerprint: string;
  planReviewerFingerprint: string;
  now?: number;
}): Promise<string> {
  assertReviewCandidate(input.candidate);
  assertDistinctRecoveryReviewer(input.reviewerFingerprint, input.planReviewerFingerprint);
  const evidence = await readBoundedLocalApprovalFile(input.finalityEvidencePath, 1024 * 1024);
  const decision = DecisionSchema.parse({
    format: "tr-local-proposal-recovery-decision-v3",
    decision: "abandon-invalidated-action",
    candidateSha256: proposalRecoveryCandidateDigest(input.candidate),
    finalityEvidenceSha256: createHash("sha256").update(evidence).digest("hex"),
    evidenceReference: input.evidenceReference,
    draftedAt: new Date(input.now ?? Date.now()).toISOString(),
    reviewerFingerprint: input.reviewerFingerprint,
    registryId: input.candidate.registryId,
    contractAddress: input.candidate.contractAddress,
    role: input.candidate.role,
    authorizationId: input.candidate.authorizationId,
    evidenceCommitment: input.candidate.evidenceCommitment,
    attemptDigest: input.candidate.attemptDigest,
    journalBindingDigest: input.candidate.journalBindingDigest,
    reservationActionSequence: input.candidate.reservationActionSequence,
    reservationActionKind: input.candidate.reservationActionKind,
    reservationActionPayloadHash: input.candidate.reservationActionPayloadHash,
    finalizedGovernanceActionCount: input.candidate.finalizedGovernanceActionCount,
    finalizedLastActionKind: input.candidate.finalizedLastActionKind,
    finalizedLastActionPayloadHash: input.candidate.finalizedLastActionPayloadHash,
    finalizedBlockHash: input.candidate.finalizedBlockHash,
    approvedPlanSha256: input.candidate.approvedPlanSha256,
  });
  return `${canonicalizeJson(decision)}\n`;
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
  planReviewerFingerprint: string;
  candidate: RecoveryCandidate;
  now?: number;
}): Promise<{ decision: ProposalRecoveryDecision; decisionSha256: string;
  finalityAuthenticated: false; releaseQualified: false; retryPermitted: false }> {
  assertDistinctRecoveryReviewer(input.reviewerFingerprint, input.planReviewerFingerprint);
  const candidate = input.candidate;
  assertReviewCandidate(candidate);
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
  const draftedAt = Date.parse(decision.draftedAt);
  if (!Number.isFinite(draftedAt) || new Date(draftedAt).toISOString() !== decision.draftedAt
    || draftedAt < now - 24 * 60 * 60 * 1000
    || draftedAt > now + 300_000
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
    || decision.reservationActionKind !== candidate.reservationActionKind
    || decision.reservationActionPayloadHash !== candidate.reservationActionPayloadHash
    || decision.finalizedGovernanceActionCount !== candidate.finalizedGovernanceActionCount
    || decision.finalizedLastActionKind !== candidate.finalizedLastActionKind
    || decision.finalizedLastActionPayloadHash !== candidate.finalizedLastActionPayloadHash
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
