import { randomBytes } from "node:crypto";

import type { MidnightDIDResolverInterface } from "@midnight-ntwrk/midnight-did";
import {
  DidSchema,
  HashHexSchema,
  recognitionAccreditorAnchorCommitment,
  resolveGovernedRecognitionAccreditorAnchor,
  ScopedIdentifierSchema,
  sha256Hex,
  type GovernancePolicyRecord,
  type SignedRecognitionAuthorityAssertion,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  verifyRecognitionAuthorityAssertion,
  verifyRecognitionAccreditationVp,
  recognitionAccreditationSubmissionCommitment,
  type RecognitionAccreditationStatusSource,
  type RecognitionAccreditationSubmission,
  type VerifiedRecognitionAccreditation,
  type VerifiedRecognitionAuthorityAssertion,
} from "@midnight-ntwrk/trust-registry-integration";
import { z } from "zod";

import {
  hasMatchingApplicationChallengeHash,
  type ApplicationChallengeStore,
} from "./application-challenges.js";
import type { RecognitionAdmissionReceipt, RecognitionAdmissionStore } from "./file-recognition-admission.js";

const CHALLENGE_TTL_MS = 5 * 60_000;
const MAX_COLLISION_ATTEMPTS = 3;

export const RecognitionAuthorityChallengeBindingSchema = z.strictObject({
  targetRegistryId: ScopedIdentifierSchema,
  recognitionId: ScopedIdentifierSchema,
  authorityDid: DidSchema.startsWith("did:midnight:"),
  recognizedRegistryId: ScopedIdentifierSchema,
  scopeResourceType: ScopedIdentifierSchema,
  scopeResourceId: ScopedIdentifierSchema,
});

export type RecognitionAuthorityChallengeBinding = z.infer<typeof RecognitionAuthorityChallengeBindingSchema>;

const bindingHash = (binding: RecognitionAuthorityChallengeBinding): string => {
  const value = RecognitionAuthorityChallengeBindingSchema.parse(binding);
  return sha256Hex(JSON.stringify([
    "tr:recognition:authority-challenge-binding:v1",
    value.targetRegistryId,
    value.recognitionId,
    value.authorityDid,
    value.recognizedRegistryId,
    value.scopeResourceType,
    value.scopeResourceId,
  ]));
};

const identityHash = (binding: RecognitionAuthorityChallengeBinding): string =>
  sha256Hex(JSON.stringify([
    "tr:recognition:authority-challenge-identity:v1",
    binding.targetRegistryId,
    binding.recognitionId,
  ]));

/** DID-control challenge only. This does not validate external accreditation. */
export class RecognitionAuthorityChallengeService {
  constructor(
    private readonly store: ApplicationChallengeStore,
    private readonly clock: () => number = Date.now,
  ) {}

  async issue(input: RecognitionAuthorityChallengeBinding): Promise<{
    nonce: string;
    challengeHash: string;
    issuedAt: string;
    expiresAt: string;
  }> {
    const binding = RecognitionAuthorityChallengeBindingSchema.parse(input);
    const nowMs = this.now();
    const expiresAtMs = nowMs + CHALLENGE_TTL_MS;
    for (let attempt = 0; attempt < MAX_COLLISION_ATTEMPTS; attempt += 1) {
      const nonce = randomBytes(32);
      const challengeHash = sha256Hex(nonce);
      const result = await this.store.insert({
        challengeHash,
        bindingHash: bindingHash(binding),
        applicationHash: identityHash(binding),
        issuedAtMs: nowMs,
        expiresAtMs,
      }, nowMs, () => this.now());
      if (result.inserted) {
        return {
          nonce: `0x${nonce.toString("hex")}`,
          challengeHash,
          issuedAt: new Date(nowMs).toISOString(),
          expiresAt: new Date(expiresAtMs).toISOString(),
        };
      }
    }
    throw new Error("Could not issue a recognition authority challenge");
  }

  /** Verify the DID assertion before atomically spending its exact-tuple challenge. */
  async verifyAndConsumeDidAssertion(input: {
    binding: RecognitionAuthorityChallengeBinding;
    nonce: string;
    signed: SignedRecognitionAuthorityAssertion;
    resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  }): Promise<VerifiedRecognitionAuthorityAssertion> {
    const result = await this.verifyThenConsume(input, async () => null);
    return result.authority;
  }

  /** Private composed path; current governance must be read from trusted state, including immediately before consumption. */
  async verifyAndConsumeAccreditedAssertion(input: {
    binding: RecognitionAuthorityChallengeBinding;
    nonce: string;
    signed: SignedRecognitionAuthorityAssertion;
    accreditation: RecognitionAccreditationSubmission;
    readCurrentGovernance: () => Promise<{
      governancePolicy: GovernancePolicyRecord;
      activePolicyCommitment: string;
    }>;
    admissionStore?: RecognitionAdmissionStore;
    resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
    statusSource: RecognitionAccreditationStatusSource;
  }): Promise<{
    authority: VerifiedRecognitionAuthorityAssertion;
    accreditation: VerifiedRecognitionAccreditation;
    evidenceCommitment: string;
    receipt?: RecognitionAdmissionReceipt;
  }> {
    if (input.admissionStore !== undefined && input.admissionStore !== this.store) {
      throw new Error("Recognition admission and challenge stores must be the same transaction store");
    }
    const admissionStore = input.admissionStore;
    const binding = RecognitionAuthorityChallengeBindingSchema.parse(input.binding);
    let verifiedPolicyCommitment: string | undefined;
    let verifiedAnchorCommitment: string | undefined;
    const scope = {
      registryId: binding.targetRegistryId,
      recognizedRegistryId: binding.recognizedRegistryId,
      scopeResourceType: binding.scopeResourceType,
      scopeResourceId: binding.scopeResourceId,
    };
    const assertCurrentGovernance = async (atMs: number): Promise<void> => {
      const governance = await input.readCurrentGovernance();
      const { anchor } = resolveGovernedRecognitionAccreditorAnchor({
        policy: governance.governancePolicy,
        activePolicyCommitment: governance.activePolicyCommitment,
        scope,
        evaluatedAtMs: atMs,
      });
      if (HashHexSchema.parse(governance.activePolicyCommitment).toLowerCase() !== verifiedPolicyCommitment
        || recognitionAccreditorAnchorCommitment(anchor) !== verifiedAnchorCommitment) {
        throw new Error("Recognition governance changed during accreditation verification");
      }
    };
    let receipt: RecognitionAdmissionReceipt | undefined;
    const combinedEvidenceCommitment = (
      authority: VerifiedRecognitionAuthorityAssertion,
      accreditation: VerifiedRecognitionAccreditation,
    ) => sha256Hex(JSON.stringify([
      "tr:recognition:combined-verified-evidence:v1",
      authority.evidenceCommitment,
      accreditation.evidenceCommitment,
    ]));
    const result = await this.verifyThenConsume(input, async (authority, evaluatedAtMs) => {
      const governance = await input.readCurrentGovernance();
      const { anchor } = resolveGovernedRecognitionAccreditorAnchor({
        policy: governance.governancePolicy,
        activePolicyCommitment: governance.activePolicyCommitment,
        scope,
        evaluatedAtMs,
      });
      verifiedPolicyCommitment = HashHexSchema.parse(governance.activePolicyCommitment).toLowerCase();
      verifiedAnchorCommitment = recognitionAccreditorAnchorCommitment(anchor);
      if (authority.statement.accreditationSubmissionCommitment
        !== recognitionAccreditationSubmissionCommitment(input.accreditation)) {
        throw new Error("Recognition assertion does not commit to the submitted accreditation VP");
      }
      const accreditation = await verifyRecognitionAccreditationVp({
        submission: input.accreditation,
        anchor,
        activePolicyCommitment: verifiedPolicyCommitment,
        targetRegistryId: binding.targetRegistryId,
        authorityDid: binding.authorityDid,
        nonce: input.nonce,
        evaluatedAtMs,
        resolver: input.resolver,
        statusSource: input.statusSource,
      });
      return accreditation;
    }, (accreditation) => accreditation.expiresAtMs, assertCurrentGovernance,
    admissionStore === undefined ? undefined : async ({ challengeHash, bindingHash, consumeAtMs, authority, evidence }) => {
      if (evidence.governedPolicyCommitment !== verifiedPolicyCommitment
        || evidence.anchorCommitment !== verifiedAnchorCommitment) {
        throw new Error("Recognition accreditation evidence does not match governed policy");
      }
      const committed = await admissionStore.accept({
        targetRegistryId: binding.targetRegistryId,
        recognitionId: binding.recognitionId,
        challengeHash,
        bindingHash,
        policyCommitment: evidence.governedPolicyCommitment,
        anchorCommitment: evidence.anchorCommitment,
        evidenceCommitment: combinedEvidenceCommitment(authority, evidence),
        expiresAtMs: Math.min(evidence.expiresAtMs, Date.parse(authority.statement.expiresAt)),
        nowMs: consumeAtMs,
        assertCurrentGovernance: () => assertCurrentGovernance(this.now()),
      });
      receipt = committed ?? undefined;
      return committed !== null;
    });
    return {
      authority: result.authority,
      accreditation: result.evidence,
      evidenceCommitment: combinedEvidenceCommitment(result.authority, result.evidence),
      ...(receipt === undefined ? {} : { receipt }),
    };
  }

  private async verifyThenConsume<Evidence>(input: {
    binding: RecognitionAuthorityChallengeBinding;
    nonce: string;
    signed: SignedRecognitionAuthorityAssertion;
    resolver: Pick<MidnightDIDResolverInterface, "resolveResult">;
  }, verifyEvidence: (
    authority: VerifiedRecognitionAuthorityAssertion,
    evaluatedAtMs: number,
  ) => Promise<Evidence>, evidenceExpiresAtMs?: (evidence: Evidence) => number,
  beforeConsume?: (consumeAtMs: number) => Promise<void>,
  commit?: (input: {
    challengeHash: string;
    bindingHash: string;
    consumeAtMs: number;
    authority: VerifiedRecognitionAuthorityAssertion;
    evidence: Evidence;
  }) => Promise<boolean>): Promise<{
    authority: VerifiedRecognitionAuthorityAssertion;
    evidence: Evidence;
  }> {
    const binding = RecognitionAuthorityChallengeBindingSchema.parse(input.binding);
    const challengeHash = input.signed.statement.challengeHash.toLowerCase();
    if (!hasMatchingApplicationChallengeHash(input.nonce, challengeHash)) {
      throw new Error("Recognition authority challenge nonce or hash is invalid");
    }
    const nowMs = this.now();
    const hash = bindingHash(binding);
    const window = await this.store.readLive(challengeHash, hash, nowMs);
    if (window === null || window.challengeHash !== challengeHash || window.bindingHash !== hash
      || !Number.isSafeInteger(window.issuedAtMs) || !Number.isSafeInteger(window.expiresAtMs)
      || window.issuedAtMs < 0 || window.issuedAtMs > nowMs
      || window.expiresAtMs <= nowMs || window.expiresAtMs <= window.issuedAtMs) {
      throw new Error("Recognition authority challenge is invalid or already consumed");
    }
    const verified = await verifyRecognitionAuthorityAssertion({
      signed: input.signed,
      expected: { ...binding, challengeHash, evaluatedAtMs: nowMs },
      resolver: input.resolver,
    });
    const issuedAtMs = Date.parse(verified.statement.issuedAt);
    if (issuedAtMs < window.issuedAtMs || issuedAtMs > nowMs || issuedAtMs >= window.expiresAtMs) {
      throw new Error("Recognition authority assertion was signed outside the challenge window");
    }
    const evidence = await verifyEvidence(verified, nowMs);
    let consumeAtMs = this.now();
    const evidenceExpiry = evidenceExpiresAtMs?.(evidence);
    if (Date.parse(verified.statement.expiresAt) <= consumeAtMs
      || (evidenceExpiry !== undefined && (!Number.isSafeInteger(evidenceExpiry)
        || evidenceExpiry <= consumeAtMs))) {
      throw new Error("Recognition proof expired before challenge consumption");
    }
    await beforeConsume?.(consumeAtMs);
    consumeAtMs = this.now();
    if (Date.parse(verified.statement.expiresAt) <= consumeAtMs
      || (evidenceExpiry !== undefined && evidenceExpiry <= consumeAtMs)) {
      throw new Error("Recognition proof expired before challenge consumption");
    }
    const consumed = commit === undefined
      ? await this.store.consume(challengeHash, hash, consumeAtMs)
      : await commit({ challengeHash, bindingHash: hash, consumeAtMs, authority: verified, evidence });
    if (!consumed) {
      throw new Error("Recognition authority challenge is invalid or already consumed");
    }
    return { authority: verified, evidence };
  }

  private now(): number {
    const value = this.clock();
    if (!Number.isSafeInteger(value) || value < 0 || value > Date.parse("9999-12-31T23:54:59.999Z")) {
      throw new RangeError("Recognition authority challenge clock is invalid");
    }
    return value;
  }
}
