import { Buffer } from "node:buffer";

import { signJubjubDigestFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { deriveJubjubPublicKeyFromSeed, encodeJubjubSignature } from "@midnight-ntwrk/trust-registry-contract";
import { sha256Hex, type RecognitionAuthorityAssertion } from "@midnight-ntwrk/trust-registry-domain";
import {
  createMidnightDid,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
  recognitionAuthorityAssertionDigest,
} from "@midnight-ntwrk/trust-registry-integration";
import { describe, expect, it } from "vitest";

import { InMemoryApplicationChallengeStore } from "../application-challenges.js";
import {
  RecognitionAuthorityChallengeService,
  type RecognitionAuthorityChallengeBinding,
} from "../recognition-authority-challenges.js";

const seed = new Uint8Array(32).fill(94);
const authorityDid = createMidnightDid("recognition-challenge-authority");
const methodId = `${authorityDid}#assert-1`;
const issuedAtMs = Date.parse("2026-05-20T00:00:00.000Z");
const binding: RecognitionAuthorityChallengeBinding = {
  targetRegistryId: "registry:recognition-challenge:trusted",
  recognitionId: "recognition:challenge:authority:v1",
  authorityDid,
  recognizedRegistryId: "registry:external:trusted:v1",
  scopeResourceType: "credentialFamily",
  scopeResourceId: "credential-family:example:v1",
};
const resolver = createMidnightDidResolver([
  createMidnightDidLedgerFixture(authorityDid, {
    schnorrJubjubAssertionMethods: [
      { id: "assert-1", publicKey: deriveJubjubPublicKeyFromSeed(seed) },
    ],
  }),
]);

const signedFor = (challengeHash: string, changes: Partial<RecognitionAuthorityAssertion> = {}) => {
  const statement: RecognitionAuthorityAssertion = {
    version: "tr-recognition-authority-assertion-v1",
    ...binding,
    accreditationEvidenceCommitment: sha256Hex("referenced-accreditation"),
    challengeHash,
    issuedAt: new Date(issuedAtMs).toISOString(),
    expiresAt: new Date(issuedAtMs + 60 * 60_000).toISOString(),
    ...changes,
  };
  return {
    statement,
    proof: {
      verificationMethodId: methodId,
      algorithm: "jubjub-schnorr" as const,
      signature: `0x${Buffer.from(encodeJubjubSignature(
        signJubjubDigestFromSeed(seed, recognitionAuthorityAssertionDigest(statement, methodId)),
      )).toString("hex")}`,
    },
  };
};

describe("recognition authority DID challenge", () => {
  it("spends a tuple-bound challenge only after verifying the current DID assertion", async () => {
    const service = new RecognitionAuthorityChallengeService(
      new InMemoryApplicationChallengeStore(), () => issuedAtMs + 1000,
    );
    const challenge = await service.issue(binding);
    const signed = signedFor(challenge.challengeHash, {
      issuedAt: new Date(issuedAtMs + 1000).toISOString(),
    });
    await expect(service.verifyAndConsumeDidAssertion({
      binding: { ...binding, scopeResourceId: "credential-family:other:v1" },
      nonce: challenge.nonce,
      signed,
      resolver,
    })).rejects.toThrow(/invalid or already consumed/u);
    await expect(service.verifyAndConsumeDidAssertion({
      binding,
      nonce: challenge.nonce,
      signed: { ...signed, statement: { ...signed.statement, recognizedRegistryId: "registry:wrong:v1" } },
      resolver,
    })).rejects.toThrow(/does not match/u);
    await expect(service.verifyAndConsumeDidAssertion({
      binding,
      nonce: challenge.nonce,
      signed: {
        ...signed,
        statement: { ...signed.statement, accreditationEvidenceCommitment: sha256Hex("substituted") },
      },
      resolver,
    })).rejects.toThrow(/signature is invalid/u);
    const verified = await service.verifyAndConsumeDidAssertion({ binding, nonce: challenge.nonce, signed, resolver });
    expect(verified.statement).toEqual(signed.statement);
    await expect(service.verifyAndConsumeDidAssertion({ binding, nonce: challenge.nonce, signed, resolver }))
      .rejects.toThrow(/already consumed/u);
  });

  it("rejects a bad nonce, pre-challenge assertion, expiry, and concurrent replay", async () => {
    let nowMs = issuedAtMs;
    const service = new RecognitionAuthorityChallengeService(
      new InMemoryApplicationChallengeStore(), () => nowMs,
    );
    const challenge = await service.issue(binding);
    const signed = signedFor(challenge.challengeHash);
    await expect(service.verifyAndConsumeDidAssertion({
      binding,
      nonce: `0x${"00".repeat(32)}`,
      signed,
      resolver,
    })).rejects.toThrow(/nonce or hash/u);
    nowMs += 1000;
    await expect(service.verifyAndConsumeDidAssertion({
      binding,
      nonce: challenge.nonce,
      signed: signedFor(challenge.challengeHash, { issuedAt: new Date(issuedAtMs - 1000).toISOString() }),
      resolver,
    })).rejects.toThrow(/outside the challenge window/u);
    await expect(service.verifyAndConsumeDidAssertion({
      binding,
      nonce: challenge.nonce,
      signed: signedFor(challenge.challengeHash, { issuedAt: new Date(nowMs + 1000).toISOString() }),
      resolver,
    })).rejects.toThrow(/outside the challenge window/u);
    const results = await Promise.allSettled([
      service.verifyAndConsumeDidAssertion({ binding, nonce: challenge.nonce, signed, resolver }),
      service.verifyAndConsumeDidAssertion({ binding, nonce: challenge.nonce, signed, resolver }),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    const expired = await service.issue(binding);
    nowMs += 5 * 60_000;
    await expect(service.verifyAndConsumeDidAssertion({
      binding, nonce: expired.nonce, signed: signedFor(expired.challengeHash), resolver,
    })).rejects.toThrow(/invalid or already consumed/u);
  });
});
