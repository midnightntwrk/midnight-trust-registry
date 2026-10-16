import { Buffer } from "node:buffer";

import { signJubjubDigestFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { deriveJubjubPublicKeyFromSeed, encodeJubjubSignature } from "@midnight-ntwrk/trust-registry-contract";
import { sha256Hex, type RecognitionAuthorityAssertion } from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it } from "vitest";

import { createMidnightDidLedgerFixture, createMidnightDidResolver } from "../did-resolution.js";
import { createMidnightDid, createRecognitionScenarioFixture } from "../fixtures.js";
import {
  recognitionAuthorityAssertionDigest,
  verifyRecognitionAuthorityAssertion,
} from "../recognition-authority-assertion.js";

const seed = new Uint8Array(32).fill(93);
const authorityDid = createMidnightDid("recognition-assertion-authority");
const methodId = `${authorityDid}#assert-1`;
const registryId = "registry:recognition-assertion:trusted";
const fixture = createRecognitionScenarioFixture("recognition-assertion");
const evaluatedAtMs = Date.parse("2026-05-20T00:10:00.000Z");
const statement: RecognitionAuthorityAssertion = {
  version: "tr-recognition-authority-assertion-v1",
  targetRegistryId: registryId,
  recognitionId: fixture.recognitionId,
  authorityDid,
  recognizedRegistryId: fixture.recognizedRegistryId,
  scopeResourceType: fixture.scopeResourceType,
  scopeResourceId: fixture.scopeResourceId,
  accreditationSubmissionCommitment: sha256Hex("independent-accreditation-reference"),
  challengeHash: sha256Hex("one-use-recognition-challenge"),
  issuedAt: "2026-05-20T00:00:00.000Z",
  expiresAt: "2026-05-20T01:00:00.000Z",
};
const signed = {
  statement,
  proof: {
    verificationMethodId: methodId,
    algorithm: "jubjub-schnorr" as const,
    signature: `0x${Buffer.from(encodeJubjubSignature(
      signJubjubDigestFromSeed(seed, recognitionAuthorityAssertionDigest(statement, methodId)),
    )).toString("hex")}`,
  },
};
const expected = {
  targetRegistryId: registryId,
  recognitionId: fixture.recognitionId,
  authorityDid,
  recognizedRegistryId: fixture.recognizedRegistryId,
  scopeResourceType: fixture.scopeResourceType,
  scopeResourceId: fixture.scopeResourceId,
  challengeHash: statement.challengeHash,
  evaluatedAtMs,
};
const resolver = createMidnightDidResolver([
  createMidnightDidLedgerFixture(authorityDid, {
    schnorrJubjubAssertionMethods: [
      { id: "assert-1", publicKey: deriveJubjubPublicKeyFromSeed(seed) },
    ],
  }),
]);

describe("Midnight DID recognition authority assertion", () => {
  it("verifies a scoped, challenge-bound authority statement and returns a signed evidence commitment", async () => {
    const verified = await verifyRecognitionAuthorityAssertion({ signed, expected, resolver });
    expect(verified.statement).toEqual(statement);
    expect(verified.verificationMethodId).toBe(methodId);
    expect(verified.didStateVersionId).toBe("1");
    expect(verified.evaluatedAtMs).toBe(evaluatedAtMs);
    expect(verified.evidenceCommitment).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(verified.evidenceCommitment).not.toBe(statement.accreditationSubmissionCommitment);
    const nextVersion = createMidnightDidResolver([
      createMidnightDidLedgerFixture(authorityDid, {
        version: 2n,
        schnorrJubjubAssertionMethods: [
          { id: "assert-1", publicKey: deriveJubjubPublicKeyFromSeed(seed) },
        ],
      }),
    ]);
    const updated = await verifyRecognitionAuthorityAssertion({
      signed, expected, resolver: nextVersion,
    });
    expect(updated.didStateVersionId).toBe("2");
    expect(updated.evidenceCommitment).not.toBe(verified.evidenceCommitment);
  });

  it("rejects changed authority, registry, scope, and challenge with no trust fallback", async () => {
    for (const changed of [
      { authorityDid: createMidnightDid("other-authority") },
      { recognizedRegistryId: "registry:other:v1" },
      { scopeResourceType: "other-scope" },
      { scopeResourceId: "credential-family:other:v1" },
      { challengeHash: sha256Hex("other-challenge") },
      { targetRegistryId: "registry:other:trusted" },
      { recognitionId: "recognition:other:v1" },
    ]) {
      await expect(verifyRecognitionAuthorityAssertion({
        signed,
        expected: { ...expected, ...changed },
        resolver,
      })).rejects.toThrow(/does not match/u);
    }
  });

  it("rejects altered signed content, expired or premature evidence, and a rotated DID key", async () => {
    await expect(verifyRecognitionAuthorityAssertion({
      signed: {
        ...signed,
        statement: { ...statement, accreditationSubmissionCommitment: `0x${"00".repeat(32)}` },
      },
      expected,
      resolver,
    })).rejects.toThrow(/nonzero/u);
    await expect(verifyRecognitionAuthorityAssertion({
      signed: {
        ...signed,
        statement: { ...statement, expiresAt: "2026-05-22T00:00:00.000Z" },
      },
      expected,
      resolver,
    })).rejects.toThrow(/at most 24 hours/u);
    await expect(verifyRecognitionAuthorityAssertion({
      signed: { ...signed, statement: { ...statement, accreditationSubmissionCommitment: sha256Hex("substituted") } },
      expected,
      resolver,
    })).rejects.toThrow(/signature is invalid/u);
    await expect(verifyRecognitionAuthorityAssertion({
      signed,
      expected: { ...expected, evaluatedAtMs: Date.parse(statement.expiresAt) },
      resolver,
    })).rejects.toThrow(/not current/u);
    await expect(verifyRecognitionAuthorityAssertion({
      signed,
      expected: { ...expected, evaluatedAtMs: Date.parse(statement.issuedAt) - 60_001 },
      resolver,
    })).rejects.toThrow(/not current/u);
    const rotatedResolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(authorityDid, {
        schnorrJubjubAssertionMethods: [
          { id: "assert-1", publicKey: deriveJubjubPublicKeyFromSeed(new Uint8Array(32).fill(94)) },
        ],
      }),
    ]);
    await expect(verifyRecognitionAuthorityAssertion({
      signed, expected, resolver: rotatedResolver,
    })).rejects.toThrow(/signature is invalid/u);
  });

  it("requires the resolved DID assertion relationship, not authentication alone", async () => {
    const authenticationOnly = createMidnightDidResolver([
      createMidnightDidLedgerFixture(authorityDid, {
        schnorrJubjubAuthenticationMethods: [
          { id: "assert-1", publicKey: deriveJubjubPublicKeyFromSeed(seed) },
        ],
      }),
    ]);
    await expect(verifyRecognitionAuthorityAssertion({
      signed, expected, resolver: authenticationOnly,
    })).rejects.toThrow();
  });
});
