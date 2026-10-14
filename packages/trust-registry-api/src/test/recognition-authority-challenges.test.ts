import { Buffer } from "node:buffer";

import { signJubjubDigestFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { deriveJubjubPublicKeyFromSeed, encodeJubjubSignature } from "@midnight-ntwrk/trust-registry-contract";
import { sha256Hex, type RecognitionAccreditorAnchor, type RecognitionAuthorityAssertion } from "@midnight-ntwrk/trust-registry-domain";
import {
  createMidnightDid,
  createMidnightDidLedgerFixture,
  createMidnightDidResolver,
  recognitionAuthorityAssertionDigest,
  recognitionAccreditationSubmissionCommitment,
  LocalTrustRegistryIntegrationHarness,
  verifyRecognitionAccreditationVp,
} from "@midnight-ntwrk/trust-registry-integration";
import { describe, expect, it, vi } from "vitest";

vi.mock("@midnight-ntwrk/trust-registry-integration", async (importOriginal) => ({
  ...await importOriginal<typeof import("@midnight-ntwrk/trust-registry-integration")>(),
  verifyRecognitionAccreditationVp: vi.fn(),
}));

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
    accreditationSubmissionCommitment: sha256Hex("referenced-accreditation"),
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
        statement: { ...signed.statement, accreditationSubmissionCommitment: sha256Hex("substituted") },
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

  it("spends the nonce only after both proofs and the accreditation commitment match", async () => {
    const accreditedBinding = { ...binding, scopeResourceType: "credentialfamily" };
    const harness = new LocalTrustRegistryIntegrationHarness("recognition-challenge");
    expect(harness.registryId).toBe(binding.targetRegistryId);
    const anchor: RecognitionAccreditorAnchor = {
      format: "tr-recognition-accreditor-anchor-v1",
      targetRegistryId: binding.targetRegistryId,
      policyId: harness.policyId,
      policyVersion: `v${(harness.simulator.getLedger().governancePolicyVersion + 1n).toString()}`,
      accreditorDid: createMidnightDid("accreditor"),
      accreditorAssertionMethodId: `${createMidnightDid("accreditor")}#assertion-1`,
      credentialFamilyId: "credential-family:accreditation:v1",
      schemaId: "schema:accreditation:v1",
      statusRegistryId: "status-registry:accreditation:v1",
      statusAuthorityDid: createMidnightDid("status-authority"),
      statusAuthorityMethodId: `${createMidnightDid("status-authority")}#assertion-1`,
      recognizedRegistryId: binding.recognizedRegistryId,
      scopeResourceType: accreditedBinding.scopeResourceType,
      scopeResourceId: binding.scopeResourceId,
      effectiveFrom: "2026-05-20T00:00:00.000Z",
      effectiveUntil: "2026-05-21T00:00:00.000Z",
    };
    harness.governRecognitionAccreditorAnchor(anchor);
    const evaluatedAtMs = Math.max(issuedAtMs + 1000, Date.parse(harness.policyRecord.effectiveFrom) + 1000);
    const commitment = sha256Hex("verified-accreditation-evidence");
    const verifiedAccreditation = {
      evidenceCommitment: commitment,
      anchorCommitment: sha256Hex("anchor"),
      claimsCommitment: sha256Hex("claims"),
      presentationHash: sha256Hex("presentation"),
      accreditorDidStateVersionId: "accreditor-state",
      authorityDidStateVersionId: "authority-state",
      statusAuthorityDidStateVersionId: "status-state",
      statusDecisionCommitment: sha256Hex("status"),
      evaluatedAtMs,
      expiresAtMs: evaluatedAtMs + 60_000,
    };
    const verifier = vi.mocked(verifyRecognitionAccreditationVp);
    verifier.mockReset();
    let nowMs = evaluatedAtMs;
    const service = new RecognitionAuthorityChallengeService(
      new InMemoryApplicationChallengeStore(), () => nowMs,
    );
    const challenge = await service.issue(accreditedBinding);
    const accreditation = {
      rawCredentialBody: "not used by mocked verifier",
      rawPresentationBody: "not used by mocked verifier",
      credentialProof: {},
      presentationProof: {},
    };
    const signed = signedFor(challenge.challengeHash, {
      ...accreditedBinding,
      accreditationSubmissionCommitment: recognitionAccreditationSubmissionCommitment(accreditation),
      issuedAt: new Date(evaluatedAtMs).toISOString(),
    });
    const request = {
      binding: accreditedBinding,
      nonce: challenge.nonce,
      signed,
      accreditation,
      governancePolicy: harness.policyRecord,
      activePolicyCommitment: `0x${Buffer.from(harness.simulator.getLedger().governancePolicyCommitment).toString("hex")}`,
      resolver,
      statusSource: { verifyPinnedStatus: vi.fn() },
    };
    verifier.mockRejectedValueOnce(new Error("accreditation VP is invalid"));
    await expect(service.verifyAndConsumeAccreditedAssertion(request)).rejects.toThrow(/VP is invalid/u);
    await expect(service.verifyAndConsumeAccreditedAssertion({
      ...request,
      signed: signedFor(challenge.challengeHash, {
        ...accreditedBinding,
        accreditationSubmissionCommitment: sha256Hex("another-submission"),
        issuedAt: new Date(evaluatedAtMs).toISOString(),
      }),
    })).rejects.toThrow(/submitted accreditation VP/u);
    verifier.mockResolvedValue(verifiedAccreditation);
    await expect(service.verifyAndConsumeAccreditedAssertion({
      ...request,
      governancePolicy: {
        ...harness.policyRecord,
        recognitionAccreditorAnchors: [{ ...anchor, scopeResourceId: "credential-family:other:v1" }],
      },
    })).rejects.toThrow(/active governed policy/u);
    verifier.mockImplementationOnce(async () => {
      nowMs += 1000;
      return { ...verifiedAccreditation, expiresAtMs: evaluatedAtMs + 500 };
    });
    await expect(service.verifyAndConsumeAccreditedAssertion(request))
      .rejects.toThrow(/expired before challenge consumption/u);
    const results = await Promise.allSettled([
      service.verifyAndConsumeAccreditedAssertion(request),
      service.verifyAndConsumeAccreditedAssertion(request),
    ]);
    expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
    expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
    const successful = results.find((result) => result.status === "fulfilled");
    expect(successful?.value.evidenceCommitment).toBe(sha256Hex(JSON.stringify([
      "tr:recognition:combined-verified-evidence:v1",
      successful?.value.authority.evidenceCommitment,
      verifiedAccreditation.evidenceCommitment,
    ])));
    expect(verifier).toHaveBeenCalledWith(expect.objectContaining({
      nonce: challenge.nonce,
      authorityDid,
      targetRegistryId: binding.targetRegistryId,
      evaluatedAtMs,
    }));
  });
});
