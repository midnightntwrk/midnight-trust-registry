import { Buffer } from "node:buffer";

import { signJubjubDigestFromSeed } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { encodeJubjubSignature } from "@midnight-ntwrk/trust-registry-contract";
import {
  recognitionAccreditationClaimsCommitment,
  sha256Hex,
  type RecognitionAuthorityAssertion,
} from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it, vi } from "vitest";

import {
  createRecognitionAccreditationVpScenarioFixture,
  RECOGNITION_VP_FIXTURE_ANCHOR,
  RECOGNITION_VP_FIXTURE_AUTHORITY_DID,
  RECOGNITION_VP_FIXTURE_TIME_MS,
} from "../recognition-accreditation-vp-fixtures.js";
import { recognitionAuthorityAssertionDigest, verifyRecognitionAuthorityAssertion } from "../recognition-authority-assertion.js";
import { recognitionAccreditationSubmissionCommitment, verifyRecognitionAccreditationVp } from "../recognition-accreditation-vp.js";

const NOW = RECOGNITION_VP_FIXTURE_TIME_MS;
const authorityDid = RECOGNITION_VP_FIXTURE_AUTHORITY_DID;
const anchor = RECOGNITION_VP_FIXTURE_ANCHOR;
const accreditorDid = anchor.accreditorDid;
const bytes32 = (value: string | Uint8Array): Uint8Array => Buffer.from(sha256Hex(value).slice(2), "hex");
const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;

async function fixture(options: Parameters<typeof createRecognitionAccreditationVpScenarioFixture>[0] = {}) {
  const scenario = await createRecognitionAccreditationVpScenarioFixture(options);
  const statusSource = { verifyPinnedStatus: vi.fn(scenario.statusSource.verifyPinnedStatus) };
  return { ...scenario, statusSource, input: { ...scenario.input, statusSource } };
}

describe("independently signed recognition accreditation VP", () => {
  it("commits to exact submitted bodies but canonicalizes proof object order", async () => {
    const { input } = await fixture();
    const commitment = recognitionAccreditationSubmissionCommitment(input.submission);
    const reorderedProof = Object.fromEntries(
      Object.entries(input.submission.credentialProof).reverse(),
    );
    expect(recognitionAccreditationSubmissionCommitment({
      ...input.submission,
      credentialProof: reorderedProof,
    })).toBe(commitment);
    expect(recognitionAccreditationSubmissionCommitment({
      ...input.submission,
      rawCredentialBody: `${input.submission.rawCredentialBody} `,
    })).not.toBe(commitment);
  });

  it("verifies distinct accreditor, holder and status DID methods and returns redacted evidence", async () => {
    const { input, claims, statusSource } = await fixture();
    const result = await verifyRecognitionAccreditationVp(input);
    expect(result.claimsCommitment).toBe(recognitionAccreditationClaimsCommitment(claims));
    expect(result.evidenceCommitment).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(result.accreditorDidStateVersionId).toBeTruthy();
    expect(result.authorityDidStateVersionId).toBeTruthy();
    expect(result.statusAuthorityDidStateVersionId).toBeTruthy();
    expect(result.expiresAtMs).toBe(NOW + 15 * 60_000);
    expect(JSON.stringify(result)).not.toContain(authorityDid);
    expect(statusSource.verifyPinnedStatus).toHaveBeenCalledOnce();
  });

  it("binds a separate signed authority DID assertion to the verified accreditation evidence", async () => {
    const { input, authorityAssertionSeed } = await fixture();
    const accreditation = await verifyRecognitionAccreditationVp(input);
    const challengeHash = hex(bytes32(Buffer.from(input.nonce.slice(2), "hex")));
    const statement: RecognitionAuthorityAssertion = {
      version: "tr-recognition-authority-assertion-v1",
      targetRegistryId: input.targetRegistryId,
      recognitionId: "recognition:external:example:v1",
      authorityDid,
      recognizedRegistryId: anchor.recognizedRegistryId,
      scopeResourceType: anchor.scopeResourceType,
      scopeResourceId: anchor.scopeResourceId,
      accreditationSubmissionCommitment: recognitionAccreditationSubmissionCommitment(input.submission),
      challengeHash,
      issuedAt: new Date(NOW).toISOString(),
      expiresAt: new Date(NOW + 60_000).toISOString(),
    };
    const verificationMethodId = `${authorityDid}#assertion-1`;
    const signed = {
      statement,
      proof: {
        verificationMethodId,
        algorithm: "jubjub-schnorr" as const,
        signature: hex(Buffer.from(encodeJubjubSignature(signJubjubDigestFromSeed(
          authorityAssertionSeed,
          recognitionAuthorityAssertionDigest(statement, verificationMethodId),
        )))),
      },
    };
    const verifiedAuthority = await verifyRecognitionAuthorityAssertion({
      signed,
      expected: { ...statement, evaluatedAtMs: NOW },
      resolver: input.resolver,
    });
    expect(verifiedAuthority.statement.accreditationSubmissionCommitment).toBe(
      recognitionAccreditationSubmissionCommitment(input.submission),
    );
    expect(verifiedAuthority.statement.accreditationSubmissionCommitment).not.toBe(accreditation.evidenceCommitment);
    await expect(verifyRecognitionAuthorityAssertion({
      signed: {
        ...signed,
        statement: { ...statement, accreditationSubmissionCommitment: sha256Hex("substituted-accreditation") },
      },
      expected: { ...statement, evaluatedAtMs: NOW },
      resolver: input.resolver,
    })).rejects.toThrow(/signature is invalid/u);
  });

  it("rejects signed claims outside governed issuer, authority, registry, scope and family", async () => {
    for (const claims of [
      { accreditorDid: authorityDid },
      { authorityDid: accreditorDid },
      { recognizedRegistryId: "registry:external:other" },
      { scopeResourceId: "credential-family:other:v1" },
      { credentialFamilyId: "credential-family:other:v1" },
      { schemaId: "schema:other:v1" },
      { statusRegistryId: "status-registry:other:v1" },
    ]) {
      const { input, statusSource } = await fixture({ claims });
      await expect(verifyRecognitionAccreditationVp(input)).rejects.toThrow();
      expect(statusSource.verifyPinnedStatus).not.toHaveBeenCalled();
    }
  });

  it("rejects tampered proof, body substitution, wrong challenge and non-authentication holder method", async () => {
    const { input, statusSource } = await fixture();
    const credentialProof = structuredClone(input.submission.credentialProof);
    const signature = credentialProof.signature as Record<string, unknown>;
    signature.s = (BigInt(signature.s as string) + 1n).toString();
    await expect(verifyRecognitionAccreditationVp({
      ...input,
      submission: { ...input.submission, credentialProof },
    })).rejects.toThrow();
    const presentationProof = structuredClone(input.submission.presentationProof);
    const vpSignature = presentationProof.signature as Record<string, unknown>;
    vpSignature.s = (BigInt(vpSignature.s as string) + 1n).toString();
    await expect(verifyRecognitionAccreditationVp({
      ...input,
      submission: { ...input.submission, presentationProof },
    })).rejects.toThrow();
    await expect(verifyRecognitionAccreditationVp({
      ...input,
      nonce: `0x${"22".repeat(32)}`,
    })).rejects.toThrow(/challenge/u);
    await expect(verifyRecognitionAccreditationVp({
      ...input,
      submission: { ...input.submission, rawCredentialBody: `${input.submission.rawCredentialBody} ` },
    })).rejects.toThrow();
    const substituted = await fixture({ presentationCredentialBodyRoot: sha256Hex("substituted") });
    await expect(verifyRecognitionAccreditationVp(substituted.input)).rejects.toThrow(/substitutes/u);
    const wrongMethod = await fixture({ holderMethodId: `${authorityDid}#assertion-1` });
    await expect(verifyRecognitionAccreditationVp(wrongMethod.input)).rejects.toThrow();
    await expect(verifyRecognitionAccreditationVp({
      ...input,
      submission: {
        ...input.submission,
        rawCredentialBody: input.submission.rawCredentialBody.replace(
          '"claims":', '"unexpected":true,"claims":',
        ),
      },
    })).rejects.toThrow(/unexpected fields/u);
    await expect(verifyRecognitionAccreditationVp({
      ...input,
      submission: {
        ...input.submission,
        rawCredentialBody: input.submission.rawCredentialBody.replace(
          '"claims":', '"version":"tr-recognition-accreditation-vp-body-v1","claims":',
        ),
      },
    })).rejects.toThrow(/canonical JSON/u);
    expect(statusSource.verifyPinnedStatus).not.toHaveBeenCalled();
  });

  it("rejects expired, inactive, stale and substituted status", async () => {
    const expired = await fixture({ claims: { expiresAt: "2026-05-20T00:10:00.000Z" } });
    await expect(verifyRecognitionAccreditationVp(expired.input)).rejects.toThrow(/effective window/u);
    for (const changed of [
      { active: false },
      { validUntilMs: NOW },
      { registryId: "status-registry:other:v1" },
      { authorityMethodId: `${accreditorDid}#assertion-1` },
      { statusHandleCommitment: sha256Hex("substituted") },
    ]) {
      const { input, statusSource } = await fixture();
      statusSource.verifyPinnedStatus.mockImplementationOnce(async () => ({
        registryId: anchor.statusRegistryId,
        authorityMethodId: anchor.statusAuthorityMethodId,
        statusHandleCommitment: sha256Hex("accreditation-status-handle"),
        active: true,
        validUntilMs: NOW + 15 * 60_000,
        decisionCommitment: sha256Hex("pinned-status-decision"),
        ...changed,
      }));
      await expect(verifyRecognitionAccreditationVp(input)).rejects.toThrow(/status is not active/u);
    }
  });
});
