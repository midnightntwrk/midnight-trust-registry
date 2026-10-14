import { Buffer } from "node:buffer";

import {
  createMidnightDIDHolderBinding,
  resolveMidnightDIDMethodBinding,
  signMidnightDIDCredentialProof,
  signMidnightDIDPresentationProof,
} from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import { deriveJubjubPublicKey } from "@midnight-ntwrk/trust-registry-contract";
import {
  RecognitionAccreditorAnchorSchema,
  canonicalizeJson,
  recognitionAccreditationClaimsCommitment,
  sha256Hex,
  type RecognitionAccreditationClaims,
} from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it, vi } from "vitest";

import { encodeApplicationVpProof } from "../application-vp-proof-json.js";
import { createMidnightDidLedgerFixture, createMidnightDidResolver } from "../did-resolution.js";
import { createMidnightDid } from "../fixtures.js";
import { verifyRecognitionAccreditationVp } from "../recognition-accreditation-vp.js";

const NOW = Date.parse("2026-05-20T00:10:00.000Z");
const NONCE = `0x${"11".repeat(32)}`;
const authorityDid = createMidnightDid("accreditation-authority");
const accreditorDid = createMidnightDid("independent-accreditor");
const statusAuthorityDid = createMidnightDid("accreditation-status-authority");
const bytes32 = (value: string | Uint8Array): Uint8Array => Buffer.from(sha256Hex(value).slice(2), "hex");
const hex = (value: Uint8Array): string => `0x${Buffer.from(value).toString("hex")}`;

const anchor = RecognitionAccreditorAnchorSchema.parse({
  format: "tr-recognition-accreditor-anchor-v1",
  targetRegistryId: "registry:local:trusted",
  policyId: "policy:recognition:accreditors",
  policyVersion: "v1",
  accreditorDid,
  accreditorAssertionMethodId: `${accreditorDid}#assertion-1`,
  credentialFamilyId: "credential-family:registry-accreditation:v1",
  schemaId: "schema:registry-accreditation:v1",
  statusRegistryId: "status-registry:accreditation:v1",
  statusAuthorityDid,
  statusAuthorityMethodId: `${statusAuthorityDid}#assertion-1`,
  recognizedRegistryId: "registry:external:trusted",
  scopeResourceType: "credentialfamily",
  scopeResourceId: "credential-family:example:v1",
  effectiveFrom: "2026-05-20T00:00:00.000Z",
  effectiveUntil: "2026-05-21T00:00:00.000Z",
});

async function fixture(options: {
  claims?: Partial<RecognitionAccreditationClaims>;
  presentationCredentialBodyRoot?: string;
  holderMethodId?: string;
} = {}) {
  const accreditorSecret = 19n;
  const holderSecret = 23n;
  const statusSecret = 29n;
  const resolver = createMidnightDidResolver([
    createMidnightDidLedgerFixture(accreditorDid, {
      verificationMethodId: "assertion-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKey(accreditorSecret),
    }),
    createMidnightDidLedgerFixture(authorityDid, {
      schnorrJubjubAuthenticationMethods: [
        { id: "auth-1", publicKey: deriveJubjubPublicKey(holderSecret) },
      ],
    }),
    createMidnightDidLedgerFixture(statusAuthorityDid, {
      verificationMethodId: "assertion-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKey(statusSecret),
    }),
  ]);
  const [accreditorMethod, holderMethod] = await Promise.all([
    resolveMidnightDIDMethodBinding({
      resolver,
      did: parseMidnightDIDString(accreditorDid),
      verificationMethodId: "#assertion-1",
      relationship: "assertionMethod",
    }),
    resolveMidnightDIDMethodBinding({
      resolver,
      did: parseMidnightDIDString(authorityDid),
      verificationMethodId: "#auth-1",
      relationship: "authentication",
    }),
  ]);
  const claims: RecognitionAccreditationClaims = {
    version: "tr-recognition-accreditation-claims-v1",
    authorityDid,
    accreditorDid,
    recognizedRegistryId: anchor.recognizedRegistryId,
    scopeResourceType: anchor.scopeResourceType,
    scopeResourceId: anchor.scopeResourceId,
    credentialFamilyId: anchor.credentialFamilyId,
    schemaId: anchor.schemaId,
    statusRegistryId: anchor.statusRegistryId,
    statusHandleCommitment: sha256Hex("accreditation-status-handle"),
    issuedAt: "2026-05-20T00:09:00.000Z",
    expiresAt: "2026-05-20T01:00:00.000Z",
    ...options.claims,
  };
  const rawCredentialBody = canonicalizeJson({
    version: "tr-recognition-accreditation-vp-body-v1",
    issuerMethodId: anchor.accreditorAssertionMethodId,
    holderMethodId: options.holderMethodId ?? `${authorityDid}#auth-1`,
    claims,
  });
  const credentialBodyRoot = bytes32(rawCredentialBody);
  const rawPresentationBody = canonicalizeJson({
    version: "tr-recognition-accreditation-presentation-v1",
    subjectDid: authorityDid,
    credentialBodyRoot: options.presentationCredentialBodyRoot ?? hex(credentialBodyRoot),
  });
  const presentationBodyRoot = bytes32(rawPresentationBody);
  const credentialProof = signMidnightDIDCredentialProof({
    methodBinding: accreditorMethod,
    secretScalar: accreditorSecret,
    bodyRoot: credentialBodyRoot,
    createdAt: BigInt(NOW - 60_000),
    challengeHash: bytes32("accreditation-issuance-challenge"),
  });
  const presentationProof = signMidnightDIDPresentationProof({
    methodBinding: holderMethod,
    secretScalar: holderSecret,
    bodyRoot: presentationBodyRoot,
    createdAt: BigInt(NOW),
    challengeHash: bytes32(Buffer.from(NONCE.slice(2), "hex")),
  });
  const statusSource = {
    verifyPinnedStatus: vi.fn(async () => ({
      registryId: anchor.statusRegistryId,
      authorityMethodId: anchor.statusAuthorityMethodId,
      statusHandleCommitment: claims.statusHandleCommitment,
      active: true,
      validUntilMs: NOW + 15 * 60_000,
      decisionCommitment: sha256Hex("pinned-status-decision"),
    })),
  };
  return {
    input: {
      submission: {
        rawCredentialBody,
        rawPresentationBody,
        credentialProof: encodeApplicationVpProof(credentialProof),
        presentationProof: encodeApplicationVpProof(presentationProof),
      },
      anchor,
      targetRegistryId: anchor.targetRegistryId,
      authorityDid,
      nonce: NONCE,
      evaluatedAtMs: NOW,
      resolver,
      statusSource,
    },
    claims,
    statusSource,
    holderBinding: createMidnightDIDHolderBinding(holderMethod).explicitBinding,
  };
}

describe("independently signed recognition accreditation VP", () => {
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
