import { describe, expect, it } from "vitest";

import {
  RecognitionAccreditationClaimsSchema,
  RecognitionAccreditorAnchorSchema,
  assertRecognitionAccreditationClaimsMatchAnchor,
  recognitionAccreditationClaimsCommitment,
  recognitionAccreditorAnchorCommitment,
} from "../recognition-accreditation.js";

const authorityDid = `did:midnight:undeployed:${"a".repeat(64)}`;
const accreditorDid = `did:midnight:undeployed:${"b".repeat(64)}`;
const statusAuthorityDid = `did:midnight:undeployed:${"c".repeat(64)}`;
const evaluatedAtMs = Date.parse("2026-05-20T00:10:00.000Z");

const anchor = RecognitionAccreditorAnchorSchema.parse({
  format: "tr-recognition-accreditor-anchor-v1",
  targetRegistryId: "registry:local:trusted",
  policyId: "policy:recognition:accreditors",
  policyVersion: "v1",
  accreditorDid,
  accreditorAssertionMethodId: `${accreditorDid}#assert-1`,
  credentialFamilyId: "credential-family:registry-accreditation:v1",
  schemaId: "schema:registry-accreditation:v1",
  statusRegistryId: "status-registry:accreditation:v1",
  statusAuthorityDid,
  statusAuthorityMethodId: `${statusAuthorityDid}#assert-1`,
  recognizedRegistryId: "registry:external:trusted",
  scopeResourceType: "credentialfamily",
  scopeResourceId: "credential-family:example:v1",
  effectiveFrom: "2026-05-20T00:00:00.000Z",
  effectiveUntil: "2026-05-21T00:00:00.000Z",
});
const claims = RecognitionAccreditationClaimsSchema.parse({
  version: "tr-recognition-accreditation-claims-v1",
  authorityDid,
  accreditorDid,
  recognizedRegistryId: anchor.recognizedRegistryId,
  scopeResourceType: anchor.scopeResourceType,
  scopeResourceId: anchor.scopeResourceId,
  credentialFamilyId: anchor.credentialFamilyId,
  schemaId: anchor.schemaId,
  statusRegistryId: anchor.statusRegistryId,
  statusHandleCommitment: `0x${"d".repeat(64)}`,
  issuedAt: "2026-05-20T00:01:00.000Z",
  expiresAt: "2026-05-20T01:00:00.000Z",
});

describe("recognition accreditation anchor and claims", () => {
  it("commits exact governed policy and claims independently of object property order", () => {
    const reorderedAnchor = Object.fromEntries(Object.entries(anchor).reverse()) as typeof anchor;
    const reorderedClaims = Object.fromEntries(Object.entries(claims).reverse()) as typeof claims;
    expect(recognitionAccreditorAnchorCommitment(reorderedAnchor))
      .toBe(recognitionAccreditorAnchorCommitment(anchor));
    expect(recognitionAccreditationClaimsCommitment(reorderedClaims))
      .toBe(recognitionAccreditationClaimsCommitment(claims));
    expect(recognitionAccreditorAnchorCommitment(anchor))
      .not.toBe(recognitionAccreditationClaimsCommitment(claims));
    expect(recognitionAccreditorAnchorCommitment({
      ...anchor, effectiveFrom: "2026-05-20T08:00:00+08:00",
    })).toBe(recognitionAccreditorAnchorCommitment(anchor));
    expect(recognitionAccreditationClaimsCommitment({
      ...claims, issuedAt: "2026-05-20T08:01:00+08:00",
    })).toBe(recognitionAccreditationClaimsCommitment(claims));
    expect(() => assertRecognitionAccreditationClaimsMatchAnchor({
      anchor, claims, authorityDid, evaluatedAtMs,
    })).not.toThrow();
  });

  it("rejects wrong applicant, accreditor, registry, scope, family, schema and status registry", () => {
    for (const changed of [
      { authorityDid: `did:midnight:undeployed:${"e".repeat(64)}` },
      { accreditorDid: authorityDid },
      { recognizedRegistryId: "registry:other:trusted" },
      { scopeResourceType: "requestprofile" },
      { scopeResourceId: "credential-family:other:v1" },
      { credentialFamilyId: "credential-family:other:v1" },
      { schemaId: "schema:other:v1" },
      { statusRegistryId: "status-registry:other:v1" },
    ]) {
      expect(() => assertRecognitionAccreditationClaimsMatchAnchor({
        anchor, claims: { ...claims, ...changed }, authorityDid, evaluatedAtMs,
      })).toThrow(/do not match/u);
    }
  });

  it("rejects unknown fields, mismatched DID methods, case variants, and invalid windows", () => {
    expect(() => RecognitionAccreditorAnchorSchema.parse({ ...anchor, untrusted: true })).toThrow();
    expect(() => RecognitionAccreditationClaimsSchema.parse({ ...claims, extra: "claim" })).toThrow();
    expect(() => RecognitionAccreditorAnchorSchema.parse({
      ...anchor, accreditorAssertionMethodId: `${authorityDid}#assert-1`,
    })).toThrow(/must belong/u);
    expect(() => RecognitionAccreditorAnchorSchema.parse({
      ...anchor, statusAuthorityMethodId: `${authorityDid}#assert-1`,
    })).toThrow(/must belong/u);
    expect(() => RecognitionAccreditorAnchorSchema.parse({
      ...anchor, recognizedRegistryId: "Registry:External:Trusted",
    })).toThrow(/canonical lowercase/u);
    expect(() => RecognitionAccreditorAnchorSchema.parse({
      ...anchor, effectiveUntil: anchor.effectiveFrom,
    })).toThrow(/must be positive/u);
    expect(() => RecognitionAccreditorAnchorSchema.parse({
      ...anchor, effectiveFrom: "2026-05-20T00:00:00.0001Z",
    })).toThrow(/millisecond precision/u);
    expect(() => RecognitionAccreditationClaimsSchema.parse({
      ...claims, expiresAt: claims.issuedAt,
    })).toThrow(/must be positive/u);
  });

  it("rejects an authority self-accreditation even if the anchor names it", () => {
    expect(() => assertRecognitionAccreditationClaimsMatchAnchor({
      anchor: {
        ...anchor,
        accreditorDid: authorityDid,
        accreditorAssertionMethodId: `${authorityDid}#assert-1`,
      },
      claims: { ...claims, accreditorDid: authorityDid },
      authorityDid,
      evaluatedAtMs,
    })).toThrow(/do not match/u);
  });

  it("rejects inactive policy or claims at the trusted evaluation instant", () => {
    for (const at of [
      Date.parse("2026-05-20T00:00:00.000Z"),
      Date.parse(claims.expiresAt),
      Date.parse(anchor.effectiveUntil),
    ]) {
      expect(() => assertRecognitionAccreditationClaimsMatchAnchor({
        anchor, claims, authorityDid, evaluatedAtMs: at,
      })).toThrow(/outside its effective window/u);
    }
    expect(() => assertRecognitionAccreditationClaimsMatchAnchor({
      anchor, claims, authorityDid, evaluatedAtMs: Number.NaN,
    })).toThrow(/evaluation time is invalid/u);
  });
});
