import { Buffer } from "node:buffer";

import {
  createMidnightDIDHolderBinding,
  resolveMidnightDIDMethodBinding,
  signMidnightDIDCredentialProof,
  signMidnightDIDPresentationProof,
} from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import { deriveJubjubPublicKey } from "@midnight-ntwrk/trust-registry-contract";
import { ApplicationChallengeBindingSchema, computeAuthorizationScopeCommitment, issuerGovernedResourceId, sha256Hex } from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it, vi } from "vitest";

import {
  ApplicationVpDependencyUnavailableError,
  createApplicationVpIntakeVerifier,
  verifyApplicationVp,
  type ApplicationVpFamilyAdapter,
  type ApplicationVpMaterial,
} from "../application-vp-verifier.js";
import { createMidnightDidLedgerFixture, createMidnightDidResolver } from "../did-resolution.js";
import { createIssuerAuthorizationScopeFixture, createIssuerScenarioFixture, createMidnightDid } from "../fixtures.js";

const NOW = Date.parse("2026-05-20T00:01:00.000Z");
const NONCE = `0x${"11".repeat(32)}`;
const bytes32 = (value: string): Uint8Array => Buffer.from(sha256Hex(value).slice(2), "hex");

async function fixture() {
  const issuerDid = createMidnightDid("vp-issuer");
  const subjectDid = createMidnightDid("vp-holder");
  const issuerSecret = 19n;
  const holderSecret = 23n;
  const resolver = createMidnightDidResolver([
    createMidnightDidLedgerFixture(issuerDid, {
      verificationMethodId: "assertion-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKey(issuerSecret),
    }),
    createMidnightDidLedgerFixture(subjectDid, {
      verificationMethodId: "auth-1",
      schnorrJubjubPublicKey: deriveJubjubPublicKey(holderSecret),
    }),
  ]);
  const issuerMethod = await resolveMidnightDIDMethodBinding({
    resolver,
    did: parseMidnightDIDString(issuerDid),
    verificationMethodId: "#assertion-1",
    relationship: "assertionMethod",
  });
  const holderMethod = await resolveMidnightDIDMethodBinding({
    resolver,
    did: parseMidnightDIDString(subjectDid),
    verificationMethodId: "#auth-1",
    relationship: "authentication",
  });
  const credentialBodyRoot = bytes32("credential-body");
  const presentationBodyRoot = bytes32("presentation-body");
  const challengeHash = Buffer.from(sha256Hex(Buffer.from(NONCE.slice(2), "hex")).slice(2), "hex");
  const holderBinding = createMidnightDIDHolderBinding(holderMethod).explicitBinding;
  const material: ApplicationVpMaterial = {
    issuerDid,
    issuerMethodId: "#assertion-1",
    subjectDid,
    holderMethodId: "#auth-1",
    credentialProof: signMidnightDIDCredentialProof({
      methodBinding: issuerMethod,
      secretScalar: issuerSecret,
      bodyRoot: credentialBodyRoot,
      createdAt: BigInt(NOW - 60_000),
      challengeHash: bytes32("issuance-challenge"),
    }),
    presentationProof: signMidnightDIDPresentationProof({
      methodBinding: holderMethod,
      secretScalar: holderSecret,
      bodyRoot: presentationBodyRoot,
      createdAt: BigInt(NOW),
      challengeHash,
    }),
    credentialBodyRoot,
    presentationBodyRoot,
    credentialHolderBinding: holderBinding,
    presentationHolderBinding: holderBinding,
    statusBinding: {
      registryRef: {
        registryId: bytes32("status-registry"),
        authorityVerificationMethodRef: issuerMethod.verificationMethodRef,
      },
      statusHandleCommitment: bytes32("credential-status-handle"),
    },
    credentialExpiresAtMs: NOW + 60 * 60_000,
  };
  const family: ApplicationVpFamilyAdapter<{ raw: string }> = {
    prepare: vi.fn(async () => material),
    assertCredentialBodyBinding: vi.fn(async () => true as const),
    assertIssuerEligible: vi.fn(async () => true as const),
    assertStatusActive: vi.fn(async () => ({ validUntilMs: NOW + 15 * 60_000 })),
    assertRoleClaims: vi.fn(async () => ({
      claimsCommitment: sha256Hex("accepted-issuer-claims"),
      scopeCommitment: computeAuthorizationScopeCommitment(createIssuerAuthorizationScopeFixture(createIssuerScenarioFixture("vp"))),
    })),
  };
  return {
    input: {
      submission: { raw: "private-presentation-payload" },
      nonce: NONCE,
      expectedSubjectDid: subjectDid,
      scope: createIssuerAuthorizationScopeFixture(createIssuerScenarioFixture("vp")),
      evaluatedAtMs: NOW,
      resolver,
      family,
    },
    material,
    family,
  };
}

describe("published VC proof and DID application verifier port", () => {
  it("adapts proof-observed bindings for challenge intake rather than echoing expected inputs", async () => {
    const { input, family } = await fixture();
    const binding = ApplicationChallengeBindingSchema.parse({
      registryId: "registry:vp:test",
      applicationId: "application:vp:one",
      subjectDid: input.expectedSubjectDid,
      evidenceVerifierDid: createMidnightDid("vp-evidence-verifier"),
      role: "issuer",
      policyId: "policy:vp:v1",
      policyVersion: "v1",
      scope: input.scope,
      scopeCommitment: computeAuthorizationScopeCommitment(input.scope),
      governedResource: { type: "credentialFamily", id: issuerGovernedResourceId(input.scope, "credentialFamily") },
    });
    const verifyPresentation = createApplicationVpIntakeVerifier({
      resolver: input.resolver,
      family: input.family,
    });
    const context = { nonce: input.nonce, binding, evaluatedAt: new Date(NOW).toISOString() };
    const verified = await verifyPresentation(input.submission, context);
    expect(verified.subjectDid).toBe(input.expectedSubjectDid);
    expect(verified.nonce).toBe(input.nonce);
    expect(verified.scopeCommitment).toBe(binding.scopeCommitment);
    await expect(verifyPresentation(input.submission, { ...context, nonce: `0x${"22".repeat(32)}` }))
      .rejects.toMatchObject({ category: "invalid_presentation" });
    await expect(verifyPresentation(input.submission, {
      ...context,
      binding: { ...binding, subjectDid: createMidnightDid("other-holder") },
    }))
      .rejects.toMatchObject({ category: "invalid_presentation" });
    await expect(verifyPresentation(input.submission, {
      ...context,
      evaluatedAt: new Date(NOW + 6 * 60_000).toISOString(),
    })).rejects.toMatchObject({ category: "expired" });
    await expect(verifyPresentation(input.submission, {
      ...context,
      evaluatedAt: "May 20, 2026 00:01:00 UTC",
    })).rejects.toMatchObject({ category: "invalid_presentation" });
    const otherScope = { ...input.scope, credentialFamilyId: "credential-family:other" };
    family.assertRoleClaims = vi.fn(async () => ({
      claimsCommitment: sha256Hex("accepted-issuer-claims"),
      scopeCommitment: binding.scopeCommitment,
    }));
    await expect(verifyPresentation(input.submission, {
      ...context,
      binding: {
        ...binding,
        scope: otherScope,
        scopeCommitment: computeAuthorizationScopeCommitment(otherScope),
        governedResource: { type: "credentialFamily", id: issuerGovernedResourceId(otherScope, "credentialFamily") },
      },
    })).rejects.toMatchObject({ category: "ineligible" });
  });

  it("checks real issuance/presentation proofs, DID methods, challenge, and trusted eligibility ports", async () => {
    const { input, family, material } = await fixture();
    const verified = await verifyApplicationVp(input);
    expect(verified.subjectDid).toBe(input.expectedSubjectDid);
    expect(verified.nonce).toBe(NONCE);
    expect(verified.scopeCommitment).toBe(computeAuthorizationScopeCommitment(input.scope));
    expect(verified.presentationHash).toMatch(/^0x[0-9a-f]{64}$/u);
    expect(verified.presentationHash).not.toBe(sha256Hex(bytes32("presentation-body")));
    expect(verified.expiresAt).toBe(new Date(NOW + 15 * 60_000).toISOString());
    expect(JSON.stringify(verified)).not.toContain("private-presentation-payload");
    expect(family.assertIssuerEligible).toHaveBeenCalledOnce();
    expect(family.assertCredentialBodyBinding).toHaveBeenCalledOnce();
    expect(family.assertStatusActive).toHaveBeenCalledOnce();
    expect(family.assertRoleClaims).toHaveBeenCalledOnce();
    expect(family.assertRoleClaims).toHaveBeenCalledWith(material);
  });

  it("rejects wrong challenge or holder before eligibility checks", async () => {
    const { input, family } = await fixture();
    await expect(verifyApplicationVp({ ...input, nonce: `0x${"22".repeat(32)}` })).rejects.toMatchObject({
      category: "invalid_presentation",
    });
    await expect(verifyApplicationVp({ ...input, expectedSubjectDid: createMidnightDid("other-holder") })).rejects.toMatchObject({
      category: "invalid_presentation",
    });
    expect(family.assertIssuerEligible).not.toHaveBeenCalled();
  });

  it("permits bounded clock skew but rejects future proofs outside the allowance", async () => {
    const { input, material, family } = await fixture();
    const futureProof = { ...material.presentationProof, createdAt: BigInt(NOW + 1) };
    // The signature must cover the altered timestamp; re-sign with the fixture holder key.
    const holderMethod = await resolveMidnightDIDMethodBinding({
      resolver: input.resolver,
      did: parseMidnightDIDString(material.subjectDid),
      verificationMethodId: material.holderMethodId,
      relationship: "authentication",
    });
    family.prepare = vi.fn(async () => ({
      ...material,
      presentationProof: signMidnightDIDPresentationProof({
        methodBinding: holderMethod,
        secretScalar: 23n,
        bodyRoot: material.presentationBodyRoot,
        createdAt: futureProof.createdAt,
        challengeHash: material.presentationProof.challengeHash,
      }),
    }));
    await expect(verifyApplicationVp(input)).resolves.toMatchObject({ subjectDid: material.subjectDid });
    family.prepare = vi.fn(async () => ({
      ...material,
      presentationProof: signMidnightDIDPresentationProof({
        methodBinding: holderMethod,
        secretScalar: 23n,
        bodyRoot: material.presentationBodyRoot,
        createdAt: BigInt(NOW + 60_001),
        challengeHash: material.presentationProof.challengeHash,
      }),
    }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "invalid_presentation" });
  });

  it("rejects substituted credential signatures, roots, and future issuance timestamps", async () => {
    const { input, material, family } = await fixture();
    family.prepare = vi.fn(async () => ({
      ...material,
      credentialProof: {
        ...material.credentialProof,
        signature: { ...material.credentialProof.signature, s: material.credentialProof.signature.s + 1n },
      },
    }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "invalid_presentation" });
    family.prepare = vi.fn(async () => ({ ...material, credentialBodyRoot: bytes32("other-credential-body") }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "invalid_presentation" });
    family.prepare = vi.fn(async () => ({
      ...material,
      credentialProof: { ...material.credentialProof, createdAt: BigInt(NOW + 60_001) },
    }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "invalid_presentation" });
    expect(family.assertCredentialBodyBinding).not.toHaveBeenCalled();
  });

  it("rejects an invalid credential status reference before consulting live status", async () => {
    const { input, material, family } = await fixture();
    family.prepare = vi.fn(async () => ({
      ...material,
      statusBinding: { ...material.statusBinding, statusHandleCommitment: new Uint8Array(31) },
    }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "invalid_presentation" });
    expect(family.assertStatusActive).not.toHaveBeenCalled();
  });

  it("requires the trusted family to bind claims, status, holder, and expiry to the signed credential body", async () => {
    const { input, family } = await fixture();
    family.assertCredentialBodyBinding = vi.fn(async () => false as unknown as true);
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "invalid_presentation" });
    family.assertCredentialBodyBinding = vi.fn(async () => { throw new Error("private body witness mismatch"); });
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({
      category: "invalid_presentation",
      message: "Application VP invalid_presentation",
    });
    expect(family.assertIssuerEligible).not.toHaveBeenCalled();
  });

  it("caps attestation lifetime even when the credential and status are longer lived", async () => {
    const { input, material, family } = await fixture();
    family.prepare = vi.fn(async () => ({ ...material, credentialExpiresAtMs: NOW + 48 * 60 * 60_000 }));
    family.assertStatusActive = vi.fn(async () => ({ validUntilMs: NOW + 48 * 60 * 60_000 }));
    await expect(verifyApplicationVp(input)).resolves.toMatchObject({
      expiresAt: new Date(NOW + 24 * 60 * 60_000).toISOString(),
    });
  });

  it("distinguishes retryable resolver and status outages from semantic denials", async () => {
    const { input, family, material } = await fixture();
    await expect(verifyApplicationVp({
      ...input,
      resolver: { resolveResult: async () => { throw new Error("private resolver endpoint"); } },
    })).rejects.toMatchObject({ category: "unavailable", message: "Application VP unavailable" });
    family.prepare = vi.fn(async () => { throw new ApplicationVpDependencyUnavailableError(); });
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "unavailable" });
    family.prepare = vi.fn(async () => material);
    family.assertStatusActive = vi.fn(async () => { throw new ApplicationVpDependencyUnavailableError(); });
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({
      category: "unavailable",
      message: "Application VP unavailable",
    });
  });

  it("rejects a tampered proof or body root without exposing the circuit error", async () => {
    const { input, material, family } = await fixture();
    family.prepare = vi.fn(async () => ({
      ...material,
      presentationProof: {
        ...material.presentationProof,
        signature: { ...material.presentationProof.signature, s: material.presentationProof.signature.s + 1n },
      },
    }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "invalid_presentation" });
    family.prepare = vi.fn(async () => ({ ...material, presentationBodyRoot: bytes32("substituted-body") }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "invalid_presentation" });
    expect(family.assertIssuerEligible).not.toHaveBeenCalled();
  });

  it("rejects a substituted issuer DID, method key, or holder binding", async () => {
    const { input, material, family } = await fixture();
    family.prepare = vi.fn(async () => ({ ...material, issuerDid: createMidnightDid("other-issuer") }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "invalid_presentation" });

    family.prepare = vi.fn(async () => ({
      ...material,
      credentialProof: { ...material.credentialProof, publicKey: deriveJubjubPublicKey(31n) },
    }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "invalid_presentation" });

    family.prepare = vi.fn(async () => ({
      ...material,
      presentationHolderBinding: {
        holderVerificationMethodRef: material.credentialProof.signerVerificationMethodRef,
      },
    }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "invalid_presentation" });
    expect(family.assertIssuerEligible).not.toHaveBeenCalled();
  });

  it("fails closed on expired credential, stale presentation, status, or role claims", async () => {
    const { input, material, family } = await fixture();
    family.prepare = vi.fn(async () => ({ ...material, credentialExpiresAtMs: NOW - 1 }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "expired" });
    family.prepare = vi.fn(async () => ({ ...material, credentialExpiresAtMs: Number.NaN }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "invalid_presentation" });

    family.prepare = vi.fn(async () => material);
    await expect(verifyApplicationVp({ ...input, evaluatedAtMs: NOW + 6 * 60_000 })).rejects.toMatchObject({ category: "expired" });

    family.assertStatusActive = vi.fn(async () => ({ validUntilMs: NOW - 1 }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "expired" });
    expect(family.assertRoleClaims).not.toHaveBeenCalled();

    family.assertStatusActive = vi.fn(async () => ({ validUntilMs: NOW + 15 * 60_000 }));
    family.assertRoleClaims = vi.fn(async () => { throw new Error("private claim mismatch"); });
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "ineligible" });
  });

  it("redacts issuer and status adapter denials before returning any attestation", async () => {
    const { input, family } = await fixture();
    family.assertIssuerEligible = vi.fn(async () => false as unknown as true);
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({
      category: "ineligible",
      message: "Application VP ineligible",
    });
    expect(family.assertStatusActive).not.toHaveBeenCalled();

    family.assertIssuerEligible = vi.fn(async () => true as const);
    family.assertStatusActive = vi.fn(async () => { throw new Error("private status witness details"); });
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({
      category: "ineligible",
      message: "Application VP ineligible",
    });
    expect(family.assertRoleClaims).not.toHaveBeenCalled();
  });
});
