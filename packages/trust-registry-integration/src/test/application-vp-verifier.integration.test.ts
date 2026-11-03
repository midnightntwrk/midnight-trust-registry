import { Buffer } from "node:buffer";

import {
  resolveMidnightDIDMethodBinding,
  signMidnightDIDPresentationProof,
} from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import {
  deriveJubjubPublicKey,
  deriveJubjubPublicKeyFromSeed,
  signApplicationEvidenceCommitmentFromSeed,
} from "@midnight-ntwrk/trust-registry-contract";
import { ApplicationChallengeBindingSchema, computeAuthorizationScopeCommitment, issuerGovernedResourceId, sha256Hex } from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it, vi } from "vitest";

import {
  ApplicationVpDependencyUnavailableError,
  createApplicationVpIntakeVerifier,
  verifyApplicationVp,
} from "../application-vp-verifier.js";
import { verifyApplicationStatusDecisionWitness } from "../application-status-attestation.js";
import { decodeApplicationVpProof, encodeApplicationVpProof } from "../application-vp-proof-json.js";
import { createMidnightDidLedgerFixture, createMidnightDidResolver } from "../did-resolution.js";
import { createMidnightDid } from "../fixtures.js";
import { createApplicationVpIntakePorts } from "../vp-evidence-attestation.js";
import { createApplicationVpScenarioFixture, VP_FIXTURE_NONCE, VP_FIXTURE_TIME_MS } from "../vp-scenario-fixtures.js";

const NOW = VP_FIXTURE_TIME_MS;
const NONCE = VP_FIXTURE_NONCE;
const bytes32 = (value: string): Uint8Array => Buffer.from(sha256Hex(value).slice(2), "hex");

async function fixture() {
  const scenario = await createApplicationVpScenarioFixture();
  if (scenario.input.scope.role !== "issuer") throw new Error("Expected issuer VP scenario");
  const family = {
    prepare: vi.fn(scenario.family.prepare),
    assertCredentialBodyBinding: vi.fn(scenario.family.assertCredentialBodyBinding),
    assertIssuerEligible: vi.fn(scenario.family.assertIssuerEligible),
    assertStatusActive: vi.fn(scenario.family.assertStatusActive),
    assertRoleClaims: vi.fn(scenario.family.assertRoleClaims),
  };
  return {
    input: { ...scenario.input, scope: scenario.input.scope, family },
    material: scenario.material,
    issuerBinding: scenario.fixtureStatusPolicyBinding,
    family,
  };
}

describe("published VC proof and DID application verifier port", () => {
  it("retains the exact private status witness used to create redacted VP evidence", async () => {
    const scenario = await createApplicationVpScenarioFixture();
    const result = await verifyApplicationVp(scenario.input);
    const challengeHash = sha256Hex(Buffer.from(scenario.input.nonce.slice(2), "hex"));
    const signed = scenario.readStatusWitness(challengeHash);
    expect(signed).not.toBeNull();
    expect(scenario.readStatusWitness(sha256Hex("other-challenge"))).toBeNull();
    await expect(verifyApplicationStatusDecisionWitness({
      signed,
      expectedCommitment: result.statusDecisionCommitment,
      material: scenario.material,
      binding: scenario.fixtureStatusPolicyBinding,
      nonce: scenario.input.nonce,
      evaluatedAtMs: scenario.input.evaluatedAtMs,
      resolver: scenario.input.resolver,
    })).resolves.toBe(true);
  });

  it("uses distinct authentication and assertion methods on the same applicant DID", async () => {
    const scenario = await createApplicationVpScenarioFixture();
    const did = parseMidnightDIDString(scenario.input.expectedSubjectDid);
    const holderMethod = await resolveMidnightDIDMethodBinding({
      resolver: scenario.input.resolver,
      did,
      verificationMethodId: "#auth-1",
      relationship: "authentication",
    });
    expect(scenario.subjectAssertion.method.verificationMethodRef).not.toEqual(
      holderMethod.verificationMethodRef,
    );
    const assertionMethod = await resolveMidnightDIDMethodBinding({
      resolver: scenario.input.resolver,
      did,
      verificationMethodId: "#assertion-1",
      relationship: "assertionMethod",
    });
    expect(scenario.subjectAssertion.method).toEqual(assertionMethod);
    await expect(resolveMidnightDIDMethodBinding({
      resolver: scenario.input.resolver,
      did,
      verificationMethodId: "#auth-1",
      relationship: "assertionMethod",
    })).rejects.toThrow(/not authorized/u);
    await expect(resolveMidnightDIDMethodBinding({
      resolver: scenario.input.resolver,
      did,
      verificationMethodId: "#assertion-1",
      relationship: "authentication",
    })).rejects.toThrow(/not authorized/u);
    await expect(verifyApplicationVp(scenario.input)).resolves.toMatchObject({ subjectDid: did });
  });

  it("round-trips submitted proof JSON without losing cryptographic fields", async () => {
    const { input, material } = await fixture();
    const submitted = structuredClone(input.submission);
    expect(decodeApplicationVpProof(submitted.credentialProof)).toEqual(material.credentialProof);
    expect(decodeApplicationVpProof(submitted.presentationProof)).toEqual(material.presentationProof);
    expect(encodeApplicationVpProof(decodeApplicationVpProof(submitted.credentialProof))).toEqual(submitted.credentialProof);
  });

  it("rejects substituted submitted bodies and proof signatures before eligibility checks", async () => {
    const { input, family } = await fixture();
    const changedCredential = structuredClone(input.submission);
    changedCredential.rawCredentialBody = "substituted-credential-body";
    await expect(verifyApplicationVp({ ...input, submission: changedCredential })).rejects.toMatchObject({
      category: "invalid_presentation",
    });
    const changedPresentation = structuredClone(input.submission);
    changedPresentation.rawPresentationBody = "substituted-presentation-body";
    await expect(verifyApplicationVp({ ...input, submission: changedPresentation })).rejects.toMatchObject({
      category: "invalid_presentation",
    });
    const changedProof = structuredClone(input.submission);
    const credentialProof = changedProof.credentialProof as Record<string, unknown>;
    const signature = credentialProof.signature as Record<string, unknown>;
    signature.s = (BigInt(signature.s as string) + 1n).toString();
    await expect(verifyApplicationVp({ ...input, submission: changedProof })).rejects.toMatchObject({
      category: "invalid_presentation",
    });
    expect(family.assertIssuerEligible).not.toHaveBeenCalled();
  });

  it("rejects a validly signed credential whose role scope differs from the application", async () => {
    const { input } = await fixture();
    const otherScope = { ...input.scope, credentialFamilyId: "credential-family:other" };
    const signedOtherScope = await createApplicationVpScenarioFixture(input.nonce, { scope: otherScope });
    const assertStatusActive = vi.fn(signedOtherScope.family.assertStatusActive);
    await expect(verifyApplicationVp({
      ...signedOtherScope.input,
      scope: input.scope,
      family: { ...signedOtherScope.family, assertStatusActive },
    })).rejects.toMatchObject({ category: "ineligible" });
    expect(assertStatusActive).toHaveBeenCalledOnce();
  });

  it("rejects a validly signed presentation that names a different credential body root", async () => {
    const scenario = await createApplicationVpScenarioFixture(NONCE, {
      presentationCredentialBodyRoot: sha256Hex("another-credential-body"),
    });
    const family = {
      ...scenario.family,
      assertCredentialBodyBinding: vi.fn(scenario.family.assertCredentialBodyBinding),
      assertIssuerEligible: vi.fn(scenario.family.assertIssuerEligible),
    };
    await expect(verifyApplicationVp({ ...scenario.input, family })).rejects.toMatchObject({
      category: "invalid_presentation",
    });
    expect(family.assertCredentialBodyBinding).toHaveBeenCalledOnce();
    expect(family.assertIssuerEligible).not.toHaveBeenCalled();
  });

  it("fails closed on malformed submitted proof JSON", async () => {
    const { input, family } = await fixture();
    const missingProof = structuredClone(input.submission);
    delete (missingProof as Partial<typeof missingProof>).presentationProof;
    await expect(verifyApplicationVp({ ...input, submission: missingProof })).rejects.toMatchObject({
      category: "invalid_presentation",
    });
    const extraField = structuredClone(input.submission);
    Object.assign(extraField.credentialProof, { unexpected: true });
    await expect(verifyApplicationVp({ ...input, submission: extraField })).rejects.toMatchObject({
      category: "invalid_presentation",
    });
    const nonCanonical = structuredClone(input.submission);
    Object.assign(nonCanonical.presentationProof, { createdAt: "01" });
    await expect(verifyApplicationVp({ ...input, submission: nonCanonical })).rejects.toMatchObject({
      category: "invalid_presentation",
    });
    expect(family.assertIssuerEligible).not.toHaveBeenCalled();
  });

  it("provides redacted VP and DID-bound signing ports for one-use intake", async () => {
    const { input } = await fixture();
    const verifierDid = createMidnightDid("vp-evidence-verifier");
    const seed = new Uint8Array(32).fill(41);
    const signer = {
      did: verifierDid,
      keyId: `${verifierDid}#assertion-1`,
      publicKey: deriveJubjubPublicKeyFromSeed(seed),
      signCommitment: (keyId: Uint8Array, commitment: Uint8Array) =>
        signApplicationEvidenceCommitmentFromSeed(seed, keyId, commitment),
    };
    const binding = ApplicationChallengeBindingSchema.parse({
      registryId: "registry:vp:test",
      applicationId: "application:vp:signed",
      subjectDid: input.expectedSubjectDid,
      evidenceVerifierDid: verifierDid,
      role: "issuer",
      policyId: "policy:vp:v1",
      policyVersion: "v1",
      scope: input.scope,
      scopeCommitment: computeAuthorizationScopeCommitment(input.scope),
      governedResource: { type: "credentialFamily", id: issuerGovernedResourceId(input.scope, "credentialFamily") },
    });
    const ports = await createApplicationVpIntakePorts({
      resolver: input.resolver, family: input.family, signer,
    });
    const context = { nonce: NONCE, binding, evaluatedAt: new Date(NOW).toISOString() };
    const verified = await ports.verifyPresentation(input.submission, context);
    expect(verified.subjectDid).toBe(input.expectedSubjectDid);
    expect(verified.expiresAt).toBe(new Date(NOW + 5 * 60_000).toISOString());
    expect(JSON.stringify(verified)).not.toContain("private-presentation-payload");
    const commitment = sha256Hex("application-evidence-test");
    const signature = await ports.signEvidence(commitment);
    const authorized = { did: signer.did, keyIds: [signer.keyId], algorithms: ["jubjub-schnorr" as const] };
    expect(ports.verifyEvidenceSignature(commitment, signature, authorized)).toBe(true);
    expect(ports.verifyEvidenceSignature(sha256Hex("different"), signature, authorized)).toBe(false);
    expect(ports.verifyEvidenceSignature(commitment, { ...signature, keyId: `${signer.did}#other` }, authorized)).toBe(false);
    expect(ports.verifyEvidenceSignature(commitment, signature, { ...authorized, keyIds: [] })).toBe(false);
    expect(JSON.stringify(signature)).not.toContain("private-presentation-payload");

    await expect(createApplicationVpIntakePorts({
      resolver: input.resolver,
      family: input.family,
      signer: { ...signer, did: createMidnightDid("wrong-verifier") },
    })).rejects.toThrow();
    await expect(createApplicationVpIntakePorts({
      resolver: input.resolver,
      family: input.family,
      signer: { ...signer, publicKey: deriveJubjubPublicKey(31n) },
    })).rejects.toThrow(/does not match its DID assertion method/u);
    await expect(ports.verifyPresentation(input.submission, {
      ...context, nonce: `0x${"22".repeat(32)}`,
    })).rejects.toMatchObject({ category: "invalid_presentation" });
    const invalidPorts = await createApplicationVpIntakePorts({
      resolver: input.resolver,
      family: input.family,
      signer: {
        ...signer,
        signCommitment: (keyId: Uint8Array) =>
          signApplicationEvidenceCommitmentFromSeed(seed, keyId, new Uint8Array(32).fill(7)),
      },
    });
    await expect(invalidPorts.signEvidence(commitment)).rejects.toThrow(/invalid signature/u);
  });

  it("rejects evidence signing when the DID assertion method rotates after port creation", async () => {
    const { input } = await fixture();
    const signerDid = createMidnightDid("vp-evidence-verifier");
    const seed = new Uint8Array(32).fill(41);
    const signer = {
      did: signerDid,
      keyId: `${signerDid}#assertion-1`,
      publicKey: deriveJubjubPublicKeyFromSeed(seed),
      signCommitment: (keyId: Uint8Array, commitment: Uint8Array) =>
        signApplicationEvidenceCommitmentFromSeed(seed, keyId, commitment),
    };
    const ports = await createApplicationVpIntakePorts({
      resolver: input.resolver, family: input.family, signer,
    });
    const rotated = createMidnightDidResolver([
      createMidnightDidLedgerFixture(signerDid, {
        verificationMethodId: "assertion-1",
        schnorrJubjubPublicKey: deriveJubjubPublicKey(31n),
      }),
    ]);
    vi.spyOn(input.resolver, "resolveResult").mockImplementation((did) => rotated.resolveResult(did));
    await expect(ports.signEvidence(sha256Hex("after-rotation"))).rejects.toThrow(
      /does not match its DID assertion method/u,
    );
  });

  it("binds VP evidence to the selected assertion key when the DID has two methods", async () => {
    const { input } = await fixture();
    const did = createMidnightDid("vp-evidence-verifier");
    const firstSeed = new Uint8Array(32).fill(41);
    const secondSeed = new Uint8Array(32).fill(42);
    const first = { id: "assertion-1", publicKey: deriveJubjubPublicKeyFromSeed(firstSeed) };
    const second = { id: "assertion-2", publicKey: deriveJubjubPublicKeyFromSeed(secondSeed) };
    const resolver = createMidnightDidResolver([
      createMidnightDidLedgerFixture(did, { schnorrJubjubAssertionMethods: [first, second] }),
    ]);
    const signer = {
      did,
      keyId: `${did}#assertion-2`,
      publicKey: second.publicKey,
      signCommitment: (keyId: Uint8Array, commitment: Uint8Array) =>
        signApplicationEvidenceCommitmentFromSeed(secondSeed, keyId, commitment),
    };
    const ports = await createApplicationVpIntakePorts({ resolver, family: input.family, signer });
    const commitment = sha256Hex("selected-assertion-method");
    const signature = await ports.signEvidence(commitment);
    expect(ports.verifyEvidenceSignature(commitment, signature, {
      did, keyIds: [signer.keyId], algorithms: ["jubjub-schnorr"],
    })).toBe(true);
    expect(ports.verifyEvidenceSignature(commitment, signature, {
      did, keyIds: [`${did}#assertion-1`], algorithms: ["jubjub-schnorr"],
    })).toBe(false);
    expect(ports.verifyEvidenceSignature(commitment, {
      ...signature, keyId: `${did}#assertion-1`,
    }, { did, keyIds: [signer.keyId], algorithms: ["jubjub-schnorr"] })).toBe(false);

    const retired = createMidnightDidResolver([
      createMidnightDidLedgerFixture(did, { schnorrJubjubAssertionMethods: [first], version: 2n }),
    ]);
    vi.spyOn(resolver, "resolveResult").mockImplementation((resolvedDid) => retired.resolveResult(resolvedDid));
    await expect(ports.signEvidence(commitment)).rejects.toThrow(/Verification method is absent/u);
  });

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
    expect(verified.expiresAt).toBe(new Date(NOW + 5 * 60_000).toISOString());
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

  it.each([
    ["revoked", { active: false }],
    ["wrong registry", { registryId: sha256Hex("another-status-registry") }],
    ["wrong status authority", { authorityMethod: `${createMidnightDid("other-issuer")}#assertion-1` }],
    ["wrong status handle", { statusHandleCommitment: sha256Hex("another-status-handle") }],
  ])("rejects a %s test-family status decision bound to the signed credential", async (_label, statusDecision) => {
    const scenario = await createApplicationVpScenarioFixture(NONCE, { statusDecision });
    await expect(verifyApplicationVp(scenario.input)).rejects.toMatchObject({ category: "ineligible" });
  });

  it("rejects a stale test-family status decision without extending evidence lifetime", async () => {
    const scenario = await createApplicationVpScenarioFixture(NONCE, {
      statusDecision: { validUntilMs: NOW - 1 },
    });
    await expect(verifyApplicationVp(scenario.input)).rejects.toMatchObject({ category: "expired" });
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
    family.assertCredentialBodyBinding = vi.fn(async () => true as const);
    family.assertStatusActive = vi.fn(async () => ({
      validUntilMs: NOW + 48 * 60 * 60_000,
      statusDecisionCommitment: sha256Hex("test-status-long-lived"),
    }));
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

    family.assertStatusActive = vi.fn(async () => ({
      validUntilMs: NOW - 1,
      statusDecisionCommitment: sha256Hex("test-status-expired"),
    }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "expired" });
    expect(family.assertRoleClaims).not.toHaveBeenCalled();

    family.assertStatusActive = vi.fn(async () => ({
      validUntilMs: NOW + 15 * 60_000,
      statusDecisionCommitment: sha256Hex("test-status-claims"),
    }));
    family.assertRoleClaims = vi.fn(async () => { throw new Error("private claim mismatch"); });
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "ineligible" });
  });

  it("redacts issuer and status adapter denials before returning any attestation", async () => {
    const { input, family, issuerBinding } = await fixture();
    family.assertIssuerEligible = vi.fn(async () => false as unknown as typeof issuerBinding);
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({
      category: "ineligible",
      message: "Application VP ineligible",
    });
    expect(family.assertStatusActive).not.toHaveBeenCalled();

    family.assertIssuerEligible = vi.fn(async () => issuerBinding);
    family.assertStatusActive = vi.fn(async () => { throw new Error("private status witness details"); });
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({
      category: "ineligible",
      message: "Application VP ineligible",
    });
    expect(family.assertRoleClaims).not.toHaveBeenCalled();
  });

  it("passes only the eligible issuer's governed status binding and challenge context to status verification", async () => {
    const { input, family, issuerBinding } = await fixture();
    await verifyApplicationVp(input);
    expect(family.assertStatusActive).toHaveBeenCalledWith(
      expect.any(Object), issuerBinding, { nonce: NONCE, evaluatedAtMs: NOW },
    );

    family.assertStatusActive.mockClear();
    family.assertIssuerEligible = vi.fn(async () => ({
      ...issuerBinding,
      statusRegistryId: sha256Hex("substituted-governed-registry"),
    }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "ineligible" });
    expect(family.assertStatusActive).not.toHaveBeenCalled();
  });

  it("rejects missing or malformed status-decision commitments before issuing evidence", async () => {
    const { input, family } = await fixture();
    family.assertStatusActive = vi.fn(async () => ({
      validUntilMs: NOW + 60_000,
      statusDecisionCommitment: undefined as unknown as string,
    }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "ineligible" });
    expect(family.assertRoleClaims).not.toHaveBeenCalled();
    family.assertStatusActive = vi.fn(async () => ({
      validUntilMs: NOW + 60_000,
      statusDecisionCommitment: "not-a-commitment",
    }));
    await expect(verifyApplicationVp(input)).rejects.toMatchObject({ category: "ineligible" });
  });
});
