import { Buffer } from "node:buffer";

import {
  resolveMidnightDIDMethodBinding,
  signMidnightDIDCredentialProof,
  signMidnightDIDPresentationProof,
} from "@midnight-ntwrk/credential-did-midnight";
import { parseMidnightDIDString } from "@midnight-ntwrk/midnight-did";
import { signJubjubDigest } from "@midnight-ntwrk/midnight-did-jubjub-schnorr";
import { encodeJubjubSignature } from "@midnight-ntwrk/trust-registry-contract";
import { canonicalizeJson, sha256Hex } from "@midnight-ntwrk/trust-registry-domain";
import { describe, expect, it, vi } from "vitest";

import { verifyQualifiedApplicationVp } from "../application-vp-verifier.js";
import { encodeApplicationVpProof } from "../application-vp-proof-json.js";
import { applicationStatusAttestationDigest, createAttestedApplicationStatusSource } from "../application-status-attestation.js";
import { createCanonicalApplicationVpFamilyAdapter } from "../canonical-application-vp-family.js";
import {
  createApplicationVpScenarioFixture,
  VP_FIXTURE_TRUST_CONTEXT,
} from "../vp-scenario-fixtures.js";

const root = (body: string): Uint8Array => Buffer.from(sha256Hex(body).slice(2), "hex");
const hex = (bytes: Uint8Array): string => `0x${Buffer.from(bytes).toString("hex")}`;

async function signedSubmission(credentialChanges: Record<string, unknown> = {}) {
  const fixture = await createApplicationVpScenarioFixture();
  const oldCredential = JSON.parse(fixture.input.submission.rawCredentialBody) as Record<string, unknown>;
  const credentialBody = canonicalizeJson({
    ...oldCredential,
    ...credentialChanges,
    version: "tr-application-vp-credential-v1",
  });
  const credentialBodyRoot = root(credentialBody);
  const oldPresentation = JSON.parse(fixture.input.submission.rawPresentationBody) as Record<string, unknown>;
  const rest = Object.fromEntries(Object.entries(oldPresentation)
    .filter(([key]) => key !== "privatePayload" && key !== "audience"));
  const presentationBody = canonicalizeJson({
    ...rest,
    version: "tr-application-vp-presentation-v1",
    credentialBodyRoot: hex(credentialBodyRoot),
    origin: oldPresentation.audience,
  });
  const issuerMethod = await resolveMidnightDIDMethodBinding({
    resolver: fixture.input.resolver,
    did: parseMidnightDIDString(fixture.material.issuerDid),
    verificationMethodId: fixture.material.issuerMethodId,
    relationship: "assertionMethod",
  });
  const credentialProof = signMidnightDIDCredentialProof({
    methodBinding: issuerMethod,
    secretScalar: 19n,
    bodyRoot: credentialBodyRoot,
    createdAt: fixture.material.credentialProof.createdAt,
    challengeHash: fixture.material.credentialProof.challengeHash,
  });
  const presentationProof = signMidnightDIDPresentationProof({
    methodBinding: fixture.subjectAuthentication.method,
    secretScalar: fixture.subjectAuthentication.secretScalar,
    bodyRoot: root(presentationBody),
    createdAt: fixture.material.presentationProof.createdAt,
    challengeHash: fixture.material.presentationProof.challengeHash,
  });
  const submission = {
    rawCredentialBody: credentialBody,
    rawPresentationBody: presentationBody,
    credentialProof: encodeApplicationVpProof(credentialProof),
    presentationProof: encodeApplicationVpProof(presentationProof),
  };
  const issuerEligibility = vi.fn(async () => fixture.fixtureStatusPolicyBinding);
  const statusStatement = {
    ...fixture.signedStatusAttestation.statement,
    credentialBodyRoot: hex(credentialBodyRoot),
  };
  const statusSource = vi.fn(createAttestedApplicationStatusSource({
    resolver: fixture.input.resolver,
    fetchAttestation: async () => ({
      statement: statusStatement,
      proof: {
        ...fixture.signedStatusAttestation.proof,
        signature: hex(encodeJubjubSignature(signJubjubDigest(
          19n, applicationStatusAttestationDigest(statusStatement),
        ))),
      },
    }),
  }));
  const family = createCanonicalApplicationVpFamilyAdapter({
    resolver: fixture.input.resolver,
    issuerEligibility,
    statusSource,
  });
  const input = {
    ...fixture.input,
    submission,
    family,
    trustContext: VP_FIXTURE_TRUST_CONTEXT,
    expectedPolicyId: "policy:vp:v1",
    expectedPolicyVersion: "v1",
  };
  return { input, issuerEligibility, statusSource };
}

describe("canonical application VP family", () => {
  it("verifies published VC proofs over exact canonical bodies and host trust context", async () => {
    const { input, issuerEligibility, statusSource } = await signedSubmission();
    await expect(verifyQualifiedApplicationVp(input)).resolves.toMatchObject({
      subjectDid: input.expectedSubjectDid,
      nonce: input.nonce,
    });
    expect(issuerEligibility).toHaveBeenCalledOnce();
    expect(statusSource).toHaveBeenCalledOnce();
    await expect(verifyQualifiedApplicationVp({
      ...input,
      trustContext: { ...input.trustContext, contractAddress: `0x${"f".repeat(64)}` },
    })).rejects.toMatchObject({ category: "invalid_presentation" });
  });

  it("rejects changed credential linkage before issuer eligibility", async () => {
    const { input, issuerEligibility } = await signedSubmission();
    const presentation = JSON.parse(input.submission.rawPresentationBody) as Record<string, unknown>;
    const submission = { ...input.submission, rawPresentationBody: canonicalizeJson({
      ...presentation, credentialBodyRoot: `0x${"f".repeat(64)}`,
    }) };
    await expect(verifyQualifiedApplicationVp({ ...input, submission }))
      .rejects.toMatchObject({ category: "invalid_presentation" });
    expect(issuerEligibility).not.toHaveBeenCalled();
  });

  it("fails closed when the host has no governed issuer grant", async () => {
    const { input, issuerEligibility, statusSource } = await signedSubmission();
    issuerEligibility.mockRejectedValueOnce(new Error("No finalized issuer grant"));
    await expect(verifyQualifiedApplicationVp(input)).rejects.toMatchObject({ category: "ineligible" });
    expect(statusSource).not.toHaveBeenCalled();
  });

  it("rejects a signed credential scope that differs from the requested role", async () => {
    const baseline = await createApplicationVpScenarioFixture();
    const { input, issuerEligibility, statusSource } = await signedSubmission({
      scope: { ...baseline.input.scope, schemaId: "schema:substituted" },
    });
    await expect(verifyQualifiedApplicationVp(input)).rejects.toMatchObject({ category: "ineligible" });
    expect(issuerEligibility).toHaveBeenCalledOnce();
    expect(statusSource).toHaveBeenCalledOnce();
  });

  it("rejects noncanonical, unknown-field, and fixture-only bodies", async () => {
    const { input, issuerEligibility } = await signedSubmission();
    const credential = JSON.parse(input.submission.rawCredentialBody) as Record<string, unknown>;
    for (const rawCredentialBody of [
      JSON.stringify(credential, null, 2),
      canonicalizeJson({ ...credential, extra: true }),
      canonicalizeJson({ ...credential, version: "tr-vp-fixture-v1" }),
    ]) {
      await expect(verifyQualifiedApplicationVp({ ...input, submission: {
        ...input.submission, rawCredentialBody,
      } })).rejects.toMatchObject({ category: "invalid_presentation" });
    }
    expect(issuerEligibility).not.toHaveBeenCalled();
  });
});
