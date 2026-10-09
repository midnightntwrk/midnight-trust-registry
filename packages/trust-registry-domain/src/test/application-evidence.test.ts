import { describe, expect, it } from "vitest";

import {
  assertValidApplicationEvidence,
  computeApplicationEvidenceCommitment,
  issuerGovernedResourceIdFromScopeCommitment,
  requestGovernedResourceIdFromScopeCommitment,
  type ApplicationEvidenceSubmission,
} from "../index.js";

const HASH_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HASH_C = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const HASH_D = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const ISSUER_RESOURCE_ID = issuerGovernedResourceIdFromScopeCommitment(HASH_A, "credentialFamily");

const createSubmission = (): ApplicationEvidenceSubmission => {
  const envelope = {
    version: "tr-application-evidence-v1" as const,
    registryId: "registry:midnight:kanon",
    applicationId: "application:issuer:acme:v1",
    subjectDid: "did:midnight:issuer:acme",
    role: "issuer" as const,
    policyId: "policy:kanon:v1",
    policyVersion: "v1",
    scopeCommitment: HASH_A,
    governedResource: { type: "credentialFamily" as const, id: ISSUER_RESOURCE_ID },
    evidenceVerifierDid: "did:midnight:evidence-verifier:one",
    verifiedAt: "2026-07-27T00:00:00Z",
    expiresAt: "2026-07-28T00:00:00Z",
    challengeHash: HASH_B,
    presentationHash: HASH_C,
    claimsCommitment: HASH_D,
  };
  return {
    envelope,
    commitment: computeApplicationEvidenceCommitment(envelope),
    signature: {
      keyId: "did:midnight:evidence-verifier:one#assertion-1",
      algorithm: "jubjub-schnorr",
      value: "simulated-valid-signature",
    },
  };
};

const expectation = {
  registryId: "registry:midnight:kanon",
  applicationId: "application:issuer:acme:v1",
  subjectDid: "did:midnight:issuer:acme",
  role: "issuer" as const,
  policyId: "policy:kanon:v1",
  policyVersion: "v1",
  scopeCommitment: HASH_A,
  governedResource: { type: "credentialFamily" as const, id: ISSUER_RESOURCE_ID },
  challengeHash: HASH_B,
  evaluatedAt: "2026-07-27T12:00:00Z",
};

const authorizedVerifier = {
  did: "did:midnight:evidence-verifier:one",
  keyIds: ["did:midnight:evidence-verifier:one#assertion-1"],
  algorithms: ["jubjub-schnorr" as const],
};

describe("application evidence", () => {
  it("rejects bare issuer resource IDs before signing an envelope", () => {
    const envelope = createSubmission().envelope;
    expect(() => computeApplicationEvidenceCommitment({
      ...envelope,
      governedResource: { type: "schemaVersion", id: "1.0.0" },
    })).toThrow(/canonical composite issuer resource id/);
  });

  it("rejects a valid issuer id paired with another scope or resource type", () => {
    const envelope = createSubmission().envelope;
    expect(() => computeApplicationEvidenceCommitment({
      ...envelope,
      scopeCommitment: HASH_B,
    })).toThrow(/Issuer resource id does not match/);
    expect(() => computeApplicationEvidenceCommitment({
      ...envelope,
      governedResource: { type: "schemaVersion", id: ISSUER_RESOURCE_ID },
    })).toThrow(/Issuer resource id does not match/);
  });

  it("rejects a signed envelope longer than the 24-hour reference policy", () => {
    const submission = createSubmission();
    submission.envelope.expiresAt = "2026-07-28T00:00:00.001Z";
    submission.commitment = computeApplicationEvidenceCommitment(submission.envelope);
    expect(submission.commitment).toMatch(/^0x[0-9a-f]{64}$/);
    expect(() => assertValidApplicationEvidence(
      submission, expectation, [authorizedVerifier], () => true,
    )).toThrow(/maximum 24-hour lifetime/);
  });

  it.each(["verifier", "auditor"] as const)("binds %s request evidence to its complete signed scope", (role) => {
    const issuerEnvelope = createSubmission().envelope;
    const resourceId = requestGovernedResourceIdFromScopeCommitment(HASH_A);
    const envelope = {
      ...issuerEnvelope,
      role,
      governedResource: { type: "requestProfile" as const, id: resourceId },
    };
    expect(() => computeApplicationEvidenceCommitment(envelope)).not.toThrow();
    expect(() => computeApplicationEvidenceCommitment({
      ...envelope,
      scopeCommitment: HASH_B,
    })).toThrow(/Request resource id does not match/);
    expect(() => computeApplicationEvidenceCommitment({
      ...envelope,
      governedResource: { type: "requestProfile", id: "request-profile:admission" },
    })).toThrow(/canonical composite request resource id/);
  });

  it("binds a valid application envelope to its governed authorization", () => {
    expect(() =>
      assertValidApplicationEvidence(
        createSubmission(),
        expectation,
        [authorizedVerifier],
        () => true,
      ),
    ).not.toThrow();
  });

  it("compares hash fields by bytes without changing the signed envelope", () => {
    const submission = createSubmission();
    submission.envelope.scopeCommitment = HASH_A.toUpperCase().replace("0X", "0x");
    submission.envelope.challengeHash = HASH_B.toUpperCase().replace("0X", "0x");
    submission.commitment = computeApplicationEvidenceCommitment(submission.envelope);
    expect(() => assertValidApplicationEvidence(submission, expectation, [authorizedVerifier], () => true)).not.toThrow();
  });

  it("rejects invalid expected hash values as domain errors", () => {
    expect(() => assertValidApplicationEvidence(
      createSubmission(),
      { ...expectation, challengeHash: undefined as unknown as string },
      [authorizedVerifier],
      () => true,
    )).toThrow(/expected challengeHash is invalid/);
    expect(() => assertValidApplicationEvidence(
      createSubmission(),
      { ...expectation, scopeCommitment: "not-a-hash" },
      [authorizedVerifier],
      () => true,
    )).toThrow(/expected scopeCommitment is invalid/);
  });

  it.each([
    ["wrong application", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, applicationId: "application:issuer:other:v1" } }), /applicationId/],
    ["wrong subject", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, subjectDid: "did:midnight:issuer:other" } }), /subjectDid/],
    ["wrong role", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, role: "verifier" as const } }), /role/],
    ["wrong policy", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, policyId: "policy:kanon:v2" } }), /policyId/],
    ["wrong scope", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, scopeCommitment: HASH_B } }), /Issuer resource id does not match/],
    ["wrong resource type", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, governedResource: { type: "schemaVersion" as const, id: ISSUER_RESOURCE_ID } } }), /Issuer resource id does not match/],
    ["wrong resource id", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, governedResource: { type: "credentialFamily" as const, id: `tr:issuer-resource:v1:${"b".repeat(64)}` } } }), /Issuer resource id does not match/],
    ["wrong challenge", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, challengeHash: HASH_C } }), /challengeHash/],
  ])("rejects %s", (_name, mutate, expectedError) => {
    const submission = mutate(createSubmission());
    expect(() =>
      assertValidApplicationEvidence(
        { ...submission, commitment: computeApplicationEvidenceCommitment(submission.envelope) },
        expectation,
        [authorizedVerifier],
        () => true,
      ),
    ).toThrow(expectedError);
  });

  it("rejects expired, unauthorized, and invalidly signed evidence", () => {
    const mismatchedCommitment = createSubmission();
    mismatchedCommitment.envelope.presentationHash = HASH_A;
    expect(() =>
      assertValidApplicationEvidence(mismatchedCommitment, expectation, [authorizedVerifier], () => true),
    ).toThrow(/commitment does not match/);

    expect(() =>
      assertValidApplicationEvidence(createSubmission(), { ...expectation, evaluatedAt: "not-a-date" }, [authorizedVerifier], () => true),
    ).toThrow(/evaluation time is invalid/);

    const expired = createSubmission();
    expired.envelope.expiresAt = "2026-07-27T12:00:00Z";
    expired.commitment = computeApplicationEvidenceCommitment(expired.envelope);
    expect(() =>
      assertValidApplicationEvidence(expired, expectation, [authorizedVerifier], () => true),
    ).toThrow(/expired/);

    const future = createSubmission();
    future.envelope.verifiedAt = "2026-07-27T13:00:00Z";
    future.commitment = computeApplicationEvidenceCommitment(future.envelope);
    expect(() =>
      assertValidApplicationEvidence(future, expectation, [authorizedVerifier], () => true),
    ).toThrow(/not yet valid/);

    expect(() =>
      assertValidApplicationEvidence(createSubmission(), expectation, [], () => true),
    ).toThrow(/not authorized/);
    expect(() =>
      assertValidApplicationEvidence(createSubmission(), expectation, [authorizedVerifier], () => false),
    ).toThrow(/signature is invalid/);
  });
});
