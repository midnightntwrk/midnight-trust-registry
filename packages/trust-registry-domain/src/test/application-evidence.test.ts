import { describe, expect, it } from "vitest";

import {
  assertValidApplicationEvidence,
  computeApplicationEvidenceCommitment,
  type ApplicationEvidenceSubmission,
} from "../index.js";

const HASH_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HASH_C = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const HASH_D = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

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
  challengeHash: HASH_B,
  evaluatedAt: "2026-07-27T12:00:00Z",
};

const authorizedVerifier = {
  did: "did:midnight:evidence-verifier:one",
  keyIds: ["did:midnight:evidence-verifier:one#assertion-1"],
  algorithms: ["jubjub-schnorr" as const],
};

describe("application evidence", () => {
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

  it.each([
    ["wrong application", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, applicationId: "application:issuer:other:v1" } }), /applicationId/],
    ["wrong subject", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, subjectDid: "did:midnight:issuer:other" } }), /subjectDid/],
    ["wrong role", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, role: "verifier" as const } }), /role/],
    ["wrong policy", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, policyId: "policy:kanon:v2" } }), /policyId/],
    ["wrong scope", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, scopeCommitment: HASH_B } }), /scopeCommitment/],
    ["wrong challenge", (submission: ApplicationEvidenceSubmission) => ({ ...submission, envelope: { ...submission.envelope, challengeHash: HASH_C } }), /challengeHash/],
  ])("rejects %s", (_name, mutate, expectedError) => {
    const submission = mutate(createSubmission());
    submission.commitment = computeApplicationEvidenceCommitment(submission.envelope);
    expect(() =>
      assertValidApplicationEvidence(submission, expectation, [authorizedVerifier], () => true),
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
