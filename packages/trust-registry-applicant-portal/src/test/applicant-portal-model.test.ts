import { describe, expect, it } from "vitest";

import { TARGET_OPTIONS, describeSubmission, toInspectionCards, type PublicInspection } from "../model.js";

const inspection = {
  summary: {
    snapshotVersion: "1",
    generatedAt: "2026-05-23T05:00:00Z",
    registryLabel: "kanon-portal",
    registryId: "registry:kanon-portal",
    registryDid: "did:midnight:testnet:registry",
    policyId: "policy:default",
    currentEpochId: "epoch:003",
    epochCount: 3,
    issuerCounts: {
      proposed: 0,
      authorized: 0,
      active: 1,
      suspended: 0,
      revoked: 0,
      superseded: 0,
      archived: 0,
    },
    verifierCounts: {
      proposed: 0,
      authorized: 0,
      active: 1,
      suspended: 0,
      revoked: 0,
      superseded: 0,
      archived: 0,
    },
    recognitionCounts: {
      proposed: 0,
      authorized: 0,
      active: 1,
      suspended: 0,
      revoked: 0,
      superseded: 0,
      archived: 0,
    },
  },
  activeIssuers: [
    {
      label: "degree",
      authorization: {
        authorizationId: "auth:issuer:degree:v1",
        subjectDid: "did:midnight:testnet:issuer",
        resourceType: "credential-family",
        resourceId: "degree-scope",
        trustLevel: "gold",
        status: "active",
      },
    },
  ],
  activeVerifiers: [
    {
      label: "age-gate",
      authorization: {
        authorizationId: "auth:verifier:age-gate:v1",
        subjectDid: "did:midnight:testnet:verifier",
        resourceType: "request-profile",
        resourceId: "age-gate",
        trustLevel: "silver",
        status: "active",
      },
    },
  ],
  activeRecognitions: [
    {
      label: "gaia-x",
      recognition: {
        recognitionId: "recognition:gaia-x:v1",
        recognizedAuthorityDid: "did:midnight:testnet:gaiax",
        scope: {
          resourceType: "recognized-scope",
          resourceId: "gaia-x",
        },
        trustLevel: "observer",
        status: "active",
      },
    },
  ],
} as unknown as PublicInspection;

describe("trust registry applicant portal model", () => {
  it("offers all applicant target options", () => {
    expect(TARGET_OPTIONS.map((option) => option.value)).toEqual([
      "issuer",
      "verifier",
      "recognition",
    ]);
  });

  it("maps active trust records into public inspection cards", () => {
    const cards = toInspectionCards(inspection);
    expect(cards).toHaveLength(3);
    expect(cards[0]?.label).toBe("degree");
    expect(cards[2]?.target).toBe("recognition");
  });

  it("describes submission responses in user-facing language", () => {
    expect(describeSubmission({
      sourceMode: "workspace",
      workspaceVersion: "1",
      workspaceUpdatedAt: "2026-05-23T05:00:00Z",
      snapshotGeneratedAt: "2026-05-23T05:00:00Z",
      currentEpochId: "epoch:003",
      operation: {
        operation: "submit",
        target: "issuer",
        label: "degree",
      },
      recordKind: "authorization",
      entry: {
        label: "degree",
        authorization: {
          status: "proposed",
        },
      },
    } as never)).toMatch(/submitted degree/i);
  });
});
