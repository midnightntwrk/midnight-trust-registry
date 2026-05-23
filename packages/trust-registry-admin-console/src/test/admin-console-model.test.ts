import { describe, expect, it } from "vitest";

import {
  buildReviewCards,
  describeMutation,
  getReviewActions,
  groupReviewCards,
  type ReviewBoard,
} from "../model.js";

import type {
  TrustRegistryAuthorizationSnapshotEntry,
  TrustRegistryRecognitionSnapshotEntry,
} from "@midnight-ntwrk/trust-registry-cli";

const authorizationEvidence = (): TrustRegistryAuthorizationSnapshotEntry["evidence"] =>
  ({
    bundleId: "bundle:authorization:test",
    generatedAt: "2026-05-23T04:00:00Z",
    registryId: "registry:kanon-admin",
    subjectDid: "did:midnight:testnet:subject",
    policy: {
      policyId: "policy:default",
      policyHash: "policy-hash",
      policyVersion: "1.0.0",
      status: "active",
      registryId: "registry:kanon-admin",
      registryDid: "did:midnight:testnet:registry",
      trustLevelScale: "default",
      eligibilityCriteriaHash: "eligibility-hash",
      approvedVcTypesHash: "approved-hash",
      allowedPresentationDefinitionsHash: "allowed-hash",
      createdAt: "2026-05-23T03:30:00Z",
      effectiveFrom: "2026-05-23T03:30:00Z",
    },
    epoch: {
      epochId: "epoch:002",
      registryId: "registry:kanon-admin",
      stateRoot: "state-root",
      eventRoot: "event-root",
      policyRoot: "policy-root",
      publishedAt: "2026-05-23T03:59:59Z",
      maintainerKeyId: "maintainer:key:1",
      maintainerDid: "did:midnight:testnet:maintainer",
      signatureAlgorithm: "midnight:jubjub-schnorr",
      signature: {
        publicNonce: { x: "0x01", y: "0x02" },
        scalar: "0x03",
      },
    },
    inclusionProof: {
      leafHash: "leaf-hash",
      path: [],
      root: "state-root",
    },
    authorization: undefined,
    recognition: undefined,
  } as unknown as TrustRegistryAuthorizationSnapshotEntry["evidence"]);

const recognitionEvidence = (): TrustRegistryRecognitionSnapshotEntry["evidence"] =>
  ({
    bundleId: "bundle:recognition:test",
    generatedAt: "2026-05-23T04:00:00Z",
    registryId: "registry:kanon-admin",
    subjectDid: "did:midnight:testnet:subject",
    policy: authorizationEvidence().policy,
    epoch: authorizationEvidence().epoch,
    inclusionProof: authorizationEvidence().inclusionProof,
    authorization: undefined,
    recognition: undefined,
  } as unknown as TrustRegistryRecognitionSnapshotEntry["evidence"]);

const board: ReviewBoard = {
  summary: {
    snapshotVersion: "1",
    generatedAt: "2026-05-23T04:00:00Z",
    registryLabel: "kanon-admin",
    registryId: "registry:kanon-admin",
    registryDid: "did:midnight:testnet:registry",
    policyId: "policy:default",
    currentEpochId: "epoch:002",
    epochCount: 2,
    issuerCounts: {
      proposed: 1,
      authorized: 0,
      active: 0,
      suspended: 0,
      revoked: 0,
      superseded: 0,
      archived: 0,
    },
    verifierCounts: {
      proposed: 0,
      authorized: 1,
      active: 0,
      suspended: 0,
      revoked: 0,
      superseded: 0,
      archived: 0,
    },
    recognitionCounts: {
      proposed: 0,
      authorized: 0,
      active: 0,
      suspended: 1,
      revoked: 0,
      superseded: 0,
      archived: 0,
    },
  },
  issuers: [
    {
      label: "degree",
      authorization: {
        authorizationId: "auth:issuer:degree:v1",
        registryId: "registry:kanon-admin",
        role: "issuer",
        subjectDid: "did:midnight:testnet:issuer",
        resourceType: "credential-family",
        resourceId: "degree-scope",
        policyId: "policy:default",
        trustLevel: "gold",
        status: "proposed",
        lifecycleEventRoot: "event-root",
        evidenceHash: "evidence-hash",
        proposedAt: "2026-05-23T03:59:00Z",
      },
      evidence: authorizationEvidence(),
    } as unknown as TrustRegistryAuthorizationSnapshotEntry,
  ],
  verifiers: [
    {
      label: "age-gate",
      authorization: {
        authorizationId: "auth:verifier:age-gate:v1",
        registryId: "registry:kanon-admin",
        role: "verifier",
        subjectDid: "did:midnight:testnet:verifier",
        resourceType: "request-profile",
        resourceId: "age-gate",
        policyId: "policy:default",
        trustLevel: "silver",
        status: "authorized",
        lifecycleEventRoot: "event-root",
        evidenceHash: "evidence-hash",
        proposedAt: "2026-05-23T03:54:00Z",
        authorizedAt: "2026-05-23T03:58:00Z",
      },
      evidence: authorizationEvidence(),
    } as unknown as TrustRegistryAuthorizationSnapshotEntry,
  ],
  recognitions: [
    {
      label: "gaia-x",
      recognition: {
        recognitionId: "recognition:gaia-x:v1",
        registryId: "registry:kanon-admin",
        recognizedAuthorityDid: "did:midnight:testnet:gaiax",
        recognizedRegistryId: "registry:gaiax",
        scope: {
          resourceType: "recognized-scope",
          resourceId: "gaia-x",
        },
        policyId: "policy:default",
        trustLevel: "observer",
        status: "suspended",
        lifecycleEventRoot: "event-root",
        evidenceHash: "evidence-hash",
        proposedAt: "2026-05-23T03:50:00Z",
        authorizedAt: "2026-05-23T03:55:00Z",
        effectiveFrom: "2026-05-23T03:56:00Z",
        suspendedAt: "2026-05-23T03:57:00Z",
      },
      evidence: recognitionEvidence(),
    } as unknown as TrustRegistryRecognitionSnapshotEntry,
  ],
};

describe("trust registry admin console model", () => {
  it("derives conservative maintainer actions from lifecycle state", () => {
    expect(getReviewActions("proposed")).toEqual(["approve", "archive"]);
    expect(getReviewActions("authorized")).toEqual(["activate", "revoke", "archive"]);
    expect(getReviewActions("suspended")).toEqual(["revoke", "archive"]);
    expect(getReviewActions("archived")).toEqual([]);
  });

  it("builds review cards and groups them by status", () => {
    const cards = buildReviewCards(board);
    expect(cards).toHaveLength(3);
    expect(cards[0]?.label).toBe("degree");

    const grouped = groupReviewCards(cards);
    expect(grouped.proposed).toHaveLength(1);
    expect(grouped.authorized).toHaveLength(1);
    expect(grouped.suspended).toHaveLength(1);
  });

  it("renders mutation outcomes into operator-facing flash text", () => {
    expect(describeMutation({
      sourceMode: "workspace",
      workspaceVersion: "1",
      workspaceUpdatedAt: "2026-05-23T04:00:00Z",
      snapshotGeneratedAt: "2026-05-23T04:00:00Z",
      currentEpochId: "epoch:002",
      operation: {
        operation: "approve",
        target: "issuer",
        id: "auth:issuer:degree:v1",
      },
      recordKind: "authorization",
      entry: board.issuers[0]!,
    })).toMatch(/approved degree/i);
  });
});
