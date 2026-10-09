import { describe, expect, it, vi } from "vitest";

import { TrustRegistryAdminConsoleClient } from "../api.js";
import {
  buildReviewCards,
  describeActionConfirmation,
  describeMutation,
  executeEpochPublication,
  executeReviewAction,
  getReviewActions,
  groupReviewCards,
  type ReviewBoard,
  type ReviewBoardMutation,
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
    auditorCounts: {
      proposed: 0,
      authorized: 0,
      active: 1,
      suspended: 0,
      revoked: 0,
      superseded: 0,
      archived: 1,
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
        resourceId: `tr:request-resource:v1:${"c".repeat(64)}`,
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
  auditors: [
    {
      label: "compliance",
      authorization: {
        authorizationId: "auth:auditor:compliance:v1",
        registryId: "registry:kanon-admin",
        role: "auditor",
        subjectDid: "did:midnight:testnet:auditor",
        resourceType: "request-profile",
        resourceId: `tr:request-resource:v1:${"a".repeat(64)}`,
        policyId: "policy:default",
        trustLevel: "audit-approved",
        status: "active",
        lifecycleEventRoot: "event-root",
        evidenceHash: "evidence-hash",
        proposedAt: "2026-05-23T03:50:00Z",
        activeFrom: "2026-05-23T03:59:00Z",
      },
      evidence: authorizationEvidence(),
    } as unknown as TrustRegistryAuthorizationSnapshotEntry,
    {
      label: "retired-audit",
      authorization: {
        authorizationId: "auth:auditor:retired:v1",
        registryId: "registry:kanon-admin",
        role: "auditor",
        subjectDid: "did:midnight:testnet:auditor",
        resourceType: "request-profile",
        resourceId: `tr:request-resource:v1:${"b".repeat(64)}`,
        policyId: "policy:default",
        trustLevel: "audit-approved",
        status: "archived",
        lifecycleEventRoot: "event-root",
        evidenceHash: "evidence-hash",
        proposedAt: "2026-05-23T03:40:00Z",
        archivedAt: "2026-05-23T03:57:00Z",
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
  it("loads auditor rows separately and preserves structured mutation errors", async () => {
    const paths: string[] = [];
    const responses = new Map<string, unknown>([
      ["/v1/registry/summary", board.summary],
      ["/v1/authorizations/issuer", { entries: board.issuers }],
      ["/v1/authorizations/verifier", { entries: board.verifiers }],
      ["/v1/authorizations/auditor", { entries: board.auditors }],
      ["/v1/recognitions", { entries: board.recognitions }],
    ]);
    const fetchImpl = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
      const path = new URL(String(input)).pathname;
      paths.push(path);
      const payload = responses.get(path);
      return payload === undefined
        ? Response.json({ title: "forbidden", detail: "maintainer quorum required", status: 403 }, { status: 403 })
        : Response.json(payload);
    });
    const client = new TrustRegistryAdminConsoleClient("http://127.0.0.1:4400", fetchImpl as typeof fetch);
    const loaded = await client.loadReviewBoard();
    expect(loaded.auditors).toHaveLength(2);
    expect(paths).toContain("/v1/authorizations/auditor");
    await expect(client.mutate("auditor", "auth:auditor:compliance:v1", "suspend"))
      .rejects.toThrow(/maintainer quorum required/);
    expect(paths.at(-1)).toBe("/v1/applications/auditor/auth%3Aauditor%3Acompliance%3Av1/suspend");
  });
  it("derives conservative maintainer actions from lifecycle state", () => {
    expect(getReviewActions("proposed")).toEqual(["approve", "archive"]);
    expect(getReviewActions("authorized")).toEqual(["activate", "revoke", "archive"]);
    expect(getReviewActions("suspended")).toEqual(["revoke", "archive"]);
    expect(getReviewActions("archived")).toEqual([]);
  });

  it("builds review cards and groups them by status", () => {
    const cards = buildReviewCards(board);
    expect(cards).toHaveLength(5);
    expect(cards[0]?.label).toBe("degree");

    const grouped = groupReviewCards(cards);
    expect(grouped.proposed).toHaveLength(1);
    expect(grouped.authorized).toHaveLength(1);
    expect(grouped.suspended).toHaveLength(1);
    expect(grouped.active).toHaveLength(1);
    expect(grouped.archived).toHaveLength(1);
    expect(grouped.archived[0]?.target).toBe("auditor");
    expect(grouped.archived[0] && getReviewActions(grouped.archived[0].status)).toEqual([]);
  });

  it("rejects a wrong-role authorization row from the auditor API list", () => {
    expect(() => buildReviewCards({ ...board, auditors: [board.verifiers[0]!] }))
      .toThrow(/Cannot render verifier authorization as auditor review card/);
    const auditor = board.auditors[0]!;
    expect(() => buildReviewCards({ ...board, auditors: [{
      ...auditor,
      authorization: { ...auditor.authorization, resourceId: "https://profiles.example/audit" },
    }] })).toThrow(/canonical composite request resource ID/);
    const verifier = board.verifiers[0]!;
    expect(() => buildReviewCards({ ...board, verifiers: [{
      ...verifier,
      authorization: { ...verifier.authorization, resourceId: "https://profiles.example/age" },
    }] })).toThrow(/canonical composite request resource ID/);
  });

  it("confirms epoch publication before calling the mutation endpoint", async () => {
    const publish = vi.fn(async () => ({ recordKind: "epoch" }) as ReviewBoardMutation);
    expect(await executeEpochPublication("audit-round", () => false, publish)).toBeNull();
    expect(publish).not.toHaveBeenCalled();
    const confirm = vi.fn(async () => true);
    await executeEpochPublication("audit-round", confirm, publish);
    expect(confirm).toHaveBeenCalledWith(expect.stringContaining("anchors the current state root"));
    expect(publish).toHaveBeenCalledExactlyOnceWith("audit-round");
  });

  it("confirms auditor actions with exact role and ID before mutation", async () => {
    const card = buildReviewCards(board).find((entry) => entry.target === "auditor" && entry.status === "active");
    if (card === undefined) throw new Error("expected active auditor card");
    expect(card.detailRows).toContainEqual({ label: "Governed resource ID", value: board.auditors[0]?.authorization.resourceId });
    expect(card.detailRows).toContainEqual({ label: "Evidence epoch", value: "epoch:002" });
    expect(describeActionConfirmation(card, "suspend")).toContain("auditor record auth:auditor:compliance:v1 (active)");
    const mutate = vi.fn(async () => ({ recordKind: "authorization" }) as ReviewBoardMutation);
    expect(await executeReviewAction(card, "suspend", () => false, mutate)).toBeNull();
    expect(mutate).not.toHaveBeenCalled();
    await executeReviewAction(card, "suspend", () => true, mutate);
    expect(mutate).toHaveBeenCalledWith("auditor", "auth:auditor:compliance:v1", "suspend");
    await expect(executeReviewAction(card, "approve", () => true, mutate)).rejects.toThrow(/not available/);
    expect(mutate).toHaveBeenCalledTimes(1);
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
