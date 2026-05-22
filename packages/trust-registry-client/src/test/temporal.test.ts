import { describe, expect, it } from "vitest";

import type {
  AuthorizationRecord,
  EpochCommitment,
  RecognitionRecord,
} from "@midnight-ntwrk/trust-registry-domain";

import {
  evaluateAuthorizationRecordAtTime,
  evaluateRecognitionRecordAtTime,
  selectAuthorizationEntryAtTime,
  selectEpochCommitmentAtTime,
  selectRecognitionEntryAtTime,
} from "../temporal.js";

const HASH_A = `0x${"1".repeat(64)}`;
const HASH_B = `0x${"2".repeat(64)}`;
const HASH_C = `0x${"3".repeat(64)}`;

const authorizationRecord: AuthorizationRecord = {
  authorizationId: "auth:issuer:degree:v1",
  registryId: "registry:kanon:trusted",
  subjectDid: "did:midnight:testnet:issuer",
  role: "issuer",
  resourceType: "credential-family",
  resourceId: "credential-family:degree",
  policyId: "policy:kanon:v1",
  trustLevel: "gold",
  status: "revoked",
  lifecycleEventRoot: HASH_A,
  proposedAt: "2026-05-20T00:00:00Z",
  authorizedAt: "2026-05-20T00:10:00Z",
  activeFrom: "2026-05-20T00:20:00Z",
  revokedAt: "2026-05-20T00:40:00Z",
  evidenceHash: HASH_B,
};

const recognitionRecord: RecognitionRecord = {
  recognitionId: "recognition:gaia-x:v1",
  registryId: "registry:kanon:trusted",
  recognizedAuthorityDid: "did:midnight:testnet:gaiax",
  recognizedRegistryId: "registry:gaia-x",
  scope: {
    resourceType: "recognized-scope",
    resourceId: "gaia-x",
  },
  policyId: "policy:kanon:v1",
  trustLevel: "observer",
  status: "suspended",
  lifecycleEventRoot: HASH_A,
  proposedAt: "2026-05-20T00:00:00Z",
  authorizedAt: "2026-05-20T00:05:00Z",
  effectiveFrom: "2026-05-20T00:10:00Z",
  suspendedAt: "2026-05-20T00:30:00Z",
  evidenceHash: HASH_C,
};

const epochs: readonly EpochCommitment[] = [
  {
    epochId: "epoch:001",
    registryId: "registry:kanon:trusted",
    stateRoot: HASH_A,
    eventRoot: HASH_B,
    policyRoot: HASH_C,
    validFrom: "2026-05-20T00:00:00Z",
    validUntil: "2026-05-20T00:29:59Z",
    maintainerSignatures: [
      {
        keyId: "did:midnight:testnet:registry#key-1",
        algorithm: "jubjub-schnorr",
        signature: HASH_A,
      },
    ],
  },
  {
    epochId: "epoch:002",
    registryId: "registry:kanon:trusted",
    stateRoot: HASH_B,
    eventRoot: HASH_C,
    policyRoot: HASH_A,
    validFrom: "2026-05-20T00:30:00Z",
    validUntil: "2026-05-20T00:59:59Z",
    maintainerSignatures: [
      {
        keyId: "did:midnight:testnet:registry#key-1",
        algorithm: "jubjub-schnorr",
        signature: HASH_B,
      },
    ],
  },
];

describe("trust registry temporal helpers", () => {
  it("derives authorization lifecycle status and trust by timestamp", () => {
    expect(
      evaluateAuthorizationRecordAtTime(
        authorizationRecord,
        "2026-05-19T23:59:59Z",
      ),
    ).toEqual({
      evaluatedAt: "2026-05-19T23:59:59Z",
      statusAtTime: null,
      trustedAtTime: false,
    });

    expect(
      evaluateAuthorizationRecordAtTime(
        authorizationRecord,
        "2026-05-20T00:15:00Z",
      ),
    ).toEqual({
      evaluatedAt: "2026-05-20T00:15:00Z",
      statusAtTime: "authorized",
      trustedAtTime: false,
    });

    expect(
      evaluateAuthorizationRecordAtTime(
        authorizationRecord,
        "2026-05-20T00:25:00Z",
      ),
    ).toEqual({
      evaluatedAt: "2026-05-20T00:25:00Z",
      statusAtTime: "active",
      trustedAtTime: true,
    });

    expect(
      evaluateAuthorizationRecordAtTime(
        authorizationRecord,
        "2026-05-20T00:45:00Z",
      ),
    ).toEqual({
      evaluatedAt: "2026-05-20T00:45:00Z",
      statusAtTime: "revoked",
      trustedAtTime: false,
    });
  });

  it("honors effectiveUntil and suspended authorization states", () => {
    const timeBoundRecord: AuthorizationRecord = {
      ...authorizationRecord,
      authorizationId: "auth:issuer:degree:time-bound",
      status: "suspended",
      effectiveUntil: "2026-05-20T00:29:59Z",
      suspendedAt: "2026-05-20T00:35:00Z",
      revokedAt: undefined,
    };

    expect(
      evaluateAuthorizationRecordAtTime(
        timeBoundRecord,
        "2026-05-20T00:29:00Z",
      ),
    ).toEqual({
      evaluatedAt: "2026-05-20T00:29:00Z",
      statusAtTime: "active",
      trustedAtTime: true,
    });

    expect(
      evaluateAuthorizationRecordAtTime(
        timeBoundRecord,
        "2026-05-20T00:31:00Z",
      ),
    ).toEqual({
      evaluatedAt: "2026-05-20T00:31:00Z",
      statusAtTime: "active",
      trustedAtTime: false,
    });

    expect(
      evaluateAuthorizationRecordAtTime(
        timeBoundRecord,
        "2026-05-20T00:36:00Z",
      ),
    ).toEqual({
      evaluatedAt: "2026-05-20T00:36:00Z",
      statusAtTime: "suspended",
      trustedAtTime: false,
    });
  });

  it("derives recognition lifecycle status and trust by timestamp", () => {
    expect(
      evaluateRecognitionRecordAtTime(
        recognitionRecord,
        "2026-05-20T00:12:00Z",
      ),
    ).toEqual({
      evaluatedAt: "2026-05-20T00:12:00Z",
      statusAtTime: "active",
      trustedAtTime: true,
    });

    expect(
      evaluateRecognitionRecordAtTime(
        recognitionRecord,
        "2026-05-20T00:35:00Z",
      ),
    ).toEqual({
      evaluatedAt: "2026-05-20T00:35:00Z",
      statusAtTime: "suspended",
      trustedAtTime: false,
    });
  });

  it("selects the latest visible scope record and epoch for a timestamp", () => {
    const olderRecord: AuthorizationRecord = {
      ...authorizationRecord,
      authorizationId: "auth:issuer:degree:v0",
      proposedAt: "2026-05-19T00:00:00Z",
      authorizedAt: "2026-05-19T00:10:00Z",
      activeFrom: "2026-05-19T00:20:00Z",
      archivedAt: "2026-05-19T00:50:00Z",
      status: "archived",
    };
    const selected = selectAuthorizationEntryAtTime(
      [
        { authorization: olderRecord, label: "degree-v0" },
        { authorization: authorizationRecord, label: "degree-v1" },
      ],
      "2026-05-20T00:25:00Z",
      (entry) => entry.authorization.resourceId === "credential-family:degree",
    );

    expect(selected?.authorization.authorizationId).toBe("auth:issuer:degree:v1");
    expect(
      selectEpochCommitmentAtTime(epochs, "2026-05-20T00:35:00Z")?.epochId,
    ).toBe("epoch:002");
    expect(selectEpochCommitmentAtTime(epochs, "2026-05-21T00:00:00Z")).toBeNull();
  });

  it("selects the latest visible recognition entry for a timestamp", () => {
    const olderRecognition: RecognitionRecord = {
      ...recognitionRecord,
      recognitionId: "recognition:gaia-x:v0",
      proposedAt: "2026-05-19T00:00:00Z",
      authorizedAt: "2026-05-19T00:05:00Z",
      effectiveFrom: "2026-05-19T00:10:00Z",
      archivedAt: "2026-05-19T00:50:00Z",
      status: "archived",
      suspendedAt: undefined,
    };

    const selected = selectRecognitionEntryAtTime(
      [
        { recognition: olderRecognition, label: "gaia-x-v0" },
        { recognition: recognitionRecord, label: "gaia-x-v1" },
      ],
      "2026-05-20T00:12:00Z",
      (entry) => entry.recognition.scope.resourceId === "gaia-x",
    );

    expect(selected?.recognition.recognitionId).toBe("recognition:gaia-x:v1");
  });

  it("rejects invalid timestamps", () => {
    expect(() =>
      evaluateAuthorizationRecordAtTime(authorizationRecord, "not-a-date")
    ).toThrow("invalid timestamp: not-a-date");
  });
});
