import { describe, expect, it } from "vitest";

import {
  assertLifecycleTransition,
  AuthorizationRecordSchema,
  createScopedIdentifier,
  GovernancePolicyRecordSchema,
  ParticipantRecordSchema,
  RecognitionRecordSchema,
  RegistryRecordSchema,
  sha256Hex,
} from "../index.js";

const HASH_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HASH_C = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const HASH_D = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

describe("identifier helpers", () => {
  it("creates stable scoped identifiers", () => {
    expect(createScopedIdentifier("vc-type", "Birth Credential", "v1")).toBe(
      "vc-type:birth-credential:v1",
    );
  });

  it("creates 32-byte sha256 hex digests", () => {
    expect(sha256Hex("midnight-trust-registry")).toMatch(/^0x[0-9a-f]{64}$/);
  });
});

describe("lifecycle transitions", () => {
  it("accepts a valid transition", () => {
    expect(() => assertLifecycleTransition("authorized", "active")).not.toThrow();
  });

  it("rejects an invalid transition", () => {
    expect(() => assertLifecycleTransition("active", "authorized")).toThrow(
      /Invalid lifecycle transition/,
    );
  });
});

describe("record schemas", () => {
  it("accepts a registry record", () => {
    const parsed = RegistryRecordSchema.parse({
      registryId: "registry:midnight:university",
      registryDid: "did:midnight:registry:university",
      name: "University Trust Registry",
      description: "Registry for university issuers and verifiers",
      controllerDids: ["did:midnight:governor:1"],
      maintainerDids: ["did:midnight:maintainer:1"],
      policyUri: "https://registry.example/policy",
      serviceEndpoint: "https://registry.example/query",
      logoUri: "https://registry.example/logo.svg",
      status: "active",
      createdAt: "2026-05-20T00:00:00Z",
      updatedAt: "2026-05-20T00:00:00Z",
      lifecycleEventRoot: HASH_A,
    });

    expect(parsed.registryId).toBe("registry:midnight:university");
  });

  it("accepts a participant and policy record", () => {
    expect(() =>
      GovernancePolicyRecordSchema.parse({
        policyId: "policy:university:v1",
        registryId: "registry:midnight:university",
        version: "v1",
        policyUri: "https://registry.example/policy/v1",
        status: "active",
        effectiveFrom: "2026-05-20T00:00:00Z",
        decisionRules: ["majority maintainers"],
        disputeRules: ["formal appeal"],
        retentionRules: ["retain 10 years"],
        emergencyRules: ["emergency suspension allowed"],
        lifecycleEventRoot: HASH_A,
      }),
    ).not.toThrow();

    expect(() =>
      ParticipantRecordSchema.parse({
        participantId: "participant:issuer:1",
        participantDid: "did:midnight:issuer:1",
        participantType: "issuer",
        legalName: "Example University",
        serviceEndpoint: "https://issuer.example/ssi",
        currentKeyRefs: ["did:midnight:issuer:1#key-1"],
        historicalKeyRefs: [],
        metadataUri: "https://issuer.example/metadata",
        status: "active",
        effectiveFrom: "2026-05-20T00:00:00Z",
        lifecycleEventRoot: HASH_B,
      }),
    ).not.toThrow();
  });

  it("accepts authorization and recognition records", () => {
    const authorization = AuthorizationRecordSchema.parse({
      authorizationId: "auth:issuer:birth:v1",
      registryId: "registry:midnight:university",
      subjectDid: "did:midnight:issuer:1",
      role: "issuer",
      resourceType: "credential-family",
      resourceId: "vc-type:birth:v1",
      policyId: "policy:university:v1",
      trustLevel: "approved",
      status: "active",
      proposedAt: "2026-05-20T00:00:00Z",
      authorizedAt: "2026-05-20T01:00:00Z",
      activeFrom: "2026-05-20T01:00:00Z",
      evidenceHash: HASH_C,
      lifecycleEventRoot: HASH_A,
    });

    const recognition = RecognitionRecordSchema.parse({
      recognitionId: "rec:gaia-x:issuer",
      registryId: "registry:midnight:university",
      recognizedAuthorityDid: "did:web:gaia-x.example",
      recognizedRegistryId: "registry:gaia-x:edu",
      scope: {
        resourceType: "recognized-scope",
        resourceId: "vc-type:degree:v1",
      },
      policyId: "policy:university:v1",
      trustLevel: "peer-approved",
      effectiveFrom: "2026-05-20T01:00:00Z",
      status: "authorized",
      proposedAt: "2026-05-20T00:00:00Z",
      authorizedAt: "2026-05-20T01:00:00Z",
      evidenceHash: HASH_D,
      lifecycleEventRoot: HASH_B,
    });

    expect(authorization.role).toBe("issuer");
    expect(recognition.scope.resourceId).toBe("vc-type:degree:v1");
  });

  it("rejects invalid authorization chronology", () => {
    expect(() =>
      AuthorizationRecordSchema.parse({
        authorizationId: "auth:issuer:birth:v1",
        registryId: "registry:midnight:university",
        subjectDid: "did:midnight:issuer:1",
        role: "issuer",
        resourceType: "credential-family",
        resourceId: "vc-type:birth:v1",
        policyId: "policy:university:v1",
        trustLevel: "approved",
        status: "active",
        proposedAt: "2026-05-20T02:00:00Z",
        authorizedAt: "2026-05-20T01:00:00Z",
        activeFrom: "2026-05-20T01:00:00Z",
        evidenceHash: HASH_C,
        lifecycleEventRoot: HASH_A,
      }),
    ).toThrow(/must not be earlier/);
  });

  it("requires authorizedAt after proposed state", () => {
    expect(() =>
      RecognitionRecordSchema.parse({
        recognitionId: "rec:gaia-x:issuer",
        registryId: "registry:midnight:university",
        recognizedAuthorityDid: "did:web:gaia-x.example",
        recognizedRegistryId: "registry:gaia-x:edu",
        scope: {
          resourceType: "recognized-scope",
          resourceId: "vc-type:degree:v1",
        },
        policyId: "policy:university:v1",
        trustLevel: "peer-approved",
        effectiveFrom: "2026-05-20T00:00:00Z",
        status: "authorized",
        proposedAt: "2026-05-20T00:00:00Z",
        evidenceHash: HASH_D,
        lifecycleEventRoot: HASH_B,
      }),
    ).toThrow(/authorizedAt is required/);
  });
});
