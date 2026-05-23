import { describe, expect, it } from "vitest";

import {
  TrustRegistryApiApplicationMutationResponseSchema,
  type TrustRegistryApiApplicationMutationResponse,
  type TrustRegistryApiSummary,
} from "@midnight-ntwrk/trust-registry-api";

import {
  TARGET_OPTIONS,
  describeSubmission,
  toInspectionCards,
  type PublicInspection,
} from "../model.js";

const HASH_A = `0x${"1".repeat(64)}`;
const HASH_B = `0x${"2".repeat(64)}`;
const HASH_C = `0x${"3".repeat(64)}`;
const HASH_D = `0x${"4".repeat(64)}`;
const HASH_E = `0x${"5".repeat(64)}`;

type EvidenceBundle = PublicInspection["activeIssuers"][number]["evidence"];

const summary: TrustRegistryApiSummary = {
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
};

const policy: EvidenceBundle["policy"] = {
  policyId: "policy:default",
  registryId: "registry:kanon-portal",
  version: "v1",
  policyUri: "https://example.com/policies/default",
  status: "active" as const,
  lifecycleEventRoot: HASH_A,
  effectiveFrom: "2026-05-20T00:00:00Z",
  policyTemplates: [
    {
      templateId: "policy-template:member:v1",
      family: "member" as const,
      name: "Member Governance",
      description: "Member onboarding decisions",
      requiredMaintainerThreshold: 1,
      applicableRoles: ["issuer", "verifier"],
      applicableActionKinds: ["tr:issuer:activate", "tr:verifier:activate"],
      evidenceRules: ["governance signatures"],
    },
  ],
  decisionBindings: [
    {
      bindingId: "policy-binding:member:v1",
      family: "member" as const,
      templateId: "policy-template:member:v1",
      actionScopes: ["tr:issuer:*", "tr:verifier:*"],
    },
  ],
  decisionRules: ["maintainer threshold applies"],
  disputeRules: ["appeal to maintainers"],
  retentionRules: ["retain historical evidence"],
  emergencyRules: ["suspend on incident evidence"],
};

const epoch: EvidenceBundle["epoch"] = {
  epochId: "epoch:003",
  registryId: "registry:kanon-portal",
  stateRoot: HASH_B,
  eventRoot: HASH_C,
  policyRoot: HASH_D,
  validFrom: "2026-05-23T05:00:00Z",
  validUntil: "2026-05-23T06:00:00Z",
  maintainerSignatures: [
    {
      keyId: "did:midnight:testnet:registry#key-1",
      algorithm: "jubjub-schnorr" as const,
      signature: HASH_E,
    },
  ],
};

const createAuthorizationMutationResponse = (
  target: "issuer" | "verifier",
): TrustRegistryApiApplicationMutationResponse =>
  TrustRegistryApiApplicationMutationResponseSchema.parse({
    sourceMode: "workspace",
    workspaceVersion: "1",
    workspaceUpdatedAt: "2026-05-23T05:00:00Z",
    snapshotGeneratedAt: "2026-05-23T05:00:00Z",
    currentEpochId: "epoch:003",
    operation: {
      operation: "submit",
      target,
      label: target === "issuer" ? "degree" : "age-gate",
    },
    recordKind: "authorization",
    entry: {
      label: target === "issuer" ? "degree" : "age-gate",
      authorization: {
        authorizationId: `auth:${target}:${target === "issuer" ? "degree" : "age-gate"}:v1`,
        registryId: "registry:kanon-portal",
        subjectDid: `did:midnight:testnet:${target}`,
        role: target,
        resourceType: target === "issuer" ? "credential-family" : "request-profile",
        resourceId: target === "issuer" ? "degree-scope" : "age-gate",
        policyId: "policy:default",
        trustLevel: target === "issuer" ? "gold" : "silver",
        status: "proposed",
        lifecycleEventRoot: HASH_A,
        proposedAt: "2026-05-23T05:00:00Z",
        evidenceHash: HASH_B,
      },
      evidence: {
        bundleId: `bundle:${target}:${target === "issuer" ? "degree" : "age-gate"}:v1`,
        generatedAt: "2026-05-23T05:00:00Z",
        registryId: "registry:kanon-portal",
        subjectDid: `did:midnight:testnet:${target}`,
        policy,
        epoch,
        inclusionProof: {
          proofType: "merkle-inclusion",
          root: HASH_C,
          leafHash: HASH_D,
          path: [HASH_B],
          leafIndex: 0,
        },
        authorization: {
          authorizationId: `auth:${target}:${target === "issuer" ? "degree" : "age-gate"}:v1`,
          registryId: "registry:kanon-portal",
          subjectDid: `did:midnight:testnet:${target}`,
          role: target,
          resourceType: target === "issuer" ? "credential-family" : "request-profile",
          resourceId: target === "issuer" ? "degree-scope" : "age-gate",
          policyId: "policy:default",
          trustLevel: target === "issuer" ? "gold" : "silver",
          status: "proposed",
          lifecycleEventRoot: HASH_A,
          proposedAt: "2026-05-23T05:00:00Z",
          evidenceHash: HASH_B,
        },
      },
    },
  });

const createRecognitionMutationResponse = (): TrustRegistryApiApplicationMutationResponse =>
  TrustRegistryApiApplicationMutationResponseSchema.parse({
    sourceMode: "workspace",
    workspaceVersion: "1",
    workspaceUpdatedAt: "2026-05-23T05:00:00Z",
    snapshotGeneratedAt: "2026-05-23T05:00:00Z",
    currentEpochId: "epoch:003",
    operation: {
      operation: "submit",
      target: "recognition",
      label: "gaia-x",
    },
    recordKind: "recognition",
    entry: {
      label: "gaia-x",
      recognition: {
        recognitionId: "recognition:gaia-x:v1",
        registryId: "registry:kanon-portal",
        recognizedAuthorityDid: "did:midnight:testnet:gaiax",
        recognizedRegistryId: "registry:gaia-x",
        scope: {
          resourceType: "recognized-scope",
          resourceId: "gaia-x",
        },
        policyId: "policy:default",
        trustLevel: "observer",
        status: "proposed",
        lifecycleEventRoot: HASH_A,
        proposedAt: "2026-05-23T05:00:00Z",
        evidenceHash: HASH_B,
      },
      evidence: {
        bundleId: "bundle:recognition:gaia-x:v1",
        generatedAt: "2026-05-23T05:00:00Z",
        registryId: "registry:kanon-portal",
        subjectDid: "did:midnight:testnet:gaiax",
        policy,
        epoch,
        inclusionProof: {
          proofType: "merkle-inclusion",
          root: HASH_C,
          leafHash: HASH_D,
          path: [HASH_B],
          leafIndex: 0,
        },
        recognition: {
          recognitionId: "recognition:gaia-x:v1",
          registryId: "registry:kanon-portal",
          recognizedAuthorityDid: "did:midnight:testnet:gaiax",
          recognizedRegistryId: "registry:gaia-x",
          scope: {
            resourceType: "recognized-scope",
            resourceId: "gaia-x",
          },
          policyId: "policy:default",
          trustLevel: "observer",
          status: "proposed",
          lifecycleEventRoot: HASH_A,
          proposedAt: "2026-05-23T05:00:00Z",
          evidenceHash: HASH_B,
        },
      },
    },
  });

const createEpochMutationResponse = (): TrustRegistryApiApplicationMutationResponse =>
  TrustRegistryApiApplicationMutationResponseSchema.parse({
    sourceMode: "workspace",
    workspaceVersion: "1",
    workspaceUpdatedAt: "2026-05-23T05:00:00Z",
    snapshotGeneratedAt: "2026-05-23T05:00:00Z",
    currentEpochId: "epoch:004",
    operation: {
      operation: "publish-epoch",
      label: "post-review",
    },
    recordKind: "epoch",
    epoch: {
      ...epoch,
      epochId: "epoch:004",
    },
  });

const inspection: PublicInspection = {
  summary,
  activeIssuers: [
    {
      label: "degree",
      authorization: {
        authorizationId: "auth:issuer:degree:v1",
        registryId: "registry:kanon-portal",
        subjectDid: "did:midnight:testnet:issuer",
        role: "issuer",
        resourceType: "credential-family",
        resourceId: "degree-scope",
        policyId: "policy:default",
        trustLevel: "gold",
        status: "active",
        lifecycleEventRoot: HASH_A,
        proposedAt: "2026-05-20T00:00:00Z",
        authorizedAt: "2026-05-20T00:05:00Z",
        activeFrom: "2026-05-20T00:10:00Z",
        evidenceHash: HASH_B,
      },
      evidence: {
        bundleId: "bundle:issuer:degree:v1",
        generatedAt: "2026-05-23T05:00:00Z",
        registryId: "registry:kanon-portal",
        subjectDid: "did:midnight:testnet:issuer",
        policy,
        epoch,
        inclusionProof: {
          proofType: "merkle-inclusion",
          root: HASH_C,
          leafHash: HASH_D,
          path: [HASH_B],
          leafIndex: 0,
        },
        authorization: {
          authorizationId: "auth:issuer:degree:v1",
          registryId: "registry:kanon-portal",
          subjectDid: "did:midnight:testnet:issuer",
          role: "issuer",
          resourceType: "credential-family",
          resourceId: "degree-scope",
          policyId: "policy:default",
          trustLevel: "gold",
          status: "active",
          lifecycleEventRoot: HASH_A,
          proposedAt: "2026-05-20T00:00:00Z",
          authorizedAt: "2026-05-20T00:05:00Z",
          activeFrom: "2026-05-20T00:10:00Z",
          evidenceHash: HASH_B,
        },
      },
    },
  ],
  activeVerifiers: [
    {
      label: "age-gate",
      authorization: {
        authorizationId: "auth:verifier:age-gate:v1",
        registryId: "registry:kanon-portal",
        subjectDid: "did:midnight:testnet:verifier",
        role: "verifier",
        resourceType: "request-profile",
        resourceId: "age-gate",
        policyId: "policy:default",
        trustLevel: "silver",
        status: "active",
        lifecycleEventRoot: HASH_A,
        proposedAt: "2026-05-20T00:00:00Z",
        authorizedAt: "2026-05-20T00:05:00Z",
        activeFrom: "2026-05-20T00:10:00Z",
        evidenceHash: HASH_B,
      },
      evidence: {
        bundleId: "bundle:verifier:age-gate:v1",
        generatedAt: "2026-05-23T05:00:00Z",
        registryId: "registry:kanon-portal",
        subjectDid: "did:midnight:testnet:verifier",
        policy,
        epoch,
        inclusionProof: {
          proofType: "merkle-inclusion",
          root: HASH_C,
          leafHash: HASH_D,
          path: [HASH_B],
          leafIndex: 0,
        },
        authorization: {
          authorizationId: "auth:verifier:age-gate:v1",
          registryId: "registry:kanon-portal",
          subjectDid: "did:midnight:testnet:verifier",
          role: "verifier",
          resourceType: "request-profile",
          resourceId: "age-gate",
          policyId: "policy:default",
          trustLevel: "silver",
          status: "active",
          lifecycleEventRoot: HASH_A,
          proposedAt: "2026-05-20T00:00:00Z",
          authorizedAt: "2026-05-20T00:05:00Z",
          activeFrom: "2026-05-20T00:10:00Z",
          evidenceHash: HASH_B,
        },
      },
    },
  ],
  activeRecognitions: [
    {
      label: "gaia-x",
      recognition: {
        recognitionId: "recognition:gaia-x:v1",
        registryId: "registry:kanon-portal",
        recognizedAuthorityDid: "did:midnight:testnet:gaiax",
        recognizedRegistryId: "registry:gaia-x",
        scope: {
          resourceType: "recognized-scope",
          resourceId: "gaia-x",
        },
        policyId: "policy:default",
        trustLevel: "observer",
        status: "active",
        lifecycleEventRoot: HASH_A,
        proposedAt: "2026-05-20T00:00:00Z",
        authorizedAt: "2026-05-20T00:05:00Z",
        effectiveFrom: "2026-05-20T00:10:00Z",
        evidenceHash: HASH_B,
      },
      evidence: {
        bundleId: "bundle:recognition:gaia-x:v1",
        generatedAt: "2026-05-23T05:00:00Z",
        registryId: "registry:kanon-portal",
        subjectDid: "did:midnight:testnet:gaiax",
        policy,
        epoch,
        inclusionProof: {
          proofType: "merkle-inclusion",
          root: HASH_C,
          leafHash: HASH_D,
          path: [HASH_B],
          leafIndex: 0,
        },
        recognition: {
          recognitionId: "recognition:gaia-x:v1",
          registryId: "registry:kanon-portal",
          recognizedAuthorityDid: "did:midnight:testnet:gaiax",
          recognizedRegistryId: "registry:gaia-x",
          scope: {
            resourceType: "recognized-scope",
            resourceId: "gaia-x",
          },
          policyId: "policy:default",
          trustLevel: "observer",
          status: "active",
          lifecycleEventRoot: HASH_A,
          proposedAt: "2026-05-20T00:00:00Z",
          authorizedAt: "2026-05-20T00:05:00Z",
          effectiveFrom: "2026-05-20T00:10:00Z",
          evidenceHash: HASH_B,
        },
      },
    },
  ],
};

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

  it("describes authorization submissions in user-facing language", () => {
    expect(describeSubmission(createAuthorizationMutationResponse("issuer"))).toMatch(
      /submitted degree/i,
    );
  });

  it("describes recognition submissions in user-facing language", () => {
    expect(describeSubmission(createRecognitionMutationResponse())).toMatch(
      /recognition application/i,
    );
  });

  it("describes epoch publication responses in user-facing language", () => {
    expect(describeSubmission(createEpochMutationResponse())).toBe(
      "Published epoch epoch:004.",
    );
  });
});
