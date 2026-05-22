import { describe, expect, it } from "vitest";

import {
  TrustRegistryEvidenceBundleJsonSchema,
  TrustRegistryEvidenceBundleSchema,
  computeAuthorizationStatementLeafHash,
  computeMerkleRootFromProof,
  computeRecognitionStatementLeafHash,
  computeSingleStatementStateRoot,
} from "../index.js";

const HASH_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HASH_C = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const HASH_D = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

describe("trust registry evidence bundle", () => {
  it("accepts authorization evidence bundles", () => {
    const parsed = TrustRegistryEvidenceBundleSchema.parse({
      bundleId: "bundle:issuer:birth:v1",
      generatedAt: "2026-05-20T02:00:00Z",
      registryId: "registry:midnight:university",
      subjectDid: "did:midnight:issuer:1",
      policy: {
        policyId: "policy:university:v1",
        registryId: "registry:midnight:university",
        version: "v1",
        policyUri: "https://registry.example/policy/v1",
        status: "active",
        effectiveFrom: "2026-05-20T00:00:00Z",
        policyTemplates: [
          {
            templateId: "policy-template:university:member:v1",
            family: "member",
            name: "Member Governance",
            description: "Issuer and verifier onboarding",
            requiredMaintainerThreshold: 2,
            applicableRoles: ["issuer", "verifier"],
            applicableActionKinds: ["tr:issuer:propose", "tr:verifier:propose"],
            evidenceRules: ["application bundle", "quorum signatures"],
          },
        ],
        decisionBindings: [
          {
            bindingId: "policy-binding:university:member:v1",
            family: "member",
            templateId: "policy-template:university:member:v1",
            actionScopes: ["issuer-authorization"],
          },
        ],
        decisionRules: ["majority maintainers"],
        disputeRules: ["formal appeal"],
        retentionRules: ["retain 10 years"],
        emergencyRules: ["emergency suspension allowed"],
        lifecycleEventRoot: HASH_A,
      },
      epoch: {
        epochId: "epoch:0001",
        registryId: "registry:midnight:university",
        stateRoot: HASH_A,
        eventRoot: HASH_B,
        policyRoot: HASH_C,
        validFrom: "2026-05-20T02:00:00Z",
        validUntil: "2026-05-20T03:00:00Z",
        maintainerSignatures: [
          {
            keyId: "did:midnight:maintainer:1#key-1",
            algorithm: "jubjub-schnorr",
            signature: "sig-1",
          },
        ],
      },
      inclusionProof: {
        proofType: "merkle-inclusion",
        root: HASH_A,
        leafHash: HASH_D,
        path: [HASH_B, HASH_C],
        leafIndex: 0,
      },
      authorization: {
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
        evidenceHash: HASH_D,
        lifecycleEventRoot: HASH_A,
      },
      referencedStatusRegistryId: "status-registry:birth:v1",
      referencedStatusPolicyUri: "https://registry.example/status-policy",
    });

    expect(parsed.authorization?.role).toBe("issuer");
  });

  it("rejects bundles without authorization or recognition", () => {
    expect(() =>
      TrustRegistryEvidenceBundleSchema.parse({
        bundleId: "bundle:issuer:birth:v1",
        generatedAt: "2026-05-20T02:00:00Z",
        registryId: "registry:midnight:university",
        subjectDid: "did:midnight:issuer:1",
        policy: {
          policyId: "policy:university:v1",
          registryId: "registry:midnight:university",
          version: "v1",
          policyUri: "https://registry.example/policy/v1",
          status: "active",
          effectiveFrom: "2026-05-20T00:00:00Z",
          policyTemplates: [
            {
              templateId: "policy-template:university:member:v1",
              family: "member",
              name: "Member Governance",
              description: "Issuer and verifier onboarding",
              requiredMaintainerThreshold: 2,
              applicableRoles: ["issuer", "verifier"],
              applicableActionKinds: ["tr:issuer:propose", "tr:verifier:propose"],
              evidenceRules: ["application bundle", "quorum signatures"],
            },
          ],
          decisionBindings: [
            {
              bindingId: "policy-binding:university:member:v1",
              family: "member",
              templateId: "policy-template:university:member:v1",
              actionScopes: ["issuer-authorization"],
            },
          ],
          decisionRules: ["majority maintainers"],
          disputeRules: ["formal appeal"],
          retentionRules: ["retain 10 years"],
          emergencyRules: ["emergency suspension allowed"],
          lifecycleEventRoot: HASH_A,
        },
        epoch: {
          epochId: "epoch:0001",
          registryId: "registry:midnight:university",
          stateRoot: HASH_A,
          eventRoot: HASH_B,
          policyRoot: HASH_C,
          validFrom: "2026-05-20T02:00:00Z",
          validUntil: "2026-05-20T03:00:00Z",
          maintainerSignatures: [
            {
              keyId: "did:midnight:maintainer:1#key-1",
              algorithm: "jubjub-schnorr",
              signature: "sig-1",
            },
          ],
        },
        inclusionProof: {
          proofType: "merkle-inclusion",
          root: HASH_A,
          leafHash: HASH_D,
          path: [HASH_B, HASH_C],
          leafIndex: 0,
        },
      }),
    ).toThrow(/either an authorization or a recognition/);
  });

  it("exports a JSON schema with policy, epoch, inclusion, authorization, and recognition sections", () => {
    expect(TrustRegistryEvidenceBundleJsonSchema.required).toContain("policy");
    expect(TrustRegistryEvidenceBundleJsonSchema.required).toContain("epoch");
    expect(TrustRegistryEvidenceBundleJsonSchema.required).toContain("inclusionProof");
    expect(TrustRegistryEvidenceBundleJsonSchema.properties.authorization).toBeDefined();
    expect(TrustRegistryEvidenceBundleJsonSchema.properties.recognition).toBeDefined();
  });

  it("hashes the full statement payload and reconstructs the anchored state root", () => {
    const authorizationLeaf = computeAuthorizationStatementLeafHash({
      authorizationId: "auth:issuer:birth:v1",
      registryId: "registry:midnight:university",
      subjectDid: "did:midnight:issuer:1",
      role: "issuer",
      resourceType: "credential-family",
      resourceId: "vc-type:birth:v1",
      policyId: "policy:university:v1",
      trustLevel: "approved",
      status: "active",
      lifecycleEventRoot: HASH_A,
      proposedAt: "2026-05-20T00:00:00Z",
      authorizedAt: "2026-05-20T01:00:00Z",
      activeFrom: "2026-05-20T01:00:00Z",
      evidenceHash: HASH_D,
    });
    const changedAuthorizationLeaf = computeAuthorizationStatementLeafHash({
      authorizationId: "auth:issuer:birth:v1",
      registryId: "registry:midnight:university",
      subjectDid: "did:midnight:issuer:1",
      role: "issuer",
      resourceType: "credential-family",
      resourceId: "vc-type:birth:v1",
      policyId: "policy:university:v1",
      trustLevel: "silver",
      status: "active",
      lifecycleEventRoot: HASH_A,
      proposedAt: "2026-05-20T00:00:00Z",
      authorizedAt: "2026-05-20T01:00:00Z",
      activeFrom: "2026-05-20T01:00:00Z",
      evidenceHash: HASH_D,
    });

    expect(changedAuthorizationLeaf).not.toBe(authorizationLeaf);
    expect(
      computeSingleStatementStateRoot(authorizationLeaf, HASH_B),
    ).toBe(
      computeMerkleRootFromProof(authorizationLeaf, [HASH_B], 0),
    );

    const recognitionLeaf = computeRecognitionStatementLeafHash({
      recognitionId: "recognition:gaia-x:v1",
      registryId: "registry:midnight:university",
      recognizedAuthorityDid: "did:midnight:issuer:1",
      recognizedRegistryId: "registry:gaia-x",
      scope: {
        resourceType: "recognized-scope",
        resourceId: "gaia-x",
        context: {
          jurisdiction: "eu",
          assurance: "high",
        },
      },
      policyId: "policy:university:v1",
      trustLevel: "observer",
      status: "active",
      lifecycleEventRoot: HASH_C,
      proposedAt: "2026-05-20T00:00:00Z",
      authorizedAt: "2026-05-20T00:05:00Z",
      effectiveFrom: "2026-05-20T00:10:00Z",
      evidenceHash: HASH_D,
    });

    expect(recognitionLeaf).toMatch(/^0x[0-9a-f]{64}$/);
  });
});
