import { describe, expect, it } from "vitest";

import {
  EpochCommitmentSchema,
  TrustRegistryEvidenceBundleJsonSchema,
  TrustRegistryEvidenceBundleSchema,
  computeAuthorizationStatementLeafHash,
  computeMerkleRootFromProof,
  computeRecognitionStatementLeafHash,
  computeSingleStatementStateRoot,
  computeIssuerStatusPolicyBindingCommitment,
  issuerGovernedResourceIdFromScopeCommitment,
} from "../index.js";

const HASH_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HASH_C = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const HASH_D = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const ISSUER_RESOURCE_ID = issuerGovernedResourceIdFromScopeCommitment(HASH_A, "credentialFamily");
const STATUS_BINDING = {
  version: "tr-issuer-status-policy-v1",
  trustRegistryId: "registry:midnight:university",
  issuerAuthorizationId: "auth:issuer:birth:v1",
  statusRegistryId: HASH_C,
  statusAuthorityVerificationMethod: "did:midnight:issuer:1#status-key",
  statusPolicyId: "policy:status:birth",
  statusPolicyVersion: "v1",
  statusPolicyContentCommitment: HASH_D,
} as const;

describe("trust registry evidence bundle", () => {
  it("requires one epoch signature in both bundle schemas", () => {
    const epoch = {
      epochId: "epoch:0001",
      registryId: "registry:midnight:university",
      stateRoot: HASH_A,
      eventRoot: HASH_B,
      policyRoot: HASH_C,
      validFrom: "2026-05-20T02:00:00Z",
      validUntil: "2026-05-20T03:00:00Z",
      maintainerSignatures: [{
        keyId: "did:midnight:maintainer:1#key-1",
        algorithm: "jubjub-schnorr",
        signature: "sig-1",
      }],
    };
    expect(EpochCommitmentSchema.safeParse(epoch).success).toBe(true);
    const invalid = EpochCommitmentSchema.safeParse({
      ...epoch,
      maintainerSignatures: [...epoch.maintainerSignatures, epoch.maintainerSignatures[0]],
    });
    expect(invalid.success).toBe(false);
    if (invalid.success) throw new Error("expected cardinality rejection");
    expect(invalid.error.issues).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "too_big", path: ["maintainerSignatures"] }),
    ]));
    const missing = EpochCommitmentSchema.safeParse({
      ...epoch,
      maintainerSignatures: [],
    });
    expect(missing.success).toBe(false);
    if (missing.success) throw new Error("expected missing-signature rejection");
    expect(missing.error.issues).toEqual(expect.arrayContaining([
      expect.objectContaining({ code: "too_small", path: ["maintainerSignatures"] }),
    ]));
    expect(
      TrustRegistryEvidenceBundleJsonSchema.properties.epoch.properties
        .maintainerSignatures.maxItems,
    ).toBe(1);
    expect(
      TrustRegistryEvidenceBundleJsonSchema.properties.epoch.properties
        .maintainerSignatures.minItems,
    ).toBe(1);
  });

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
        resourceId: ISSUER_RESOURCE_ID,
        policyId: "policy:university:v1",
        trustLevel: "approved",
        status: "active",
        statusPolicyBindingCommitment: computeIssuerStatusPolicyBindingCommitment(STATUS_BINDING),
        proposedAt: "2026-05-20T00:00:00Z",
        authorizedAt: "2026-05-20T01:00:00Z",
        activeFrom: "2026-05-20T01:00:00Z",
        evidenceHash: HASH_D,
        lifecycleEventRoot: HASH_A,
      },
      statusPolicyBinding: STATUS_BINDING,
      referencedStatusRegistryId: "status-registry:birth:v1",
      referencedStatusPolicyUri: "https://registry.example/status-policy",
    });

    expect(parsed.authorization?.role).toBe("issuer");
    expect(TrustRegistryEvidenceBundleSchema.safeParse({
      ...parsed,
      authorization: { ...parsed.authorization, role: "verifier" },
    }).success).toBe(false);
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
    expect(TrustRegistryEvidenceBundleJsonSchema.properties.authorization.properties.statusPolicyBindingCommitment).toBeDefined();
    expect(TrustRegistryEvidenceBundleJsonSchema.properties.statusPolicyBinding).toBeDefined();
    expect(TrustRegistryEvidenceBundleJsonSchema.allOf).toHaveLength(2);
    expect(TrustRegistryEvidenceBundleJsonSchema.properties.recognition).toBeDefined();
  });

  it("hashes the full statement payload and reconstructs the anchored state root", () => {
    const authorizationLeaf = computeAuthorizationStatementLeafHash({
      authorizationId: "auth:issuer:birth:v1",
      registryId: "registry:midnight:university",
      subjectDid: "did:midnight:issuer:1",
      role: "issuer",
      resourceType: "credential-family",
      resourceId: ISSUER_RESOURCE_ID,
      policyId: "policy:university:v1",
      trustLevel: "approved",
      statusPolicyBindingCommitment: HASH_B,
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
      resourceId: ISSUER_RESOURCE_ID,
      policyId: "policy:university:v1",
      trustLevel: "silver",
      statusPolicyBindingCommitment: HASH_B,
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
    expect(
      computeRecognitionStatementLeafHash({
        recognitionId: "recognition:gaia-x:v1",
        registryId: "registry:midnight:university",
        recognizedAuthorityDid: "did:midnight:issuer:1",
        recognizedRegistryId: "registry:gaia-x",
        scope: {
          resourceType: "recognized-scope",
          resourceId: "gaia-x",
          context: {
            assurance: "high",
            jurisdiction: "eu",
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
      }),
    ).toBe(recognitionLeaf);
    expect(() =>
      computeMerkleRootFromProof(authorizationLeaf, [HASH_B], 2),
    ).toThrow(/out of range/i);
  });
});
