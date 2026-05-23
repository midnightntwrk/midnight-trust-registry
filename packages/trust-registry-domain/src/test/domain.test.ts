import { describe, expect, it } from "vitest";

import {
  assertLifecycleTransition,
  AuthorizationRecordSchema,
  createScopedIdentifier,
  GovernancePolicyRecordSchema,
  ParticipantRecordSchema,
  RecognitionRecordSchema,
  RegistryRecordSchema,
  resolveGovernancePolicyTemplate,
  sha256Hex,
} from "../index.js";

const HASH_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const HASH_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const HASH_C = "0xcccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const HASH_D = "0xdddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

const createPolicyTemplates = () => [
  {
    templateId: "policy-template:university:maintainer:v1",
    family: "maintainer" as const,
    name: "Maintainer Governance",
    description: "Maintainer onboarding and membership changes",
    requiredMaintainerThreshold: 2,
    applicableRoles: ["maintainer"] as const,
    applicableActionKinds: [
      "tr:maintainer:propose",
      "tr:maintainer:authorize",
      "tr:maintainer:activate",
    ],
    evidenceRules: ["quorum signatures", "membership evidence"],
  },
  {
    templateId: "policy-template:university:member:v1",
    family: "member" as const,
    name: "Member Governance",
    description: "Issuer, verifier, and recognition onboarding decisions",
    requiredMaintainerThreshold: 2,
    applicableRoles: ["issuer", "verifier", "authority"] as const,
    applicableActionKinds: [
      "tr:issuer:propose",
      "tr:verifier:propose",
      "tr:recognition:propose",
    ],
    evidenceRules: ["application bundle", "quorum signatures"],
  },
  {
    templateId: "policy-template:university:emergency:v1",
    family: "emergency" as const,
    name: "Emergency Governance",
    description: "Compromise response and emergency suspensions",
    requiredMaintainerThreshold: 1,
    applicableRoles: ["issuer", "verifier", "maintainer", "authority", "auditor"] as const,
    applicableActionKinds: ["tr:issuer:suspend", "tr:verifier:revoke"],
    evidenceRules: ["incident evidence", "quorum signatures"],
  },
  {
    templateId: "policy-template:university:archival:v1",
    family: "archival" as const,
    name: "Archival Governance",
    description: "Historical archival and closure decisions",
    requiredMaintainerThreshold: 2,
    applicableRoles: ["issuer", "verifier", "maintainer", "authority", "auditor"] as const,
    applicableActionKinds: ["tr:issuer:archive", "tr:maintainer:archive"],
    evidenceRules: ["archival justification", "quorum signatures"],
  },
  {
    templateId: "policy-template:university:auditor:v1",
    family: "auditor" as const,
    name: "Auditor Governance",
    description: "Auditor onboarding and oversight decisions",
    requiredMaintainerThreshold: 2,
    applicableRoles: ["auditor"] as const,
    applicableActionKinds: ["tr:auditor:propose", "tr:auditor:activate"],
    evidenceRules: ["audit mandate", "quorum signatures"],
  },
];

const createDecisionBindings = () => [
  {
    bindingId: "policy-binding:university:maintainer:v1",
    family: "maintainer" as const,
    templateId: "policy-template:university:maintainer:v1",
    actionScopes: ["maintainer-membership"],
  },
  {
    bindingId: "policy-binding:university:member:v1",
    family: "member" as const,
    templateId: "policy-template:university:member:v1",
    actionScopes: ["issuer-authorization", "verifier-authorization", "recognition"],
  },
  {
    bindingId: "policy-binding:university:emergency:v1",
    family: "emergency" as const,
    templateId: "policy-template:university:emergency:v1",
    actionScopes: ["participant-emergency"],
  },
  {
    bindingId: "policy-binding:university:archival:v1",
    family: "archival" as const,
    templateId: "policy-template:university:archival:v1",
    actionScopes: ["participant-archival"],
  },
  {
    bindingId: "policy-binding:university:auditor:v1",
    family: "auditor" as const,
    templateId: "policy-template:university:auditor:v1",
    actionScopes: ["auditor-authorization"],
  },
];

const createPolicyRecordInput = () => ({
  policyId: "policy:university:v1",
  registryId: "registry:midnight:university",
  version: "v1",
  policyUri: "https://registry.example/policy/v1",
  status: "active" as const,
  effectiveFrom: "2026-05-20T00:00:00Z",
  policyTemplates: createPolicyTemplates(),
  decisionBindings: createDecisionBindings(),
  decisionRules: ["majority maintainers"],
  disputeRules: ["formal appeal"],
  retentionRules: ["retain 10 years"],
  emergencyRules: ["emergency suspension allowed"],
  lifecycleEventRoot: HASH_A,
});

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
    expect(() => GovernancePolicyRecordSchema.parse(createPolicyRecordInput())).not.toThrow();

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

  it("resolves a typed governance template from a decision binding", () => {
    const policy = GovernancePolicyRecordSchema.parse(createPolicyRecordInput());

    const template = resolveGovernancePolicyTemplate(policy, "emergency");

    expect(template.family).toBe("emergency");
    expect(template.requiredMaintainerThreshold).toBe(1);
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

  it("allows pre-activation recognition records without effectiveFrom", () => {
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
        status: "authorized",
        proposedAt: "2026-05-20T00:00:00Z",
        authorizedAt: "2026-05-20T01:00:00Z",
        evidenceHash: HASH_D,
        lifecycleEventRoot: HASH_B,
      }),
    ).not.toThrow();
  });

  it("rejects governance policies with bindings that do not resolve to typed templates", () => {
    expect(() =>
      GovernancePolicyRecordSchema.parse({
        ...createPolicyRecordInput(),
        policyTemplates: createPolicyTemplates(),
        decisionBindings: [
          {
            bindingId: "policy-binding:broken:v1",
            family: "member",
            templateId: "policy-template:missing:v1",
            actionScopes: ["issuer-authorization"],
          },
        ],
      }),
    ).toThrow(/existing policy template/i);
  });

  it("rejects governance policies with duplicate template identifiers", () => {
    const [firstTemplate, secondTemplate, ...remainingTemplates] = createPolicyTemplates();
    const duplicatedTemplates = [
      firstTemplate!,
      {
        ...secondTemplate!,
        templateId: firstTemplate!.templateId,
      },
      ...remainingTemplates,
    ];

    expect(() =>
      GovernancePolicyRecordSchema.parse({
        ...createPolicyRecordInput(),
        policyTemplates: duplicatedTemplates,
      }),
    ).toThrow(/repeat templateId values/i);
  });

  it("rejects governance policies with duplicate template families", () => {
    const [firstTemplate, secondTemplate, ...remainingTemplates] = createPolicyTemplates();
    const duplicatedTemplates = [
      firstTemplate!,
      {
        ...secondTemplate!,
        family: firstTemplate!.family,
      },
      ...remainingTemplates,
    ];

    expect(() =>
      GovernancePolicyRecordSchema.parse({
        ...createPolicyRecordInput(),
        policyTemplates: duplicatedTemplates,
      }),
    ).toThrow(/repeat decision families/i);
  });

  it("rejects governance policies with duplicate binding families", () => {
    const [firstBinding, secondBinding, ...remainingBindings] = createDecisionBindings();
    const duplicatedBindings = [
      firstBinding!,
      {
        ...secondBinding!,
        family: firstBinding!.family,
      },
      ...remainingBindings,
    ];

    expect(() =>
      GovernancePolicyRecordSchema.parse({
        ...createPolicyRecordInput(),
        decisionBindings: duplicatedBindings,
      }),
    ).toThrow(/decisionBindings must not repeat decision families/i);
  });

  it("rejects governance policies when a binding family mismatches its template family", () => {
    const [firstBinding, secondBinding, ...remainingBindings] = createDecisionBindings();
    const mismatchedBindings = [
      firstBinding!,
      {
        ...secondBinding!,
        family: "emergency" as const,
      },
      ...remainingBindings,
    ];

    expect(() =>
      GovernancePolicyRecordSchema.parse({
        ...createPolicyRecordInput(),
        decisionBindings: mismatchedBindings,
      }),
    ).toThrow(/family must match the referenced policy template family/i);
  });
});
