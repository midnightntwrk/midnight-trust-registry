import { z } from "zod";

import {
  DidSchema,
  HashHexSchema,
  ScopedIdentifierSchema,
  UriSchema,
  sha256Hex,
} from "./ids.js";
import {
  AuthorizationRecordSchema,
  EpochCommitmentSchema,
  GovernancePolicyRecordSchema,
  RecognitionRecordSchema,
} from "./types.js";

const TimestampSchema = z.string().datetime({ offset: true });

const normalizeOptional = <T>(value: T | undefined): T | null => value ?? null;

const sortStringRecord = (
  value: Record<string, string> | undefined,
): Record<string, string> | null => (
  value === undefined
    ? null
    : Object.fromEntries(
        Object.entries(value).sort(([left], [right]) => left.localeCompare(right)),
      )
);

export const computeAuthorizationStatementLeafHash = (
  authorization: z.infer<typeof AuthorizationRecordSchema>,
): string =>
  sha256Hex(
    JSON.stringify({
      recordType: "authorization",
      authorizationId: authorization.authorizationId,
      registryId: authorization.registryId,
      subjectDid: authorization.subjectDid,
      role: authorization.role,
      resourceType: authorization.resourceType,
      resourceId: authorization.resourceId,
      policyId: authorization.policyId,
      trustLevel: authorization.trustLevel,
      status: authorization.status,
      lifecycleEventRoot: authorization.lifecycleEventRoot,
      proposedAt: authorization.proposedAt,
      authorizedAt: normalizeOptional(authorization.authorizedAt),
      activeFrom: normalizeOptional(authorization.activeFrom),
      issuedAt: normalizeOptional(authorization.issuedAt),
      effectiveUntil: normalizeOptional(authorization.effectiveUntil),
      suspendedAt: normalizeOptional(authorization.suspendedAt),
      revokedAt: normalizeOptional(authorization.revokedAt),
      supersededAt: normalizeOptional(authorization.supersededAt),
      archivedAt: normalizeOptional(authorization.archivedAt),
      evidenceHash: authorization.evidenceHash,
    }),
  );

export const computeRecognitionStatementLeafHash = (
  recognition: z.infer<typeof RecognitionRecordSchema>,
): string =>
  sha256Hex(
    JSON.stringify({
      recordType: "recognition",
      recognitionId: recognition.recognitionId,
      registryId: recognition.registryId,
      recognizedAuthorityDid: recognition.recognizedAuthorityDid,
      recognizedRegistryId: recognition.recognizedRegistryId,
      scope: {
        resourceType: recognition.scope.resourceType,
        resourceId: recognition.scope.resourceId,
        context: sortStringRecord(recognition.scope.context),
      },
      policyId: recognition.policyId,
      trustLevel: recognition.trustLevel,
      status: recognition.status,
      lifecycleEventRoot: recognition.lifecycleEventRoot,
      proposedAt: recognition.proposedAt,
      authorizedAt: normalizeOptional(recognition.authorizedAt),
      effectiveFrom: normalizeOptional(recognition.effectiveFrom),
      effectiveUntil: normalizeOptional(recognition.effectiveUntil),
      suspendedAt: normalizeOptional(recognition.suspendedAt),
      revokedAt: normalizeOptional(recognition.revokedAt),
      supersededAt: normalizeOptional(recognition.supersededAt),
      archivedAt: normalizeOptional(recognition.archivedAt),
      evidenceHash: recognition.evidenceHash,
    }),
  );

export const computeRegistryStatementLeafHash = (input: {
  registryId: string;
  statementId: string;
  statementStatus: string;
  lifecycleEventRoot: string;
}): string =>
  sha256Hex(
    JSON.stringify({
      recordType: "registry-statement",
      registryId: input.registryId,
      statementId: input.statementId,
      statementStatus: input.statementStatus,
      lifecycleEventRoot: input.lifecycleEventRoot,
    }),
  );

export const computeMerkleNodeHash = (
  left: string,
  right: string,
): string =>
  sha256Hex(
    JSON.stringify({
      left,
      right,
    }),
  );

export const computeMerkleRootFromProof = (
  leafHash: string,
  path: readonly string[],
  leafIndex: number,
): string => {
  let computed = leafHash;
  let currentIndex = leafIndex;

  for (const siblingHash of path) {
    computed =
      currentIndex % 2 === 0
        ? computeMerkleNodeHash(computed, siblingHash)
        : computeMerkleNodeHash(siblingHash, computed);
    currentIndex = Math.floor(currentIndex / 2);
  }

  return computed;
};

export const computeSingleStatementStateRoot = (
  leafHash: string,
  eventRoot: string,
): string =>
  computeMerkleRootFromProof(leafHash, [eventRoot], 0);

export const InclusionProofSchema = z.object({
  proofType: z.enum(["signed-statement", "merkle-inclusion", "event-membership"]),
  root: HashHexSchema,
  leafHash: HashHexSchema,
  path: z.array(HashHexSchema).min(1),
  leafIndex: z.number().int().nonnegative(),
});

export const TrustRegistryEvidenceBundleSchema = z
  .object({
    bundleId: ScopedIdentifierSchema,
    generatedAt: TimestampSchema,
    registryId: ScopedIdentifierSchema,
    subjectDid: DidSchema,
    policy: GovernancePolicyRecordSchema,
    epoch: EpochCommitmentSchema,
    inclusionProof: InclusionProofSchema,
    authorization: AuthorizationRecordSchema.optional(),
    recognition: RecognitionRecordSchema.optional(),
    referencedStatusRegistryId: ScopedIdentifierSchema.optional(),
    referencedStatusPolicyUri: UriSchema.optional(),
  })
  .superRefine((bundle, ctx) => {
    if (bundle.authorization === undefined && bundle.recognition === undefined) {
      ctx.addIssue({
        code: "custom",
        message: "Evidence bundles must include either an authorization or a recognition record",
      });
    }

    if (bundle.authorization !== undefined && bundle.authorization.subjectDid !== bundle.subjectDid) {
      ctx.addIssue({
        code: "custom",
        message: "authorization.subjectDid must match subjectDid",
        path: ["authorization", "subjectDid"],
      });
    }

    if (
      bundle.recognition !== undefined &&
      bundle.recognition.recognizedAuthorityDid !== bundle.subjectDid
    ) {
      ctx.addIssue({
        code: "custom",
        message: "recognition.recognizedAuthorityDid must match subjectDid",
        path: ["recognition", "recognizedAuthorityDid"],
      });
    }
  });

export const TrustRegistryEvidenceBundleJsonSchema = {
  $schema: "https://json-schema.org/draft/2020-12/schema",
  $id: "https://midnight.network/schemas/trust-registry/evidence-bundle-v1.json",
  title: "TrustRegistryEvidenceBundle",
  type: "object",
  required: [
    "bundleId",
    "generatedAt",
    "registryId",
    "subjectDid",
    "policy",
    "epoch",
    "inclusionProof",
  ],
  properties: {
    bundleId: {
      type: "string",
    },
    generatedAt: {
      type: "string",
      format: "date-time",
    },
    registryId: {
      type: "string",
    },
    subjectDid: {
      type: "string",
    },
    policy: {
      type: "object",
      description: "Policy snapshot used to interpret trust level and decision rules.",
      required: [
        "policyId",
        "registryId",
        "version",
        "policyUri",
        "status",
        "effectiveFrom",
        "policyTemplates",
        "decisionBindings",
      ],
      properties: {
        policyId: { type: "string" },
        registryId: { type: "string" },
        version: { type: "string" },
        policyUri: { type: "string", format: "uri" },
        status: { type: "string" },
        effectiveFrom: { type: "string", format: "date-time" },
        effectiveUntil: { type: "string", format: "date-time" },
        policyTemplates: {
          type: "array",
          minItems: 1,
          items: {
            type: "object",
            required: [
              "templateId",
              "family",
              "name",
              "description",
              "requiredMaintainerThreshold",
              "applicableRoles",
              "applicableActionKinds",
              "evidenceRules",
            ],
            properties: {
              templateId: { type: "string" },
              family: {
                enum: ["maintainer", "member", "emergency", "archival", "auditor"],
              },
              name: { type: "string" },
              description: { type: "string" },
              requiredMaintainerThreshold: { type: "integer", minimum: 1 },
              applicableRoles: {
                type: "array",
                minItems: 1,
                items: {
                  enum: ["issuer", "verifier", "maintainer", "authority", "auditor"],
                },
              },
              applicableActionKinds: {
                type: "array",
                minItems: 1,
                items: { type: "string" },
              },
              evidenceRules: {
                type: "array",
                minItems: 1,
                items: { type: "string" },
              },
            },
          },
        },
        decisionBindings: {
          type: "array",
          minItems: 1,
          items: {
            type: "object",
            required: ["bindingId", "family", "templateId", "actionScopes"],
            properties: {
              bindingId: { type: "string" },
              family: {
                enum: ["maintainer", "member", "emergency", "archival", "auditor"],
              },
              templateId: { type: "string" },
              actionScopes: {
                type: "array",
                minItems: 1,
                items: { type: "string" },
              },
            },
          },
        },
      },
    },
    epoch: {
      type: "object",
      description: "Epoch commitment anchoring the state view used by the verifier.",
      required: [
        "epochId",
        "registryId",
        "stateRoot",
        "eventRoot",
        "policyRoot",
        "validFrom",
        "validUntil",
        "maintainerSignatures",
      ],
      properties: {
        epochId: { type: "string" },
        registryId: { type: "string" },
        stateRoot: { type: "string" },
        eventRoot: { type: "string" },
        policyRoot: { type: "string" },
        validFrom: { type: "string", format: "date-time" },
        validUntil: { type: "string", format: "date-time" },
        maintainerSignatures: {
          type: "array",
          minItems: 1,
          items: {
            type: "object",
            required: ["keyId", "algorithm", "signature"],
            properties: {
              keyId: { type: "string" },
              algorithm: {
                enum: ["jubjub-schnorr", "secp256k1", "secp256r1", "ed25519"],
              },
              signature: { type: "string" },
            },
          },
        },
      },
    },
    inclusionProof: {
      type: "object",
      description: "Inclusion proof or signed statement proving membership in the published epoch state.",
      required: ["proofType", "root", "leafHash", "path", "leafIndex"],
      properties: {
        proofType: {
          enum: ["signed-statement", "merkle-inclusion", "event-membership"],
        },
        root: { type: "string" },
        leafHash: { type: "string" },
        path: {
          type: "array",
          minItems: 1,
          items: { type: "string" },
        },
        leafIndex: {
          type: "integer",
          minimum: 0,
        },
      },
    },
    authorization: {
      type: "object",
      description:
        "Issuer or verifier authorization evidence, including scoped resource permission and trust level.",
      required: [
        "authorizationId",
        "registryId",
        "subjectDid",
        "role",
        "resourceType",
        "resourceId",
        "policyId",
        "trustLevel",
        "status",
        "proposedAt",
        "evidenceHash",
      ],
      properties: {
        authorizationId: { type: "string" },
        registryId: { type: "string" },
        subjectDid: { type: "string" },
        role: { enum: ["issuer", "verifier", "maintainer", "authority", "auditor"] },
        resourceType: { type: "string" },
        resourceId: { type: "string" },
        policyId: { type: "string" },
        trustLevel: { type: "string" },
        status: { type: "string" },
        proposedAt: { type: "string", format: "date-time" },
        authorizedAt: { type: "string", format: "date-time" },
        activeFrom: { type: "string", format: "date-time" },
        effectiveUntil: { type: "string", format: "date-time" },
        evidenceHash: { type: "string" },
      },
    },
    recognition: {
      type: "object",
      description:
        "Recognition evidence showing that an external authority or registry is accepted for a scoped domain.",
      required: [
        "recognitionId",
        "registryId",
        "recognizedAuthorityDid",
        "recognizedRegistryId",
        "scope",
        "policyId",
        "trustLevel",
        "effectiveFrom",
        "evidenceHash",
        "status",
        "proposedAt",
      ],
      properties: {
        recognitionId: { type: "string" },
        registryId: { type: "string" },
        recognizedAuthorityDid: { type: "string" },
        recognizedRegistryId: { type: "string" },
        scope: {
          type: "object",
          required: ["resourceType", "resourceId"],
          properties: {
            resourceType: { type: "string" },
            resourceId: { type: "string" },
          },
        },
        policyId: { type: "string" },
        trustLevel: { type: "string" },
        effectiveFrom: { type: "string", format: "date-time" },
        effectiveUntil: { type: "string", format: "date-time" },
        evidenceHash: { type: "string" },
        status: { type: "string" },
        proposedAt: { type: "string", format: "date-time" },
      },
    },
    referencedStatusRegistryId: {
      type: "string",
      description:
        "Optional VC status-registry reference when the trust decision is paired with credential-status evidence.",
    },
    referencedStatusPolicyUri: {
      type: "string",
      format: "uri",
    },
  },
  anyOf: [{ required: ["authorization"] }, { required: ["recognition"] }],
} as const;

export type TrustRegistryEvidenceBundle = z.infer<typeof TrustRegistryEvidenceBundleSchema>;
export type InclusionProof = z.infer<typeof InclusionProofSchema>;
