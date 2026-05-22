import { z } from "zod";

import {
  TrustRegistryAuthorizationSnapshotEntrySchema,
  TrustRegistryRecognitionSnapshotEntrySchema,
} from "@midnight-ntwrk/trust-registry-cli";
import {
  AuthorizationRecordSchema,
  EpochCommitmentSchema,
  RecognitionRecordSchema,
  RegistryRecordSchema,
  TrustRegistryEvidenceBundleSchema,
} from "@midnight-ntwrk/trust-registry-domain";

const NonEmptyStringSchema = z.string().trim().min(1);
const TimestampSchema = z.string().datetime({ offset: true });

export const TrustRegistryApiAuthorizationRoleSchema = z.enum([
  "issuer",
  "verifier",
]);

export const TrustRegistryApiProblemDetailsSchema = z.object({
  type: z.string().url(),
  title: NonEmptyStringSchema,
  status: z.number().int().positive(),
  detail: NonEmptyStringSchema.optional(),
  instance: NonEmptyStringSchema.optional(),
}).catchall(z.unknown());

export const TrustRegistryApiHealthResponseSchema = z.object({
  status: z.literal("ok"),
  sourceMode: z.enum(["snapshot", "workspace", "memory"]),
  generatedAt: TimestampSchema,
  registryId: NonEmptyStringSchema,
});

export const TrustRegistryApiSummarySchema = z.object({
  snapshotVersion: z.literal("1"),
  generatedAt: TimestampSchema,
  registryLabel: NonEmptyStringSchema,
  registryId: NonEmptyStringSchema,
  registryDid: NonEmptyStringSchema,
  policyId: NonEmptyStringSchema,
  currentEpochId: NonEmptyStringSchema,
  epochCount: z.number().int().min(1),
  issuerCounts: z.record(
    AuthorizationRecordSchema.shape.status,
    z.number().int().nonnegative(),
  ),
  verifierCounts: z.record(
    AuthorizationRecordSchema.shape.status,
    z.number().int().nonnegative(),
  ),
  recognitionCounts: z.record(
    RecognitionRecordSchema.shape.status,
    z.number().int().nonnegative(),
  ),
});

export const TrustRegistryApiAuthorizationListQuerySchema = z.object({
  status: AuthorizationRecordSchema.shape.status.optional(),
});

export const TrustRegistryApiAuthorizationListResponseSchema = z.object({
  role: TrustRegistryApiAuthorizationRoleSchema,
  total: z.number().int().nonnegative(),
  entries: z.array(TrustRegistryAuthorizationSnapshotEntrySchema),
});

export const TrustRegistryApiResolveAuthorizationRequestSchema = z.object({
  role: TrustRegistryApiAuthorizationRoleSchema,
  subjectDid: NonEmptyStringSchema,
  resourceId: NonEmptyStringSchema,
  resourceType: AuthorizationRecordSchema.shape.resourceType.optional(),
  trustLevel: NonEmptyStringSchema.optional(),
});

export const TrustRegistryApiRecognitionListQuerySchema = z.object({
  status: RecognitionRecordSchema.shape.status.optional(),
});

export const TrustRegistryApiRecognitionListResponseSchema = z.object({
  total: z.number().int().nonnegative(),
  entries: z.array(TrustRegistryRecognitionSnapshotEntrySchema),
});

export const TrustRegistryApiResolveRecognitionRequestSchema = z.object({
  recognizedAuthorityDid: NonEmptyStringSchema,
  recognizedRegistryId: NonEmptyStringSchema.optional(),
  scopeResourceType: RecognitionRecordSchema.shape.scope.shape.resourceType.optional(),
  scopeResourceId: NonEmptyStringSchema,
  trustLevel: NonEmptyStringSchema.optional(),
});

export const TrustRegistryApiRegistryResponseSchema = RegistryRecordSchema;
export const TrustRegistryApiEpochResponseSchema = EpochCommitmentSchema;
export const TrustRegistryApiAuthorizationResponseSchema =
  TrustRegistryAuthorizationSnapshotEntrySchema;
export const TrustRegistryApiRecognitionResponseSchema =
  TrustRegistryRecognitionSnapshotEntrySchema;
export const TrustRegistryApiEvidenceResponseSchema =
  TrustRegistryEvidenceBundleSchema;

export type TrustRegistryApiAuthorizationRole = z.infer<
  typeof TrustRegistryApiAuthorizationRoleSchema
>;
export type TrustRegistryApiProblemDetails = z.infer<
  typeof TrustRegistryApiProblemDetailsSchema
>;
export type TrustRegistryApiHealthResponse = z.infer<
  typeof TrustRegistryApiHealthResponseSchema
>;
export type TrustRegistryApiSummary = z.infer<
  typeof TrustRegistryApiSummarySchema
>;
export type TrustRegistryApiAuthorizationListQuery = z.infer<
  typeof TrustRegistryApiAuthorizationListQuerySchema
>;
export type TrustRegistryApiAuthorizationListResponse = z.infer<
  typeof TrustRegistryApiAuthorizationListResponseSchema
>;
export type TrustRegistryApiResolveAuthorizationRequest = z.infer<
  typeof TrustRegistryApiResolveAuthorizationRequestSchema
>;
export type TrustRegistryApiRecognitionListQuery = z.infer<
  typeof TrustRegistryApiRecognitionListQuerySchema
>;
export type TrustRegistryApiRecognitionListResponse = z.infer<
  typeof TrustRegistryApiRecognitionListResponseSchema
>;
export type TrustRegistryApiResolveRecognitionRequest = z.infer<
  typeof TrustRegistryApiResolveRecognitionRequestSchema
>;
