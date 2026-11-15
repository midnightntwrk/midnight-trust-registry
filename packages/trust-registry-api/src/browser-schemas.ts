import { RecognitionRecordSchema } from "@midnight-ntwrk/trust-registry-domain/browser";
import { z } from "zod";

const NonEmptyStringSchema = z.string().trim().min(1);

export const TrustRegistryApiResolveRecognitionRequestSchema = z.object({
  recognizedAuthorityDid: NonEmptyStringSchema,
  recognizedRegistryId: NonEmptyStringSchema.optional(),
  scopeResourceType: RecognitionRecordSchema.shape.scope.shape.resourceType.optional(),
  scopeResourceId: NonEmptyStringSchema,
  scopeContext: RecognitionRecordSchema.shape.scope.shape.context.optional(),
  trustLevel: NonEmptyStringSchema.optional(),
});

export const TrustRegistryApiEvaluateRecognitionRequestSchema =
  TrustRegistryApiResolveRecognitionRequestSchema.extend({
    at: z.string().datetime({ offset: true }),
  });

export const PendingApplicationSummarySchema = z.strictObject({
  applicationId: z.string().trim().min(1).max(256),
  authorizationId: z.string().trim().min(1).max(256),
  role: z.enum(["issuer", "verifier", "auditor", "maintainer"]),
  status: z.enum(["pending", "archived"]),
  createdAt: z.string().datetime({ offset: true }),
});
export const PendingApplicationListResponseSchema = z.strictObject({
  entries: z.array(PendingApplicationSummarySchema),
});
