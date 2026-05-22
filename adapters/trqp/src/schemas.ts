import { z } from "zod";

import {
  RegistryRecordSchema,
  TrustRegistryEvidenceBundleSchema,
} from "@midnight-ntwrk/trust-registry-domain";

const NonEmptyStringSchema = z.string().trim().min(1);
const TimestampSchema = z.string().datetime({ offset: true });

export const TrqpContextSchema = z.object({
  time: TimestampSchema.optional(),
  locator: NonEmptyStringSchema.optional(),
  recognized_registry_id: NonEmptyStringSchema.optional(),
}).catchall(z.unknown());

export const TrqpAuthorizationRequestSchema = z.object({
  entity_id: NonEmptyStringSchema,
  authority_id: NonEmptyStringSchema,
  action: NonEmptyStringSchema,
  resource: NonEmptyStringSchema,
  context: TrqpContextSchema.optional(),
});

export const TrqpAuthorizationResponseSchema = z.object({
  entity_id: NonEmptyStringSchema,
  authority_id: NonEmptyStringSchema,
  action: NonEmptyStringSchema,
  resource: NonEmptyStringSchema,
  time_requested: TimestampSchema.optional(),
  time_evaluated: TimestampSchema,
  authorized: z.boolean(),
  message: NonEmptyStringSchema.optional(),
  context: TrqpContextSchema.optional(),
});

export const TrqpRecognitionRequestSchema = z.object({
  entity_id: NonEmptyStringSchema,
  authority_id: NonEmptyStringSchema,
  action: NonEmptyStringSchema,
  resource: NonEmptyStringSchema,
  context: TrqpContextSchema.optional(),
});

export const TrqpRecognitionResponseSchema = z.object({
  entity_id: NonEmptyStringSchema,
  authority_id: NonEmptyStringSchema,
  action: NonEmptyStringSchema,
  resource: NonEmptyStringSchema,
  time_requested: TimestampSchema.optional(),
  time_evaluated: TimestampSchema,
  recognized: z.boolean(),
  message: NonEmptyStringSchema.optional(),
  context: TrqpContextSchema.optional(),
});

export const TrqpProblemDetailsSchema = z.object({
  type: z.string().url(),
  title: NonEmptyStringSchema,
  status: z.number().int().positive(),
  detail: NonEmptyStringSchema.optional(),
  instance: NonEmptyStringSchema.optional(),
}).catchall(z.unknown());

export const TrqpRegistryMetadataResponseSchema = z.object({
  authority_id: NonEmptyStringSchema,
  registry_id: NonEmptyStringSchema,
  registry_did: NonEmptyStringSchema,
  name: NonEmptyStringSchema,
  description: NonEmptyStringSchema,
  status: RegistryRecordSchema.shape.status,
  policy_uri: z.string().url(),
  service_endpoint: z.string().url(),
  logo_uri: z.string().url().optional(),
  controller_dids: z.array(NonEmptyStringSchema),
  maintainer_dids: z.array(NonEmptyStringSchema),
  created_at: TimestampSchema,
  updated_at: TimestampSchema,
});

export const TrqpAuthorizationEvidenceResponseSchema =
  TrqpAuthorizationResponseSchema.extend({
    bundle: TrustRegistryEvidenceBundleSchema,
  });

export const TrqpRecognitionEvidenceResponseSchema =
  TrqpRecognitionResponseSchema.extend({
    bundle: TrustRegistryEvidenceBundleSchema,
  });

export type TrqpContext = z.infer<typeof TrqpContextSchema>;
export type TrqpAuthorizationRequest = z.infer<
  typeof TrqpAuthorizationRequestSchema
>;
export type TrqpAuthorizationResponse = z.infer<
  typeof TrqpAuthorizationResponseSchema
>;
export type TrqpRecognitionRequest = z.infer<
  typeof TrqpRecognitionRequestSchema
>;
export type TrqpRecognitionResponse = z.infer<
  typeof TrqpRecognitionResponseSchema
>;
export type TrqpProblemDetails = z.infer<typeof TrqpProblemDetailsSchema>;
export type TrqpRegistryMetadataResponse = z.infer<
  typeof TrqpRegistryMetadataResponseSchema
>;
export type TrqpAuthorizationEvidenceResponse = z.infer<
  typeof TrqpAuthorizationEvidenceResponseSchema
>;
export type TrqpRecognitionEvidenceResponse = z.infer<
  typeof TrqpRecognitionEvidenceResponseSchema
>;
