import { z } from "zod";
import type { JWK } from "jose";

import {
  AuthorizationRecordSchema,
  RecognitionRecordSchema,
  RegistryRecordSchema,
  TrustRegistryEvidenceBundleSchema,
} from "@midnight-ntwrk/trust-registry-domain";

const NonEmptyStringSchema = z.string().trim().min(1);
const UnixTimestampSchema = z.number().int().nonnegative();
const JwkSchema = z.custom<JWK>((value) => typeof value === "object" && value !== null);
const JwksSchema = z.object({
  keys: z.array(JwkSchema).min(1),
});

export const FederationEntityMetadataSchema = z.object({
  organization_name: NonEmptyStringSchema.optional(),
  organization_uri: z.string().url().optional(),
  contacts: z.array(NonEmptyStringSchema).optional(),
  federation_fetch_endpoint: z.string().url().optional(),
  homepage_uri: z.string().url().optional(),
  policy_uri: z.string().url().optional(),
  logo_uri: z.string().url().optional(),
}).catchall(z.unknown());

export const MidnightTrustRegistryMetadataSchema = z.discriminatedUnion(
  "statement_kind",
  [
    z.object({
      statement_kind: z.literal("registry"),
      registry_id: NonEmptyStringSchema,
      registry_did: NonEmptyStringSchema,
      policy_uri: z.string().url(),
      status: RegistryRecordSchema.shape.status,
      controller_dids: z.array(NonEmptyStringSchema),
      maintainer_dids: z.array(NonEmptyStringSchema),
    }),
    z.object({
      statement_kind: z.literal("registry-publication"),
      registry_id: NonEmptyStringSchema,
      registry_did: NonEmptyStringSchema,
      policy_id: NonEmptyStringSchema,
      policy_version: NonEmptyStringSchema,
      policy_uri: z.string().url(),
      status: RegistryRecordSchema.shape.status,
      authorization_bundle: TrustRegistryEvidenceBundleSchema.optional(),
      recognition_bundle: TrustRegistryEvidenceBundleSchema.optional(),
    }),
    z.object({
      statement_kind: z.literal("authorization"),
      registry_id: NonEmptyStringSchema,
      policy_id: NonEmptyStringSchema,
      trust_level: NonEmptyStringSchema,
      status: AuthorizationRecordSchema.shape.status,
      role: AuthorizationRecordSchema.shape.role,
      resource_type: AuthorizationRecordSchema.shape.resourceType,
      resource_id: NonEmptyStringSchema,
      referenced_status_registry_id: NonEmptyStringSchema.optional(),
    }),
    z.object({
      statement_kind: z.literal("recognition"),
      registry_id: NonEmptyStringSchema,
      policy_id: NonEmptyStringSchema,
      trust_level: NonEmptyStringSchema,
      status: RecognitionRecordSchema.shape.status,
      recognized_registry_id: NonEmptyStringSchema,
      scope_resource_type: NonEmptyStringSchema,
      scope_resource_id: NonEmptyStringSchema,
    }),
  ],
);

export const OpenIdFederationMetadataSchema = z.object({
  federation_entity: FederationEntityMetadataSchema.optional(),
  midnight_trust_registry: MidnightTrustRegistryMetadataSchema.optional(),
}).catchall(z.unknown());

export const EntityStatementPayloadSchema = z.object({
  iss: NonEmptyStringSchema,
  sub: NonEmptyStringSchema,
  iat: UnixTimestampSchema,
  exp: UnixTimestampSchema,
  jwks: JwksSchema,
  metadata: OpenIdFederationMetadataSchema.optional(),
  authority_hints: z.array(NonEmptyStringSchema).optional(),
  trust_anchor_hints: z.array(NonEmptyStringSchema).optional(),
  source_endpoint: z.string().url().optional(),
}).catchall(z.unknown());

export const SignedEntityStatementSchema = z.string().trim().min(1);
export const SimpleTrustChainSchema = z.array(SignedEntityStatementSchema).min(3);
export const TrustMarkPayloadSchema = z.object({
  iss: NonEmptyStringSchema,
  sub: NonEmptyStringSchema,
  iat: UnixTimestampSchema,
  exp: UnixTimestampSchema.optional(),
  trust_mark_type: z.string().url(),
  ref: z.string().url().optional(),
  logo_uri: z.string().url().optional(),
  delegation: z.string().trim().min(1).optional(),
  midnight_trust_registry: MidnightTrustRegistryMetadataSchema.optional(),
}).catchall(z.unknown());
export const SignedTrustMarkSchema = z.string().trim().min(1);

export const FederationLeafConfigurationInputSchema = z.object({
  entityId: NonEmptyStringSchema,
  publicJwks: JwksSchema,
  authorityHints: z.array(NonEmptyStringSchema),
  organizationName: NonEmptyStringSchema.optional(),
  organizationUri: z.string().url().optional(),
  contacts: z.array(NonEmptyStringSchema).optional(),
  now: UnixTimestampSchema.optional(),
  expiresInSeconds: UnixTimestampSchema.optional(),
});

export const TrustRegistryEntityConfigurationInputSchema = z.object({
  registry: RegistryRecordSchema,
  publicJwks: JwksSchema,
  authorityHints: z.array(NonEmptyStringSchema).optional(),
  now: UnixTimestampSchema.optional(),
  expiresInSeconds: UnixTimestampSchema.optional(),
});

export const AuthorizationSubordinateStatementInputSchema = z.object({
  issuerEntityId: z.string().url(),
  sourceEndpoint: z.string().url(),
  subjectPublicJwks: JwksSchema,
  bundle: TrustRegistryEvidenceBundleSchema,
  now: UnixTimestampSchema.optional(),
  expiresInSeconds: UnixTimestampSchema.optional(),
});

export const RecognitionTrustMarkInputSchema = z.object({
  issuerEntityId: z.string().url(),
  bundle: TrustRegistryEvidenceBundleSchema,
  trustMarkType: z.string().url(),
  ref: z.string().url().optional(),
  logoUri: z.string().url().optional(),
  now: UnixTimestampSchema.optional(),
  expiresInSeconds: UnixTimestampSchema.optional(),
});

export type EntityStatementPayload = z.infer<typeof EntityStatementPayloadSchema>;
export type FederationLeafConfigurationInput = z.infer<
  typeof FederationLeafConfigurationInputSchema
>;
export type TrustRegistryEntityConfigurationInput = z.infer<
  typeof TrustRegistryEntityConfigurationInputSchema
>;
export type AuthorizationSubordinateStatementInput = z.infer<
  typeof AuthorizationSubordinateStatementInputSchema
>;
export type RecognitionTrustMarkInput = z.infer<
  typeof RecognitionTrustMarkInputSchema
>;
export type TrustMarkPayload = z.infer<typeof TrustMarkPayloadSchema>;
