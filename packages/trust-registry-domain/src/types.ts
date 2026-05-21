import { z } from "zod";

import { DidSchema, HashHexSchema, ScopedIdentifierSchema, UriSchema } from "./ids.js";
import {
  assertAscendingTimestamps,
  LifecycleStatusSchema,
} from "./lifecycle.js";

const NonEmptyStringSchema = z.string().trim().min(1);
const TimestampSchema = z.string().datetime({ offset: true });
const KeyReferenceSchema = z
  .string()
  .regex(/^did:[^#]+#[A-Za-z0-9:._-]+$/, "Key references must be DID fragments");

export const RegistryControlKeyAlgorithmSchema = z.enum([
  "jubjub-schnorr",
  "secp256k1",
  "secp256r1",
  "ed25519",
]);

export const ParticipantTypeSchema = z.enum([
  "root-governor",
  "registry-maintainer",
  "authority",
  "issuer",
  "verifier",
  "auditor",
]);

export const AuthorizationRoleSchema = z.enum([
  "issuer",
  "verifier",
  "maintainer",
  "authority",
  "auditor",
]);

export const ResourceTypeSchema = z.enum([
  "credential-family",
  "schema",
  "schema-version",
  "credential-definition",
  "status-method-requirement",
  "request-profile",
  "allowed-attribute-set",
  "allowed-predicate-set",
  "disclosure-level",
  "presentation-purpose",
  "recognized-scope",
]);

export const TrustLevelSchema = NonEmptyStringSchema;

export const MaintainerSignatureSchema = z.object({
  keyId: KeyReferenceSchema,
  algorithm: RegistryControlKeyAlgorithmSchema,
  signature: NonEmptyStringSchema,
});

const BaseRecordSchema = z.object({
  status: LifecycleStatusSchema,
  lifecycleEventRoot: HashHexSchema,
});

export const RegistryRecordSchema = BaseRecordSchema.extend({
  registryId: ScopedIdentifierSchema,
  registryDid: DidSchema,
  name: NonEmptyStringSchema,
  description: NonEmptyStringSchema,
  controllerDids: z.array(DidSchema).min(1),
  maintainerDids: z.array(DidSchema).min(1),
  policyUri: UriSchema,
  serviceEndpoint: UriSchema,
  logoUri: UriSchema,
  createdAt: TimestampSchema,
  updatedAt: TimestampSchema,
  suspendedAt: TimestampSchema.optional(),
  revokedAt: TimestampSchema.optional(),
  supersededAt: TimestampSchema.optional(),
  archivedAt: TimestampSchema.optional(),
}).superRefine((record, ctx) => {
  refineEffectiveWindow(ctx, record.createdAt, undefined, "createdAt", undefined);
  refineAscendingLifecycle(
    ctx,
    [
      ["createdAt", record.createdAt],
      ["updatedAt", record.updatedAt],
      ["suspendedAt", record.suspendedAt],
      ["revokedAt", record.revokedAt],
      ["supersededAt", record.supersededAt],
      ["archivedAt", record.archivedAt],
    ],
  );
});

export const GovernancePolicyRecordSchema = BaseRecordSchema.extend({
  policyId: ScopedIdentifierSchema,
  registryId: ScopedIdentifierSchema,
  version: NonEmptyStringSchema,
  policyUri: UriSchema,
  decisionRules: z.array(NonEmptyStringSchema).min(1),
  disputeRules: z.array(NonEmptyStringSchema).min(1),
  retentionRules: z.array(NonEmptyStringSchema).min(1),
  emergencyRules: z.array(NonEmptyStringSchema).min(1),
  effectiveFrom: TimestampSchema,
  effectiveUntil: TimestampSchema.optional(),
  supersededAt: TimestampSchema.optional(),
  archivedAt: TimestampSchema.optional(),
}).superRefine((record, ctx) => {
  refineEffectiveWindow(
    ctx,
    record.effectiveFrom,
    record.effectiveUntil,
    "effectiveFrom",
    "effectiveUntil",
  );
  refineAscendingLifecycle(
    ctx,
    [
      ["effectiveFrom", record.effectiveFrom],
      ["effectiveUntil", record.effectiveUntil],
      ["supersededAt", record.supersededAt],
      ["archivedAt", record.archivedAt],
    ],
  );
});

export const ParticipantRecordSchema = BaseRecordSchema.extend({
  participantId: ScopedIdentifierSchema,
  participantDid: DidSchema,
  participantType: ParticipantTypeSchema,
  legalName: NonEmptyStringSchema,
  serviceEndpoint: UriSchema,
  currentKeyRefs: z.array(KeyReferenceSchema).min(1),
  historicalKeyRefs: z.array(KeyReferenceSchema),
  metadataUri: UriSchema,
  effectiveFrom: TimestampSchema,
  effectiveUntil: TimestampSchema.optional(),
  suspendedAt: TimestampSchema.optional(),
  revokedAt: TimestampSchema.optional(),
  supersededAt: TimestampSchema.optional(),
  archivedAt: TimestampSchema.optional(),
}).superRefine((record, ctx) => {
  refineEffectiveWindow(
    ctx,
    record.effectiveFrom,
    record.effectiveUntil,
    "effectiveFrom",
    "effectiveUntil",
  );
  refineAscendingLifecycle(
    ctx,
    [
      ["effectiveFrom", record.effectiveFrom],
      ["effectiveUntil", record.effectiveUntil],
      ["suspendedAt", record.suspendedAt],
      ["revokedAt", record.revokedAt],
      ["supersededAt", record.supersededAt],
      ["archivedAt", record.archivedAt],
    ],
  );
});

export const AuthorizationRecordSchema = BaseRecordSchema.extend({
  authorizationId: ScopedIdentifierSchema,
  registryId: ScopedIdentifierSchema,
  subjectDid: DidSchema,
  role: AuthorizationRoleSchema,
  resourceType: ResourceTypeSchema,
  resourceId: ScopedIdentifierSchema,
  policyId: ScopedIdentifierSchema,
  trustLevel: TrustLevelSchema,
  proposedAt: TimestampSchema,
  authorizedAt: TimestampSchema.optional(),
  activeFrom: TimestampSchema.optional(),
  issuedAt: TimestampSchema.optional(),
  effectiveUntil: TimestampSchema.optional(),
  suspendedAt: TimestampSchema.optional(),
  revokedAt: TimestampSchema.optional(),
  supersededAt: TimestampSchema.optional(),
  archivedAt: TimestampSchema.optional(),
  evidenceHash: HashHexSchema,
}).superRefine((record, ctx) => {
  if (record.status !== "proposed" && record.authorizedAt === undefined) {
    ctx.addIssue({
      code: "custom",
      message: "authorizedAt is required once an authorization leaves proposed state",
      path: ["authorizedAt"],
    });
  }
  if (
    ["active", "suspended", "revoked", "superseded", "archived"].includes(record.status) &&
    record.activeFrom === undefined
  ) {
    ctx.addIssue({
      code: "custom",
      message: "activeFrom is required for active or historical authorizations",
      path: ["activeFrom"],
    });
  }
  refineEffectiveWindow(
    ctx,
    record.activeFrom,
    record.effectiveUntil,
    "activeFrom",
    "effectiveUntil",
  );
  refineAscendingLifecycle(
    ctx,
    [
      ["proposedAt", record.proposedAt],
      ["authorizedAt", record.authorizedAt],
      ["activeFrom", record.activeFrom],
      ["issuedAt", record.issuedAt],
      ["effectiveUntil", record.effectiveUntil],
      ["suspendedAt", record.suspendedAt],
      ["revokedAt", record.revokedAt],
      ["supersededAt", record.supersededAt],
      ["archivedAt", record.archivedAt],
    ],
  );
});

export const RecognitionScopeSchema = z.object({
  resourceType: ResourceTypeSchema,
  resourceId: ScopedIdentifierSchema,
  context: z.record(z.string(), z.string()).optional(),
});

export const RecognitionRecordSchema = BaseRecordSchema.extend({
  recognitionId: ScopedIdentifierSchema,
  registryId: ScopedIdentifierSchema,
  recognizedAuthorityDid: DidSchema,
  recognizedRegistryId: ScopedIdentifierSchema,
  scope: RecognitionScopeSchema,
  policyId: ScopedIdentifierSchema,
  trustLevel: TrustLevelSchema,
  effectiveFrom: TimestampSchema.optional(),
  effectiveUntil: TimestampSchema.optional(),
  evidenceHash: HashHexSchema,
  proposedAt: TimestampSchema,
  authorizedAt: TimestampSchema.optional(),
  suspendedAt: TimestampSchema.optional(),
  revokedAt: TimestampSchema.optional(),
  supersededAt: TimestampSchema.optional(),
  archivedAt: TimestampSchema.optional(),
}).superRefine((record, ctx) => {
  if (record.status !== "proposed" && record.authorizedAt === undefined) {
    ctx.addIssue({
      code: "custom",
      message: "authorizedAt is required once a recognition leaves proposed state",
      path: ["authorizedAt"],
    });
  }
  if (
    ["active", "suspended", "revoked", "superseded", "archived"].includes(record.status)
    && record.effectiveFrom === undefined
  ) {
    ctx.addIssue({
      code: "custom",
      message: "effectiveFrom is required for active or historical recognitions",
      path: ["effectiveFrom"],
    });
  }
  refineEffectiveWindow(
    ctx,
    record.effectiveFrom,
    record.effectiveUntil,
    "effectiveFrom",
    "effectiveUntil",
  );
  refineAscendingLifecycle(
    ctx,
    [
      ["proposedAt", record.proposedAt],
      ["authorizedAt", record.authorizedAt],
      ["effectiveFrom", record.effectiveFrom],
      ["effectiveUntil", record.effectiveUntil],
      ["suspendedAt", record.suspendedAt],
      ["revokedAt", record.revokedAt],
      ["supersededAt", record.supersededAt],
      ["archivedAt", record.archivedAt],
    ],
  );
});

export const EpochCommitmentSchema = z
  .object({
    epochId: ScopedIdentifierSchema,
    registryId: ScopedIdentifierSchema,
    stateRoot: HashHexSchema,
    eventRoot: HashHexSchema,
    policyRoot: HashHexSchema,
    validFrom: TimestampSchema,
    validUntil: TimestampSchema,
    maintainerSignatures: z.array(MaintainerSignatureSchema).min(1),
  })
  .superRefine((record, ctx) => {
    refineEffectiveWindow(
      ctx,
      record.validFrom,
      record.validUntil,
      "validFrom",
      "validUntil",
    );
  });

export type RegistryRecord = z.infer<typeof RegistryRecordSchema>;
export type GovernancePolicyRecord = z.infer<typeof GovernancePolicyRecordSchema>;
export type ParticipantRecord = z.infer<typeof ParticipantRecordSchema>;
export type AuthorizationRecord = z.infer<typeof AuthorizationRecordSchema>;
export type RecognitionRecord = z.infer<typeof RecognitionRecordSchema>;
export type EpochCommitment = z.infer<typeof EpochCommitmentSchema>;
export type MaintainerSignature = z.infer<typeof MaintainerSignatureSchema>;

function refineEffectiveWindow(
  ctx: z.RefinementCtx,
  fromValue: string | undefined,
  untilValue: string | undefined,
  fromField: string,
  untilField: string | undefined,
): void {
  if (fromValue === undefined || untilValue === undefined) {
    return;
  }

  if (Date.parse(fromValue) > Date.parse(untilValue)) {
    ctx.addIssue({
      code: "custom",
      message: `${untilField ?? "until"} must not be earlier than ${fromField}`,
      path: untilField === undefined ? undefined : [untilField],
    });
  }
}

function refineAscendingLifecycle(
  ctx: z.RefinementCtx,
  entries: Array<readonly [field: string, value: string | undefined]>,
): void {
  try {
    assertAscendingTimestamps(entries);
  } catch (error) {
    ctx.addIssue({
      code: "custom",
      message: error instanceof Error ? error.message : "Invalid lifecycle chronology",
    });
  }
}
