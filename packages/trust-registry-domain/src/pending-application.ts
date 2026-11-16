import { z } from "zod";

import { GovernedResourceSchema } from "./application-evidence.js";
import { ApplicationChallengeBindingSchema, governedResourceInScope } from "./application-challenge-binding.js";
import { computeMutationPayloadCommitment } from "./canonical-json.js";
import { ScopedIdentifierSchema } from "./ids.js";
import { MutationIntentSchema, MutationIntentSignatureSchema } from "./mutation-intent.js";
import { AuthorizationScopeSchema, canonicalizeAuthorizationScope, computeAuthorizationScopeCommitment } from "./scope.js";

const CanonicalScopedIdentifierSchema = ScopedIdentifierSchema.refine(
  (value) => value === value.toLowerCase(),
  "Identifier must be canonical lowercase",
);

export const PendingApplicationPayloadSchema = z.strictObject({
  applicationId: CanonicalScopedIdentifierSchema,
  authorizationId: CanonicalScopedIdentifierSchema,
  scope: AuthorizationScopeSchema,
  governedResource: GovernedResourceSchema,
}).superRefine((payload, ctx) => {
  if (governedResourceInScope(payload.scope, payload.governedResource.type) !== payload.governedResource.id) {
    ctx.addIssue({ code: "custom", path: ["governedResource"], message: "Governed resource must match the exact application scope" });
  }
});

export type PendingApplicationPayload = z.infer<typeof PendingApplicationPayloadSchema>;

export const PendingApplicationSummarySchema = z.strictObject({
  applicationId: z.string().trim().min(1).max(256),
  authorizationId: z.string().trim().min(1).max(256),
  role: z.enum(["issuer", "verifier", "auditor", "maintainer"]),
  status: z.enum(["pending", "archived"]),
  createdAt: z.string().datetime({ offset: true }),
});
export const MAX_PENDING_APPLICATION_LIST_ITEMS = 10_000;
export const PendingApplicationListResponseSchema = z.strictObject({
  entries: z.array(PendingApplicationSummarySchema).max(MAX_PENDING_APPLICATION_LIST_ITEMS),
});
export type PendingApplicationSummary = z.infer<typeof PendingApplicationSummarySchema>;

export const PendingApplicationRecordSchema = z.strictObject({
  authorizationId: z.string().trim().min(1).max(256),
  binding: ApplicationChallengeBindingSchema,
  status: z.enum(["pending", "archived"]),
  createdAt: z.string().datetime({ offset: true }),
  archiveEventHash: z.string().regex(/^0x[0-9a-f]{64}$/u).optional(),
}).superRefine((record, context) => {
  if ((record.status === "archived") !== (record.archiveEventHash !== undefined)) {
    context.addIssue({ code: "custom", path: ["archiveEventHash"], message: "Archive event is required only for archived applications" });
  }
});

export type PendingApplicationRecord = z.infer<typeof PendingApplicationRecordSchema>;

export function pendingApplicationMutationPayload(input: PendingApplicationPayload): {
  applicationId: string;
  authorizationId: string;
  canonicalScope: string;
  governedResource: { type: string; id: string };
} {
  const payload = PendingApplicationPayloadSchema.parse(input);
  return {
    applicationId: payload.applicationId,
    authorizationId: payload.authorizationId,
    canonicalScope: canonicalizeAuthorizationScope(payload.scope),
    governedResource: payload.governedResource,
  };
}

export function computePendingApplicationPayloadCommitment(input: PendingApplicationPayload): string {
  return computeMutationPayloadCommitment(pendingApplicationMutationPayload(input));
}

export const SignedPendingApplicationSchema = PendingApplicationPayloadSchema.safeExtend({
  intent: MutationIntentSchema,
  signature: MutationIntentSignatureSchema,
}).superRefine((request, ctx) => {
  if (!PendingApplicationPayloadSchema.safeParse({
    applicationId: request.applicationId,
    authorizationId: request.authorizationId,
    scope: request.scope,
    governedResource: request.governedResource,
  }).success) return;
  if (request.intent.action !== "apply" || request.intent.target !== request.scope.role
    || request.intent.actorRole !== "applicant" || request.intent.targetId !== request.applicationId) {
    ctx.addIssue({ code: "custom", path: ["intent"], message: "Intent must apply for this exact role and application" });
  }
  if (request.intent.scopeCommitment !== computeAuthorizationScopeCommitment(request.scope)) {
    ctx.addIssue({ code: "custom", path: ["intent", "scopeCommitment"], message: "Intent scope commitment does not match application scope" });
  }
  if (request.intent.payloadCommitment !== computePendingApplicationPayloadCommitment({
    applicationId: request.applicationId,
    authorizationId: request.authorizationId,
    scope: request.scope,
    governedResource: request.governedResource,
  })) {
    ctx.addIssue({ code: "custom", path: ["intent", "payloadCommitment"], message: "Intent payload commitment does not match application" });
  }
  if (request.signature.keyId !== request.intent.actorKeyId) {
    ctx.addIssue({ code: "custom", path: ["signature", "keyId"], message: "Signature key does not match applicant intent" });
  }
});

export type SignedPendingApplication = z.infer<typeof SignedPendingApplicationSchema>;
