import { z } from "zod";

import { computeMutationPayloadCommitment } from "./canonical-json.js";
import { ScopedIdentifierSchema } from "./ids.js";
import { MutationIntentSchema, MutationIntentSignatureSchema } from "./mutation-intent.js";
import { AuditorScopeSchema, canonicalizeAuthorizationScope, computeAuthorizationScopeCommitment } from "./scope.js";

const ApplicationIdSchema = ScopedIdentifierSchema.refine(
  (value) => value === value.toLowerCase(),
  "Application ID must be canonical lowercase",
);

export const PendingAuditorApplicationPayloadSchema = z.strictObject({
  applicationId: ApplicationIdSchema,
  scope: AuditorScopeSchema,
});

export type PendingAuditorApplicationPayload = z.infer<typeof PendingAuditorApplicationPayloadSchema>;

export function pendingAuditorApplicationMutationPayload(input: PendingAuditorApplicationPayload): {
  applicationId: string;
  canonicalScope: string;
} {
  const payload = PendingAuditorApplicationPayloadSchema.parse(input);
  return {
    applicationId: payload.applicationId,
    canonicalScope: canonicalizeAuthorizationScope(payload.scope),
  };
}

export function computePendingAuditorApplicationPayloadCommitment(input: PendingAuditorApplicationPayload): string {
  return computeMutationPayloadCommitment(pendingAuditorApplicationMutationPayload(input));
}

export const SignedPendingAuditorApplicationSchema = PendingAuditorApplicationPayloadSchema.extend({
  intent: MutationIntentSchema,
  signature: MutationIntentSignatureSchema,
}).superRefine((request, ctx) => {
  if (request.intent.action !== "apply" || request.intent.target !== "auditor"
    || request.intent.actorRole !== "applicant" || request.intent.targetId !== request.applicationId) {
    ctx.addIssue({ code: "custom", path: ["intent"], message: "Intent must apply for this auditor application" });
  }
  if (request.intent.scopeCommitment !== computeAuthorizationScopeCommitment(request.scope)) {
    ctx.addIssue({ code: "custom", path: ["intent", "scopeCommitment"], message: "Intent scope commitment does not match auditor scope" });
  }
  if (request.intent.payloadCommitment !== computePendingAuditorApplicationPayloadCommitment({
    applicationId: request.applicationId,
    scope: request.scope,
  })) {
    ctx.addIssue({ code: "custom", path: ["intent", "payloadCommitment"], message: "Intent payload commitment does not match auditor application" });
  }
  if (request.signature.keyId !== request.intent.actorKeyId) {
    ctx.addIssue({ code: "custom", path: ["signature", "keyId"], message: "Signature key does not match applicant intent" });
  }
});

export type SignedPendingAuditorApplication = z.infer<typeof SignedPendingAuditorApplicationSchema>;
