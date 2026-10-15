import type { TrustRegistryApiMutationContext } from "@midnight-ntwrk/trust-registry-api";
import {
  AuditorScopeSchema,
  MAX_MUTATION_INTENT_LIFETIME_MS,
  MutationIntentSchema,
  SignedPendingApplicationSchema,
  computeAuthorizationScopeCommitment,
  computeMutationIntentDigest,
  computePendingApplicationPayloadCommitment,
  requestGovernedResourceId,
  type PendingApplicationPayload,
  type MutationIntent,
  type SignedPendingApplication,
} from "@midnight-ntwrk/trust-registry-domain";

export type AuditorApplicationDraft = {
  applicationId: string;
  authorizationId: string;
  actorDid: string;
  actorKeyId: string;
  requestProfileId: string;
  purpose: string;
  credentialScopeCommitment: string;
  allowedAttributes: string[];
  allowedPredicates: string[];
  disclosureLevel: string;
};

export type PreparedAuditorApplication = {
  payload: PendingApplicationPayload;
  intent: MutationIntent;
  digest: string;
};

/** Preparation never signs or stores a private key; the host rechecks context and nonce on submission. */
export function prepareAuditorApplication(
  draft: AuditorApplicationDraft,
  context: TrustRegistryApiMutationContext,
  nonce: string,
): PreparedAuditorApplication {
  const now = new Date(context.evaluatedAt);
  if (!Number.isFinite(now.getTime())) throw new Error("A valid signing time is required");
  const scope = AuditorScopeSchema.parse({
    version: "tr-scope-v1",
    role: "auditor",
    requestProfileId: draft.requestProfileId,
    purpose: draft.purpose,
    credentialScopeCommitment: draft.credentialScopeCommitment,
    allowedAttributes: draft.allowedAttributes,
    allowedPredicates: draft.allowedPredicates,
    disclosureLevel: draft.disclosureLevel,
  });
  const payload: PendingApplicationPayload = {
    applicationId: draft.applicationId,
    authorizationId: draft.authorizationId,
    scope,
    governedResource: { type: "requestProfile", id: requestGovernedResourceId(scope) },
  };
  const intent = MutationIntentSchema.parse({
    version: "tr-mutation-intent-v1",
    registryId: context.registryId,
    actorDid: draft.actorDid,
    actorKeyId: draft.actorKeyId,
    actorRole: "applicant",
    action: "apply",
    target: "auditor",
    targetId: payload.applicationId,
    scopeCommitment: computeAuthorizationScopeCommitment(scope),
    payloadCommitment: computePendingApplicationPayloadCommitment(payload),
    nonce,
    expectedWorkspaceCommitment: context.expectedWorkspaceCommitment,
    expectedEpochId: context.expectedEpochId,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + MAX_MUTATION_INTENT_LIFETIME_MS).toISOString(),
  });
  return { payload, intent, digest: computeMutationIntentDigest(intent) };
}

export function signPreparedAuditorApplication(
  prepared: PreparedAuditorApplication,
  signatureHex: string,
): SignedPendingApplication {
  return SignedPendingApplicationSchema.parse({
    ...prepared.payload,
    intent: prepared.intent,
    signature: { keyId: prepared.intent.actorKeyId, algorithm: "jubjub-schnorr", value: signatureHex },
  });
}
