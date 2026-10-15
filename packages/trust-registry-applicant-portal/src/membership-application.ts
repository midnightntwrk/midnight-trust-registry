import type { TrustRegistryApiMutationContext } from "@midnight-ntwrk/trust-registry-api";
import {
  IssuerGovernedResourceTypeSchema,
  IssuerScopeSchema,
  MAX_MUTATION_INTENT_LIFETIME_MS,
  MaintainerScopeSchema,
  MutationIntentSchema,
  SignedPendingApplicationSchema,
  VerifierScopeSchema,
  computeAuthorizationScopeCommitment,
  computeMutationIntentDigest,
  computePendingApplicationPayloadCommitment,
  issuerGovernedResourceId,
  requestGovernedResourceId,
  type IssuerGovernedResourceType,
  type PendingApplicationPayload,
  type MutationIntent,
  type SignedPendingApplication,
} from "@midnight-ntwrk/trust-registry-domain";

export type MembershipApplicationIdentity = {
  applicationId: string;
  authorizationId: string;
  actorDid: string;
  actorKeyId: string;
};

export type IssuerApplicationDraft = MembershipApplicationIdentity & {
  credentialFamilyId: string;
  schemaId: string;
  schemaVersion: string;
  credentialDefinitionId: string;
  statusMethod: string;
  governedResourceType: IssuerGovernedResourceType;
};

export type VerifierApplicationDraft = MembershipApplicationIdentity & {
  requestProfileId: string;
  purpose: string;
  credentialScopeCommitment: string;
  allowedAttributes: string[];
  allowedPredicates: string[];
  disclosureLevel: string;
};

export type MaintainerApplicationDraft = MembershipApplicationIdentity;

export type PreparedMembershipApplication = {
  payload: PendingApplicationPayload;
  intent: MutationIntent;
  digest: string;
};

export function prepareMembershipApplication(
  draft: MembershipApplicationIdentity,
  payload: PendingApplicationPayload,
  context: TrustRegistryApiMutationContext,
  nonce: string,
): PreparedMembershipApplication {
  if (draft.applicationId !== payload.applicationId || draft.authorizationId !== payload.authorizationId) {
    throw new Error("Prepared application IDs must match the applicant draft");
  }
  const now = new Date(context.evaluatedAt);
  if (!Number.isFinite(now.getTime())) throw new Error("A valid signing time is required");
  const intent = MutationIntentSchema.parse({
    version: "tr-mutation-intent-v1",
    registryId: context.registryId,
    actorDid: draft.actorDid,
    actorKeyId: draft.actorKeyId,
    actorRole: "applicant",
    action: "apply",
    target: payload.scope.role,
    targetId: payload.applicationId,
    scopeCommitment: computeAuthorizationScopeCommitment(payload.scope),
    payloadCommitment: computePendingApplicationPayloadCommitment(payload),
    nonce,
    expectedWorkspaceCommitment: context.expectedWorkspaceCommitment,
    expectedEpochId: context.expectedEpochId,
    issuedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + MAX_MUTATION_INTENT_LIFETIME_MS).toISOString(),
  });
  return { payload, intent, digest: computeMutationIntentDigest(intent) };
}

export function prepareIssuerApplication(
  draft: IssuerApplicationDraft,
  context: TrustRegistryApiMutationContext,
  nonce: string,
): PreparedMembershipApplication {
  const scope = IssuerScopeSchema.parse({
    version: "tr-scope-v1", role: "issuer",
    credentialFamilyId: draft.credentialFamilyId,
    schemaId: draft.schemaId,
    schemaVersion: draft.schemaVersion,
    credentialDefinitionId: draft.credentialDefinitionId,
    statusMethod: draft.statusMethod,
  });
  const type = IssuerGovernedResourceTypeSchema.parse(draft.governedResourceType);
  return prepareMembershipApplication(draft, {
    applicationId: draft.applicationId,
    authorizationId: draft.authorizationId,
    scope,
    governedResource: { type, id: issuerGovernedResourceId(scope, type) },
  }, context, nonce);
}

export function prepareVerifierApplication(
  draft: VerifierApplicationDraft,
  context: TrustRegistryApiMutationContext,
  nonce: string,
): PreparedMembershipApplication {
  const scope = VerifierScopeSchema.parse({
    version: "tr-scope-v1", role: "verifier",
    requestProfileId: draft.requestProfileId,
    purpose: draft.purpose,
    credentialScopeCommitment: draft.credentialScopeCommitment,
    allowedAttributes: draft.allowedAttributes,
    allowedPredicates: draft.allowedPredicates,
    disclosureLevel: draft.disclosureLevel,
  });
  return prepareMembershipApplication(draft, {
    applicationId: draft.applicationId,
    authorizationId: draft.authorizationId,
    scope,
    governedResource: { type: "requestProfile", id: requestGovernedResourceId(scope) },
  }, context, nonce);
}

export function prepareMaintainerApplication(
  draft: MaintainerApplicationDraft,
  context: TrustRegistryApiMutationContext,
  nonce: string,
): PreparedMembershipApplication {
  const scope = MaintainerScopeSchema.parse({
    version: "tr-scope-v1", role: "maintainer", registryId: context.registryId,
  });
  return prepareMembershipApplication(draft, {
    applicationId: draft.applicationId,
    authorizationId: draft.authorizationId,
    scope,
    governedResource: { type: "registry", id: scope.registryId },
  }, context, nonce);
}

export function signPreparedMembershipApplication(
  prepared: PreparedMembershipApplication,
  signatureHex: string,
): SignedPendingApplication {
  return SignedPendingApplicationSchema.parse({
    ...prepared.payload,
    intent: prepared.intent,
    signature: { keyId: prepared.intent.actorKeyId, algorithm: "jubjub-schnorr", value: signatureHex },
  });
}
