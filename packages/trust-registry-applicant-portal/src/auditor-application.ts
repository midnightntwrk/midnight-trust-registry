import type { TrustRegistryApiMutationContext } from "@midnight-ntwrk/trust-registry-api";
import { AuditorScopeSchema, requestGovernedResourceId } from "@midnight-ntwrk/trust-registry-domain/browser";

import {
  prepareMembershipApplication,
  signPreparedMembershipApplication,
  type MembershipApplicationIdentity,
  type PreparedMembershipApplication,
} from "./membership-application.js";

export type AuditorApplicationDraft = MembershipApplicationIdentity & {
  requestProfileId: string;
  purpose: string;
  credentialScopeCommitment: string;
  allowedAttributes: string[];
  allowedPredicates: string[];
  disclosureLevel: string;
};

export type PreparedAuditorApplication = PreparedMembershipApplication;

/** Preparation never signs or stores a private key; the host rechecks context and nonce on submission. */
export function prepareAuditorApplication(
  draft: AuditorApplicationDraft,
  context: TrustRegistryApiMutationContext,
  nonce: string,
): PreparedAuditorApplication {
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
  return prepareMembershipApplication(draft, {
    applicationId: draft.applicationId,
    authorizationId: draft.authorizationId,
    scope,
    governedResource: { type: "requestProfile", id: requestGovernedResourceId(scope) },
  }, context, nonce);
}

export const signPreparedAuditorApplication = signPreparedMembershipApplication;
