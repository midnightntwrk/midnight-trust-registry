import {
  AuditorScopeSchema,
  computeAuthorizationScopeCommitment,
  requestGovernedResourceId,
  type AuthorizationScope,
  type TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";

import { verifyAuditorAuthorizationBundle, type BundleVerificationOptions } from "./evidence.js";

export type AuditorMandateOptions = Omit<
  BundleVerificationOptions,
  "expectedRegistryId" | "expectedSubjectDid" | "expectedResourceId" | "expectedRole" | "requireActive"
> & {
  expectedRegistryId: string;
  expectedSubjectDid: string;
};

export type AuditorMandate = {
  authorizationId: string;
  auditorDid: string;
  requestResourceId: string;
  scopeCommitment: string;
  epochId: string;
};

/** Verifies only the mandate to ask; disclosure and holder consent are outside the registry. */
export const verifyAuditorRequestMandate = (
  bundle: TrustRegistryEvidenceBundle,
  requestedScope: Extract<AuthorizationScope, { role: "auditor" }>,
  options: AuditorMandateOptions,
): AuditorMandate => {
  if (options === null || typeof options !== "object"
    || typeof options.expectedRegistryId !== "string" || options.expectedRegistryId.length === 0
    || typeof options.expectedSubjectDid !== "string" || options.expectedSubjectDid.length === 0) {
    throw new Error("Auditor mandate requires expected registry and subject DID");
  }
  const scope = AuditorScopeSchema.parse(requestedScope);
  const requestResourceId = requestGovernedResourceId(scope);
  const verified = verifyAuditorAuthorizationBundle(bundle, {
    ...options,
    expectedRegistryId: options.expectedRegistryId,
    expectedSubjectDid: options.expectedSubjectDid,
    expectedResourceId: requestResourceId,
    expectedRole: "auditor",
    requireActive: true,
  });
  const authorization = verified.authorization;
  if (authorization === undefined) throw new Error("Auditor mandate is unavailable");
  return {
    authorizationId: authorization.authorizationId,
    auditorDid: authorization.subjectDid,
    requestResourceId,
    scopeCommitment: computeAuthorizationScopeCommitment(scope),
    epochId: verified.epoch.epochId,
  };
};
