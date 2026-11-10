import {
  AuditorScopeSchema,
  computeAuthorizationScopeCommitment,
  requestGovernedResourceId,
  type AuthorizationScope,
  type TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  AuthorizationStatus,
  type AuditorAuthorizationRecord,
} from "@midnight-ntwrk/trust-registry-contract/managed/trust-registry/contract/index.js";

import { verifyAuditorAuthorizationBundle, type BundleVerificationOptions } from "./evidence.js";
import { bytes32Commitment, hashHexToBytes32, sameBytes32 } from "./utils.js";

export type AuditorMandateOptions = Omit<
  BundleVerificationOptions,
  "expectedRegistryId" | "expectedSubjectDid" | "expectedResourceId" | "expectedRole" | "requireActive" | "evaluationTime"
> & {
  expectedRegistryId: string;
  expectedSubjectDid: string;
  evaluationTime: string;
  /** Resolve from an independently trusted current ledger state, not from the bundle. */
  currentAuthorizationRecord: AuditorAuthorizationRecord;
};

export type AuditorMandate = {
  authorizationId: string;
  auditorDid: string;
  requestResourceId: string;
  scopeCommitment: string;
  epochId: string;
};

/** Verifies only the current mandate to ask; disclosure and holder consent are outside the registry. */
export const verifyAuditorRequestMandate = (
  bundle: TrustRegistryEvidenceBundle,
  requestedScope: Extract<AuthorizationScope, { role: "auditor" }>,
  options: AuditorMandateOptions,
): AuditorMandate => {
  if (options === null || typeof options !== "object"
    || typeof options.expectedRegistryId !== "string" || options.expectedRegistryId.length === 0
    || typeof options.expectedSubjectDid !== "string" || options.expectedSubjectDid.length === 0
    || typeof options.evaluationTime !== "string" || options.evaluationTime.length === 0
    || options.currentAuthorizationRecord === undefined
    || options.currentAuthorizationRecord === null) {
    throw new Error("Auditor mandate requires expected registry, subject DID, evaluation time, and current ledger record");
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
  const current = options.currentAuthorizationRecord;
  if (current.status !== AuthorizationStatus.active) throw new Error("Auditor mandate is not active in current ledger state");
  for (const [field, actual, expected] of [
    ["authorization ID", current.authorizationId, bytes32Commitment(authorization.authorizationId)],
    ["subject DID", current.subjectDidCommitment, bytes32Commitment(authorization.subjectDid)],
    ["request resource", current.requestResourceId, bytes32Commitment(requestResourceId)],
    ["governed policy", current.policyId, hashHexToBytes32(verified.epoch.policyRoot)],
    ["trust level", current.trustLevel, bytes32Commitment(authorization.trustLevel)],
    ["evidence hash", current.evidenceHash, hashHexToBytes32(authorization.evidenceHash)],
    ["lifecycle event", current.lifecycleEventHash, hashHexToBytes32(authorization.lifecycleEventRoot)],
  ] as const) {
    if (!sameBytes32(actual, expected)) throw new Error(`Auditor mandate current ${field} mismatch`);
  }
  return {
    authorizationId: authorization.authorizationId,
    auditorDid: authorization.subjectDid,
    requestResourceId,
    scopeCommitment: computeAuthorizationScopeCommitment(scope),
    epochId: verified.epoch.epochId,
  };
};
