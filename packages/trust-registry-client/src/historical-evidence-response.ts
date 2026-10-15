import {
  AuthorizationRecordSchema,
  EpochCommitmentSchema,
  RecognitionRecordSchema,
  TrustRegistryEvidenceBundleSchema,
  canonicalizeJson,
  compareRfc3339Instants,
  type TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";

import { verifyTrustRegistryEvidenceBundle, type EpochAnchorVerificationContext } from "./evidence.js";
import {
  evaluateAuthorizationRecordAtTime,
  evaluateRecognitionRecordAtTime,
  type AuthorizationTemporalEvaluation,
  type RecognitionTemporalEvaluation,
} from "./temporal.js";

type HistoricalAuthorizationSelection = {
  role: "issuer" | "verifier" | "auditor";
  subjectDid: string;
  resourceId: string;
  resourceType?: string;
  trustLevel?: string;
  at: string;
};

type HistoricalRecognitionSelection = {
  recognizedAuthorityDid: string;
  recognizedRegistryId?: string;
  scopeResourceType?: string;
  scopeResourceId: string;
  scopeContext?: Record<string, string>;
  trustLevel?: string;
  at: string;
};

type VerifiedHistoricalEvidence<T> = T & { bundle: TrustRegistryEvidenceBundle };

const asRecord = (value: unknown, label: string): Record<string, unknown> => {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
};

const assertResponseEpoch = (
  response: Record<string, unknown>,
  bundle: TrustRegistryEvidenceBundle,
  at: string,
): void => {
  if (typeof response.evaluatedAt !== "string"
    || compareRfc3339Instants(response.evaluatedAt, at) !== 0) {
    throw new Error("Historical evidence evaluation time mismatch");
  }
  const epoch = EpochCommitmentSchema.parse(response.epoch);
  if (epoch.epochId !== bundle.epoch.epochId
    || epoch.registryId !== bundle.epoch.registryId
    || epoch.stateRoot !== bundle.epoch.stateRoot
    || epoch.eventRoot !== bundle.epoch.eventRoot
    || epoch.policyRoot !== bundle.epoch.policyRoot
    || canonicalizeJson(epoch.maintainerSignatures) !== canonicalizeJson(bundle.epoch.maintainerSignatures)
    || compareRfc3339Instants(epoch.validFrom, bundle.epoch.validFrom) !== 0
    || compareRfc3339Instants(epoch.validUntil, bundle.epoch.validUntil) !== 0) {
    throw new Error("Historical evidence response epoch mismatch");
  }
};

const assertResponseDecision = (
  response: Record<string, unknown>,
  decision: AuthorizationTemporalEvaluation | RecognitionTemporalEvaluation,
): void => {
  if (response.statusAtTime !== decision.statusAtTime
    || response.trustedAtTime !== decision.trustedAtTime) {
    throw new Error("Historical evidence response decision mismatch");
  }
};

/** The anchor must come from authenticated ledger history, not this API response. */
export const verifyHistoricalAuthorizationEvidenceResponse = (
  input: unknown,
  selection: HistoricalAuthorizationSelection,
  anchor: EpochAnchorVerificationContext,
): VerifiedHistoricalEvidence<AuthorizationTemporalEvaluation> => {
  const response = asRecord(input, "Historical authorization response");
  const bundle = TrustRegistryEvidenceBundleSchema.parse(response.bundle);
  const authorization = bundle.authorization;
  if (authorization === undefined || bundle.recognition !== undefined
    || authorization.role !== selection.role
    || authorization.subjectDid !== selection.subjectDid
    || authorization.resourceId !== selection.resourceId
    || (selection.resourceType !== undefined && authorization.resourceType !== selection.resourceType)
    || (selection.trustLevel !== undefined && authorization.trustLevel !== selection.trustLevel)) {
    throw new Error("Historical authorization scope mismatch");
  }
  const entry = asRecord(response.entry, "Historical authorization entry");
  const currentRecord = AuthorizationRecordSchema.parse(entry.authorization);
  if (currentRecord.authorizationId !== authorization.authorizationId
    || currentRecord.registryId !== authorization.registryId
    || currentRecord.subjectDid !== authorization.subjectDid
    || currentRecord.role !== authorization.role
    || currentRecord.resourceType !== authorization.resourceType
    || currentRecord.resourceId !== authorization.resourceId
    || currentRecord.policyId !== authorization.policyId
    || currentRecord.trustLevel !== authorization.trustLevel
    || currentRecord.evidenceHash !== authorization.evidenceHash
    || currentRecord.statusPolicyBindingCommitment !== authorization.statusPolicyBindingCommitment) {
    throw new Error("Historical authorization entry mismatch");
  }
  assertResponseEpoch(response, bundle, selection.at);
  const verified = verifyTrustRegistryEvidenceBundle(bundle, {
    ...anchor,
    expectedRole: selection.role,
    expectedSubjectDid: selection.subjectDid,
    expectedResourceId: selection.resourceId,
    evaluationTime: selection.at,
    requireActive: false,
  });
  const decision = evaluateAuthorizationRecordAtTime(authorization, selection.at);
  const entryDecision = evaluateAuthorizationRecordAtTime(currentRecord, selection.at);
  if (entryDecision.statusAtTime !== decision.statusAtTime
    || entryDecision.trustedAtTime !== decision.trustedAtTime) {
    throw new Error("Historical authorization entry decision mismatch");
  }
  assertResponseDecision(response, decision);
  return { ...decision, bundle: verified };
};

/** Recognition proof checking does not imply that the recognized registry is currently trusted. */
export const verifyHistoricalRecognitionEvidenceResponse = (
  input: unknown,
  selection: HistoricalRecognitionSelection,
  anchor: EpochAnchorVerificationContext,
): VerifiedHistoricalEvidence<RecognitionTemporalEvaluation> => {
  const response = asRecord(input, "Historical recognition response");
  const bundle = TrustRegistryEvidenceBundleSchema.parse(response.bundle);
  const recognition = bundle.recognition;
  if (recognition === undefined || bundle.authorization !== undefined
    || recognition.recognizedAuthorityDid !== selection.recognizedAuthorityDid
    || recognition.scope.resourceId !== selection.scopeResourceId
    || canonicalizeJson(recognition.scope.context ?? null) !== canonicalizeJson(selection.scopeContext ?? null)
    || (selection.recognizedRegistryId !== undefined
      && recognition.recognizedRegistryId !== selection.recognizedRegistryId)
    || (selection.scopeResourceType !== undefined
      && recognition.scope.resourceType !== selection.scopeResourceType)
    || (selection.trustLevel !== undefined && recognition.trustLevel !== selection.trustLevel)) {
    throw new Error("Historical recognition scope mismatch");
  }
  const entry = asRecord(response.entry, "Historical recognition entry");
  const currentRecord = RecognitionRecordSchema.parse(entry.recognition);
  if (currentRecord.recognitionId !== recognition.recognitionId
    || currentRecord.registryId !== recognition.registryId
    || currentRecord.recognizedAuthorityDid !== recognition.recognizedAuthorityDid
    || currentRecord.recognizedRegistryId !== recognition.recognizedRegistryId
    || canonicalizeJson(currentRecord.scope) !== canonicalizeJson(recognition.scope)
    || currentRecord.policyId !== recognition.policyId
    || currentRecord.trustLevel !== recognition.trustLevel
    || currentRecord.evidenceHash !== recognition.evidenceHash) {
    throw new Error("Historical recognition entry mismatch");
  }
  assertResponseEpoch(response, bundle, selection.at);
  const verified = verifyTrustRegistryEvidenceBundle(bundle, {
    ...anchor,
    expectedSubjectDid: selection.recognizedAuthorityDid,
    expectedResourceId: selection.scopeResourceId,
    ...(selection.recognizedRegistryId === undefined ? {} : {
      expectedRecognizedRegistryId: selection.recognizedRegistryId,
    }),
    evaluationTime: selection.at,
    requireActive: false,
  });
  const decision = evaluateRecognitionRecordAtTime(recognition, selection.at);
  const entryDecision = evaluateRecognitionRecordAtTime(currentRecord, selection.at);
  if (entryDecision.statusAtTime !== decision.statusAtTime
    || entryDecision.trustedAtTime !== decision.trustedAtTime) {
    throw new Error("Historical recognition entry decision mismatch");
  }
  assertResponseDecision(response, decision);
  return { ...decision, bundle: verified };
};
