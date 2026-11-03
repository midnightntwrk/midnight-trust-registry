import {
  canonicalizeJson,
  compareRfc3339Instants,
  type TrustRegistryEvidenceBundle,
} from "@midnight-ntwrk/trust-registry-domain";
import {
  evaluateAuthorizationRecordAtTime,
  evaluateRecognitionRecordAtTime,
  verifyIssuerAuthorizationBundle,
  verifyRecognitionBundle,
  verifyVerifierAuthorizationBundle,
  type EpochAnchorVerificationContext,
} from "@midnight-ntwrk/trust-registry-client";

import {
  TrqpAuthorizationEvidenceResponseSchema,
  TrqpAuthorizationRequestSchema,
  TrqpRecognitionEvidenceResponseSchema,
  TrqpRecognitionRequestSchema,
  type TrqpAuthorizationRequest,
  type TrqpRecognitionRequest,
} from "./schemas.js";

const assertEnvelope = (
  request: TrqpAuthorizationRequest | TrqpRecognitionRequest,
  response: {
    entity_id: string;
    authority_id: string;
    action: string;
    resource: string;
    time_requested?: string | undefined;
    time_evaluated: string;
    context?: TrqpAuthorizationRequest["context"] | undefined;
  },
  expectedAuthorityId: string,
): string => {
  const at = request.context?.time;
  if (at === undefined) throw new Error("Verified TRQP evidence requires an explicit request time");
  if (request.authority_id !== expectedAuthorityId
    || response.authority_id !== expectedAuthorityId
    || response.entity_id !== request.entity_id
    || response.action !== request.action
    || response.resource !== request.resource
    || canonicalizeJson(response.context ?? null) !== canonicalizeJson(request.context ?? null)
    || response.time_requested === undefined
    || compareRfc3339Instants(response.time_requested, at) !== 0
    || compareRfc3339Instants(response.time_evaluated, at) !== 0) {
    throw new Error("TRQP evidence response does not match the trusted request");
  }
  return at;
};

export type VerifiedTrqpAuthorizationEvidence = {
  authorized: boolean;
  statusAtTime: string | null;
  bundle: TrustRegistryEvidenceBundle;
};

export type VerifiedTrqpRecognitionEvidence = {
  recognized: boolean;
  statusAtTime: string | null;
  bundle: TrustRegistryEvidenceBundle;
};

/** The authority DID and epoch context must come from trusted configuration and ledger history. */
export const verifyTrqpAuthorizationEvidenceResponse = (
  input: unknown,
  requestInput: TrqpAuthorizationRequest,
  expectedAuthorityId: string,
  anchor: EpochAnchorVerificationContext,
): VerifiedTrqpAuthorizationEvidence => {
  const request = TrqpAuthorizationRequestSchema.parse(requestInput);
  const response = TrqpAuthorizationEvidenceResponseSchema.parse(input);
  const at = assertEnvelope(request, response, expectedAuthorityId);
  const role = request.action === "issue" ? "issuer"
    : request.action === "verify" ? "verifier" : null;
  if (role === null || response.bundle.authorization?.role !== role
    || response.bundle.recognition !== undefined) {
    throw new Error("TRQP authorization action does not match the evidence role");
  }
  const verify = role === "issuer" ? verifyIssuerAuthorizationBundle : verifyVerifierAuthorizationBundle;
  const bundle = verify(response.bundle, {
    ...anchor,
    expectedRole: role,
    expectedSubjectDid: request.entity_id,
    expectedResourceId: request.resource,
    evaluationTime: at,
    requireActive: false,
  });
  const decision = evaluateAuthorizationRecordAtTime(bundle.authorization!, at);
  if (response.authorized !== decision.trustedAtTime) {
    throw new Error("TRQP authorization decision does not match verified evidence");
  }
  return { authorized: decision.trustedAtTime, statusAtTime: decision.statusAtTime, bundle };
};

/** A recognized external registry never becomes a local issuer authorization. */
export const verifyTrqpRecognitionEvidenceResponse = (
  input: unknown,
  requestInput: TrqpRecognitionRequest,
  expectedAuthorityId: string,
  anchor: EpochAnchorVerificationContext,
): VerifiedTrqpRecognitionEvidence => {
  const request = TrqpRecognitionRequestSchema.parse(requestInput);
  const response = TrqpRecognitionEvidenceResponseSchema.parse(input);
  const at = assertEnvelope(request, response, expectedAuthorityId);
  const recognizedRegistryId = request.context?.recognized_registry_id;
  const recognition = response.bundle.recognition;
  if (recognizedRegistryId === undefined || recognition === undefined
    || response.bundle.authorization !== undefined
    || recognition.recognizedRegistryId !== recognizedRegistryId
    || recognition.scope.resourceType !== request.action
    || canonicalizeJson(recognition.scope.context ?? null)
      !== canonicalizeJson(request.context?.scope_context ?? null)) {
    throw new Error("TRQP recognition request does not match the exact evidence scope");
  }
  const bundle = verifyRecognitionBundle(response.bundle, {
    ...anchor,
    expectedSubjectDid: request.entity_id,
    expectedRecognizedRegistryId: recognizedRegistryId,
    expectedResourceId: request.resource,
    evaluationTime: at,
    requireActive: false,
  });
  const decision = evaluateRecognitionRecordAtTime(recognition, at);
  if (response.recognized !== decision.trustedAtTime) {
    throw new Error("TRQP recognition decision does not match verified evidence");
  }
  return { recognized: decision.trustedAtTime, statusAtTime: decision.statusAtTime, bundle };
};
