import type { EpochAnchorVerificationContext } from "@midnight-ntwrk/trust-registry-client";

import {
  verifyTrqpAuthorizationEvidenceResponse,
  verifyTrqpRecognitionEvidenceResponse,
} from "./evidence-verifier.js";
import {
  TrqpAuthorizationRequestSchema,
  TrqpRecognitionRequestSchema,
  type TrqpAuthorizationRequest,
  type TrqpRecognitionRequest,
} from "./schemas.js";

const endpoint = (apiBase: string, path: string): URL => {
  const base = new URL(apiBase);
  if (base.username !== "" || base.password !== ""
    || (base.protocol !== "https:" && !(base.protocol === "http:"
      && ["localhost", "127.0.0.1"].includes(base.hostname)))) {
    throw new Error("TRQP evidence API must be HTTPS or loopback HTTP");
  }
  return new URL(path, base);
};

const fetchEvidence = async (
  apiBase: string,
  path: string,
  request: TrqpAuthorizationRequest | TrqpRecognitionRequest,
  fetchImpl: typeof fetch,
): Promise<unknown> => {
  const response = await fetchImpl(endpoint(apiBase, path), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
    cache: "no-store",
    redirect: "error",
  });
  if (!response.ok) throw new Error(`TRQP evidence API unavailable (${response.status})`);
  return response.json() as Promise<unknown>;
};

/** The authority DID and epoch anchor must be independently authenticated. */
export const verifyTrqpAuthorizationEvidenceFromApi = async (
  apiBase: string,
  requestInput: TrqpAuthorizationRequest,
  expectedAuthorityId: string,
  anchor: EpochAnchorVerificationContext,
  fetchImpl: typeof fetch = fetch,
): Promise<ReturnType<typeof verifyTrqpAuthorizationEvidenceResponse>> => {
  const request = TrqpAuthorizationRequestSchema.parse(requestInput);
  if (request.authority_id !== expectedAuthorityId) {
    throw new Error("TRQP request authority does not match trusted configuration");
  }
  if (request.context?.time === undefined) {
    throw new Error("Verified TRQP evidence requires an explicit request time");
  }
  return verifyTrqpAuthorizationEvidenceResponse(
    await fetchEvidence(apiBase, "/v1/trqp/authorizations/evidence", request, fetchImpl),
    request, expectedAuthorityId, anchor,
  );
};

/** Recognition proof never grants local issuer or verifier authorization. */
export const verifyTrqpRecognitionEvidenceFromApi = async (
  apiBase: string,
  requestInput: TrqpRecognitionRequest,
  expectedAuthorityId: string,
  anchor: EpochAnchorVerificationContext,
  fetchImpl: typeof fetch = fetch,
): Promise<ReturnType<typeof verifyTrqpRecognitionEvidenceResponse>> => {
  const request = TrqpRecognitionRequestSchema.parse(requestInput);
  if (request.authority_id !== expectedAuthorityId) {
    throw new Error("TRQP request authority does not match trusted configuration");
  }
  if (request.context?.time === undefined || request.context.recognized_registry_id === undefined) {
    throw new Error("Verified TRQP recognition requires explicit time and external registry");
  }
  return verifyTrqpRecognitionEvidenceResponse(
    await fetchEvidence(apiBase, "/v1/trqp/recognitions/evidence", request, fetchImpl),
    request, expectedAuthorityId, anchor,
  );
};
