import type { EpochAnchorVerificationContext } from "./evidence.js";
import {
  verifyHistoricalAuthorizationEvidenceResponse,
  verifyHistoricalRecognitionEvidenceResponse,
  type HistoricalAuthorizationSelection,
  type HistoricalRecognitionSelection,
} from "./historical-evidence-response.js";

const evidenceUrl = (apiBase: string, path: string): URL => {
  const base = new URL(apiBase);
  if (base.username !== "" || base.password !== ""
    || (base.protocol !== "https:" && !(base.protocol === "http:"
      && ["localhost", "127.0.0.1"].includes(base.hostname)))) {
    throw new Error("Historical evidence API must be HTTPS or loopback HTTP");
  }
  return new URL(path, base);
};

const fetchEvidence = async (
  apiBase: string,
  path: string,
  selection: HistoricalAuthorizationSelection | HistoricalRecognitionSelection,
  fetchImpl: typeof fetch,
): Promise<unknown> => {
  const response = await fetchImpl(evidenceUrl(apiBase, path), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(selection),
    cache: "no-store",
    redirect: "error",
  });
  if (!response.ok) throw new Error(`Historical evidence API unavailable (${response.status})`);
  return response.json() as Promise<unknown>;
};

/** The epoch anchor must come from an independently authenticated ledger reader. */
export const verifyHistoricalAuthorizationEvidenceFromApi = async (
  apiBase: string,
  selection: HistoricalAuthorizationSelection,
  anchor: EpochAnchorVerificationContext,
  fetchImpl: typeof fetch = fetch,
): Promise<ReturnType<typeof verifyHistoricalAuthorizationEvidenceResponse>> =>
  verifyHistoricalAuthorizationEvidenceResponse(
    await fetchEvidence(apiBase, "/v1/authorizations/evaluate/evidence", selection, fetchImpl),
    selection,
    anchor,
  );

/** Recognition proof does not grant local issuer or verifier authorization. */
export const verifyHistoricalRecognitionEvidenceFromApi = async (
  apiBase: string,
  selection: HistoricalRecognitionSelection,
  anchor: EpochAnchorVerificationContext,
  fetchImpl: typeof fetch = fetch,
): Promise<ReturnType<typeof verifyHistoricalRecognitionEvidenceResponse>> =>
  verifyHistoricalRecognitionEvidenceResponse(
    await fetchEvidence(apiBase, "/v1/recognitions/evaluate/evidence", selection, fetchImpl),
    selection,
    anchor,
  );
