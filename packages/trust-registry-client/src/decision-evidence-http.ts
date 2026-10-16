import { DecisionEvidenceSchema, type DecisionEvidenceSelection } from "@midnight-ntwrk/trust-registry-domain";

import {
  verifyDecisionEvidenceWithTrustedReaders,
  type DecisionEvidenceCandidate,
  type TrustedDecisionEvidenceReaders,
} from "./decision-context.js";

/** An API bundle is an untrusted claim until checked against independently authenticated readers. */
export async function verifyDecisionEvidenceFromApi(
  apiBase: string,
  authorizationId: string,
  selection: Omit<DecisionEvidenceSelection, "evaluationTime">,
  readers: TrustedDecisionEvidenceReaders,
  fetchImpl: typeof fetch = fetch,
): Promise<DecisionEvidenceCandidate> {
  if (authorizationId.length === 0 || authorizationId.length > 256) {
    throw new Error("Invalid decision-evidence authorization ID");
  }
  if (selection.role !== "issuer" && selection.role !== "verifier") {
    throw new Error("Invalid decision-evidence role");
  }
  const base = new URL(apiBase);
  if (base.username !== "" || base.password !== ""
    || (base.protocol !== "https:" && !(base.protocol === "http:"
      && ["localhost", "127.0.0.1"].includes(base.hostname)))) {
    throw new Error("Decision-evidence API must be HTTPS or loopback HTTP");
  }
  const url = new URL(`/v1/decision-evidence/${selection.role}/${encodeURIComponent(authorizationId)}`, base);
  const response = await fetchImpl(url, { cache: "no-store" });
  if (!response.ok) throw new Error(`Decision-evidence API unavailable (${response.status})`);
  const result: unknown = await response.json();
  if (result === null || typeof result !== "object" || Array.isArray(result)
    || Object.keys(result).length !== 2 || !("verification" in result)
    || result.verification !== "client-required" || !("evidence" in result)) {
    throw new Error("Decision-evidence API response must require client verification");
  }
  const evidence = DecisionEvidenceSchema.parse(result.evidence);
  if (evidence.grant.authorizationId !== authorizationId || evidence.role !== selection.role) {
    throw new Error("Decision-evidence API returned a different grant");
  }
  return verifyDecisionEvidenceWithTrustedReaders(evidence, selection, readers);
}
