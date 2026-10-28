/** @typedef {{path: string, sha256: string}} EvidenceRef */
/** @typedef {"pass" | "fail" | "not-run"} CaseStatus */
/** @typedef {{index: number, path: string, record: unknown}} IndexedDecision */

import { exactFields as exactKeys } from "./standalone-exact-fields-policy.mjs";

const STATUSES = new Set(["pass", "fail", "not-run"]);

/**
 * Checks the self-attested decision history, not signer identity or receipt truth.
 * @param {string} caseId
 * @param {string} sourceRevision
 * @param {CaseStatus} status
 * @param {readonly EvidenceRef[]} evidence
 * @param {readonly IndexedDecision[]} decisions
 */
export function assessStandaloneCaseDecisionChain(caseId, sourceRevision, status, evidence, decisions) {
  /** @type {CaseStatus | null} */
  let previousDecisionStatus = null;
  let lastDecisionIndex = -1;
  let lastDecisionTimeMs = -Infinity;
  for (const { index, path, record } of decisions) {
    if (!Number.isSafeInteger(index) || index <= lastDecisionIndex || index >= evidence.length
      || evidence[index]?.path !== path
      || !exactKeys(record, ["format", "sourceRevision", "caseId", "previousStatus", "status",
        "reviewer", "reasonCode", "decidedAt", "evidence", "reviewerAuthenticated",
        "evidenceContentVerified", "releaseQualified"])) {
      throw new Error(`${caseId} decision does not match its case history: ${path}`);
    }
    const decision = /** @type {Record<string, unknown>} */ (record);
    const decidedAtMs = typeof decision.decidedAt === "string" ? Date.parse(decision.decidedAt) : NaN;
    if (decision.format !== "tr-standalone-case-decision-v1"
      || decision.sourceRevision !== sourceRevision || decision.caseId !== caseId
      || !STATUSES.has(/** @type {string} */ (decision.previousStatus))
      || (previousDecisionStatus !== null && decision.previousStatus !== previousDecisionStatus)
      || !STATUSES.has(/** @type {string} */ (decision.status))
      || typeof decision.reviewer !== "string"
      || !/^[a-zA-Z0-9._@:-]{3,128}$/u.test(decision.reviewer)
      || typeof decision.reasonCode !== "string"
      || !/^[a-z][a-z0-9-]{2,63}$/u.test(decision.reasonCode)
      || !Number.isFinite(decidedAtMs)
      || new Date(decidedAtMs).toISOString() !== decision.decidedAt
      || decidedAtMs < lastDecisionTimeMs
      || decision.reviewerAuthenticated !== false
      || decision.evidenceContentVerified !== false || decision.releaseQualified !== false
      || JSON.stringify(decision.evidence) !== JSON.stringify(evidence.slice(0, index))) {
      throw new Error(`${caseId} decision does not match its case history: ${path}`);
    }
    previousDecisionStatus = /** @type {CaseStatus} */ (decision.status);
    lastDecisionIndex = index;
    lastDecisionTimeMs = decidedAtMs;
  }
  if (previousDecisionStatus !== null && status !== previousDecisionStatus) {
    throw new Error(`${caseId} status differs from its latest decision`);
  }
  return status === "pass" && previousDecisionStatus === "pass"
    && lastDecisionIndex === evidence.length - 1;
}
