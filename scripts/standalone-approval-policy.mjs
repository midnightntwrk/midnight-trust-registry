import { validateMaintenancePolicy } from "@midnight-ntwrk/trust-registry-integration";
import { ContractMaintenanceAuthority } from "@midnight-ntwrk/midnight-js-protocol/ledger";

const FINGERPRINT = /^[A-F0-9]{40}$/u;

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/** @param {unknown} value @param {number} earliest @param {number} latest */
export function canonicalReviewerMetadata(value, earliest, latest) {
  if (!isRecord(value)) return false;
  const { approvedAt, reviewedReference } = value;
  const timestamp = Date.parse(typeof approvedAt === "string" ? approvedAt : "");
  return typeof reviewedReference === "string"
    && reviewedReference.length >= 8 && reviewedReference.length <= 512
    && !reviewedReference.startsWith("demo:")
    && typeof approvedAt === "string"
    && Number.isFinite(timestamp)
    && new Date(timestamp).toISOString() === approvedAt
    && timestamp >= earliest && timestamp <= latest;
}

/** @param {unknown} proposal @param {readonly string[]} fields @param {number} [now] */
export function reviewerProposal(proposal, fields, now = Date.now()) {
  if (!isRecord(proposal)
    || Object.keys(proposal).sort().join("\0") !== [...fields].sort().join("\0")
    || typeof proposal.reviewerFingerprint !== "string"
    || !FINGERPRINT.test(proposal.reviewerFingerprint)
    || !canonicalReviewerMetadata(proposal, -Infinity, now + 5 * 60_000)) {
    throw new Error("Canonical reviewer metadata and a human-supplied approval time are required");
  }
}

/** @param {unknown} maintenancePolicy @param {unknown} custodians */
export function validateReleaseCommittee(maintenancePolicy, custodians) {
  if (!isRecord(maintenancePolicy)
    || maintenancePolicy.mode !== "committee"
    || !Array.isArray(maintenancePolicy.verifyingKeys)
    || Object.keys(maintenancePolicy).sort().join("\0") !== "mode\0threshold\0verifyingKeys"
    || !maintenancePolicy.verifyingKeys.every((key) => typeof key === "string")
    || typeof maintenancePolicy.threshold !== "number") {
    throw new Error("Release maintenance approval requires a canonical committee policy");
  }
  const keys = /** @type {string[]} */ (maintenancePolicy.verifyingKeys);
  validateMaintenancePolicy({ mode: "committee", verifyingKeys: keys, threshold: maintenancePolicy.threshold });
  try {
    new ContractMaintenanceAuthority(keys.map((key) => key.slice(2)), maintenancePolicy.threshold, 1n);
  } catch {
    throw new Error("Release committee contains a verifying key the Midnight ledger cannot use");
  }
  if (!Array.isArray(custodians) || custodians.length !== keys.length
    || custodians.some((entry, index) => !isRecord(entry)
      || Object.keys(entry).sort().join("\0") !== "custodyReference\0holderRole\0verifyingKey"
      || entry.verifyingKey !== keys[index]
      || typeof entry.holderRole !== "string" || entry.holderRole.length < 3 || entry.holderRole.length > 128
      || typeof entry.custodyReference !== "string" || entry.custodyReference.length < 8
      || entry.custodyReference.length > 512)
    || new Set(custodians.map((entry) => entry.holderRole)).size !== keys.length) {
    throw new Error("Committee custody must bind distinct holder roles to every approved public key");
  }
}
