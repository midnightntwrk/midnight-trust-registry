import { exactRecordFields } from "./standalone-exact-fields-policy.mjs";

const HASH = /^0x[0-9a-f]{64}$/u;
const DECIMAL = /^(0|[1-9][0-9]*)$/u;

/**
 * @typedef {{ x: string, y: string }} PublicKeyCoordinates
 * @typedef {{ registryId: string, registryDidCommitment: string,
 *   governancePolicyCommitment: string, maintainerId: string,
 *   maintainerDidCommitment: string, maintainerKeyId: string,
 *   maintainerPublicKey: PublicKeyCoordinates, maintainerThreshold: string }} BootstrapRequest
 * @typedef {{ policyCommitment: string, policyVersion: string,
 *   actionSequence: string, maintainerThreshold: string,
 *   activeMaintainerCount: string }} GovernanceRequest
 * @typedef {{ format: "tr-local-committee-transition-request-v1", sourceRevision: string,
 *   bootstrapMaintenanceVerifyingKey: string, expiresAt: string,
 *   bootstrap: BootstrapRequest, governance: GovernanceRequest }} CommitteeTransitionRequest
 */

/** The untrusted request is checked before the wizard constructs Compact inputs.
 * @param {unknown} value
 * @param {string} sourceRevision
 * @returns {CommitteeTransitionRequest}
 */
export function parseCommitteeTransitionRequest(value, sourceRevision) {
  if (!exactRecordFields(value, ["bootstrap", "bootstrapMaintenanceVerifyingKey", "expiresAt",
    "format", "governance", "sourceRevision"])
    || value.format !== "tr-local-committee-transition-request-v1"
    || value.sourceRevision !== sourceRevision
    || typeof value.bootstrapMaintenanceVerifyingKey !== "string"
    || !HASH.test(value.bootstrapMaintenanceVerifyingKey)
    || typeof value.expiresAt !== "string"
    || !Number.isFinite(Date.parse(value.expiresAt))
    || !exactRecordFields(value.bootstrap, ["governancePolicyCommitment", "maintainerDidCommitment",
      "maintainerId", "maintainerKeyId", "maintainerPublicKey", "maintainerThreshold",
      "registryDidCommitment", "registryId"])
    || !exactRecordFields(value.governance, ["actionSequence", "activeMaintainerCount",
      "maintainerThreshold", "policyCommitment", "policyVersion"])) {
    throw new Error("Committee transition request has an invalid shape or source revision");
  }
  const bootstrap = value.bootstrap;
  const governance = value.governance;
  if (!exactRecordFields(bootstrap.maintainerPublicKey, ["x", "y"])) {
    throw new Error("Committee transition request has an invalid shape or source revision");
  }
  const key = bootstrap.maintainerPublicKey;
  if (typeof bootstrap.registryId !== "string"
    || [bootstrap.registryDidCommitment, bootstrap.governancePolicyCommitment,
      bootstrap.maintainerId, bootstrap.maintainerDidCommitment, bootstrap.maintainerKeyId,
      governance.policyCommitment].some((field) => typeof field !== "string" || !HASH.test(field))
    || [key.x, key.y, bootstrap.maintainerThreshold, governance.policyVersion,
      governance.actionSequence, governance.maintainerThreshold,
      governance.activeMaintainerCount].some((field) => typeof field !== "string" || !DECIMAL.test(field))) {
    throw new Error("Committee transition request contains an invalid public commitment or counter");
  }
  return /** @type {CommitteeTransitionRequest} */ (value);
}
