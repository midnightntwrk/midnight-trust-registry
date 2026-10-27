import { dirname, isAbsolute, join, resolve } from "node:path";

import { validateLocalDeploymentPlan } from "./local-deployment-plan-policy.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const NAME = /^[A-Za-z][A-Za-z0-9_]{0,127}$/u;
const FIELDS = ["circuitName", "deploymentJournalPath", "format", "initialVerifierKeyName",
  "journalPath", "network", "providerModulePath", "providerModuleSha256",
  "releaseManifestPath", "sourceRevision"];

/** @typedef {ReturnType<typeof validateLocalDeploymentPlan> & {
 * circuitName: string, deploymentJournalPath: string, initialVerifierKeyName: string
 * }} LocalVerifierKeyInsertionPlan */

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/** @param {unknown} value @returns {value is string} */
const absolutePath = (value) => typeof value === "string" && isAbsolute(value);

/** @param {unknown} candidate @returns {LocalVerifierKeyInsertionPlan} */
export function validateLocalVerifierKeyInsertionPlan(candidate) {
  if (!isRecord(candidate)
    || Object.keys(candidate).sort().join("\0") !== [...FIELDS].sort().join("\0")
    || candidate.format !== "tr-local-verifier-key-insertion-plan-v1"
    || typeof candidate.providerModuleSha256 !== "string" || !SHA256.test(candidate.providerModuleSha256)
    || typeof candidate.circuitName !== "string" || !NAME.test(candidate.circuitName)
    || typeof candidate.initialVerifierKeyName !== "string" || !NAME.test(candidate.initialVerifierKeyName)
    || !absolutePath(candidate.deploymentJournalPath)
    || !absolutePath(candidate.journalPath)
    || !absolutePath(candidate.providerModulePath)
    || !absolutePath(candidate.releaseManifestPath)) {
    throw new Error("Verifier-key insertion requires an exact local approval plan");
  }
  validateLocalDeploymentPlan({
    format: "tr-local-deployment-plan-v1",
    sourceRevision: candidate.sourceRevision,
    network: candidate.network,
    providerModulePath: candidate.providerModulePath,
    providerModuleSha256: candidate.providerModuleSha256,
    releaseManifestPath: candidate.releaseManifestPath,
    journalPath: candidate.journalPath,
  });
  const expectedJournalPath = join(dirname(resolve(candidate.deploymentJournalPath)),
    `verifier-${candidate.circuitName}.json`);
  if (resolve(candidate.journalPath) !== expectedJournalPath) {
    throw new Error("Verifier-key insertion requires the fixed per-circuit journal path");
  }
  return /** @type {LocalVerifierKeyInsertionPlan} */ (/** @type {unknown} */ (candidate));
}
