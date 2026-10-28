import { isAbsolute } from "node:path";

import { getLocalNetworkProfile } from "@midnight-ntwrk/trust-registry-integration";
import { exactFields } from "./standalone-exact-fields-policy.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const HASH = /^0x[0-9a-f]{64}$/u;
const PLAN_FIELDS = ["format", "journalPath", "network", "providerModulePath",
  "providerModuleSha256", "releaseManifestPath", "sourceRevision"];
const STAGED_PLAN_FIELDS = [...PLAN_FIELDS, "initialVerifierKeyName"];
const NETWORK_FIELDS = ["allowedHosts", "expectedGenesisHash", "indexerHttpUrl",
  "indexerWsUrl", "networkId", "rpcUrl"];

/** @typedef {{allowedHosts: string[], expectedGenesisHash: string, indexerHttpUrl: string,
 * indexerWsUrl: string, networkId: "undeployed", rpcUrl: string}} LocalDeploymentNetwork */
/** @typedef {{journalPath: string, network: LocalDeploymentNetwork,
 * providerModulePath: string, providerModuleSha256: string, releaseManifestPath: string,
 * sourceRevision: string}} LocalDeploymentPlanBase */
/** @typedef {LocalDeploymentPlanBase & (
 * {format: "tr-local-deployment-plan-v1"} |
 * {format: "tr-local-staged-deployment-plan-v1", initialVerifierKeyName: string}
 * )} LocalDeploymentPlan */

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/** @param {unknown} value */
const absolutePath = (value) => typeof value === "string" && isAbsolute(value);

/** @param {unknown} candidate @returns {LocalDeploymentPlan} */
export function validateLocalDeploymentPlan(candidate) {
  if (!isRecord(candidate)) {
    throw new Error("Local deployment requires an exact source, genesis, endpoint, and provider approval plan");
  }
  const full = exactFields(candidate, PLAN_FIELDS) && candidate.format === "tr-local-deployment-plan-v1";
  const staged = exactFields(candidate, STAGED_PLAN_FIELDS)
    && candidate.format === "tr-local-staged-deployment-plan-v1"
    && typeof candidate.initialVerifierKeyName === "string"
    && /^[A-Za-z][A-Za-z0-9_]{0,127}$/u.test(candidate.initialVerifierKeyName);
  const network = candidate.network;
  if ((!full && !staged)
    || typeof candidate.sourceRevision !== "string" || !REVISION.test(candidate.sourceRevision)
    || typeof candidate.providerModuleSha256 !== "string" || !SHA256.test(candidate.providerModuleSha256)
    || !exactFields(network, NETWORK_FIELDS)
    || network.networkId !== getLocalNetworkProfile().networkId
    || typeof network.expectedGenesisHash !== "string" || !HASH.test(network.expectedGenesisHash)
    || /^0x0{64}$/u.test(network.expectedGenesisHash)
    || ![network.rpcUrl, network.indexerHttpUrl, network.indexerWsUrl].every(
      (url) => typeof url === "string" && url.length > 0)
    || !Array.isArray(network.allowedHosts) || network.allowedHosts.length === 0
    || network.allowedHosts.some((host) => typeof host !== "string" || host.length === 0)
    || ![candidate.journalPath, candidate.providerModulePath, candidate.releaseManifestPath]
      .every(absolutePath)) {
    throw new Error("Local deployment requires an exact source, genesis, endpoint, and provider approval plan");
  }
  return /** @type {LocalDeploymentPlan} */ (/** @type {unknown} */ (candidate));
}
