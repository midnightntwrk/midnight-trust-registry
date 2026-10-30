const CONTAINER_ID = /^[0-9a-f]{64}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

/** @typedef {{
 * kind?: string, releaseQualified?: boolean, apiContainerId?: string,
 * networkId?: string, sourceRevision?: string, installInventorySha256?: string,
 * apiStartedAt?: string, apiRestartCount?: number,
 * approvalMountReadOnly?: boolean, trustAnchorMountReadOnly?: boolean
 * }} ApiTopology */
/** @typedef {{
 * format?: string, releaseQualified?: boolean, apiContainerId?: string,
 * networkId?: string, sourceRevision?: string, installInventorySha256?: string,
 * planSha256?: string, selectedStateSha256?: string, registryId?: string,
 * currentEpochId?: string, apiEgressCanaryDenied?: boolean,
 * apiDnsCanaryDenied?: boolean
 * }} CurrentJourney */

/** @param {ApiTopology | null | undefined} topology @param {CurrentJourney} journey */
export function matchingApiTopology(topology, journey) {
  return topology?.kind === "standalone-api-runtime-topology-observation"
    && topology.releaseQualified === false
    && topology.approvalMountReadOnly === true
    && topology.trustAnchorMountReadOnly === true
    && topology.apiContainerId === journey.apiContainerId
    && topology.networkId === journey.networkId
    && topology.sourceRevision === journey.sourceRevision
    && SHA256.test(topology.installInventorySha256 ?? "")
    && topology.installInventorySha256 === journey.installInventorySha256
    && CONTAINER_ID.test(topology.apiContainerId ?? "")
    && typeof topology.apiStartedAt === "string"
    && Number.isFinite(Date.parse(topology.apiStartedAt))
    && typeof topology.apiRestartCount === "number"
    && Number.isSafeInteger(topology.apiRestartCount)
    && topology.apiRestartCount >= 0;
}

/** @param {ApiTopology} left @param {ApiTopology} right */
function sameApiProcess(left, right) {
  return left.apiContainerId === right.apiContainerId
    && left.networkId === right.networkId
    && left.sourceRevision === right.sourceRevision
    && left.installInventorySha256 === right.installInventorySha256
    && left.apiStartedAt === right.apiStartedAt
    && left.apiRestartCount === right.apiRestartCount;
}

/** @param {CurrentJourney} before @param {ApiTopology} initial */
export function assertApiRestartPreflight(before, initial) {
  if (before?.format !== "tr-standalone-current-query-journey-v2"
    || before.releaseQualified !== false || before.apiEgressCanaryDenied !== true
    || before.apiDnsCanaryDenied !== true || !matchingApiTopology(initial, before)) {
    throw new Error("Approved current-query journey and running API container do not match");
  }
}

/** @param {ApiTopology} candidate @param {CurrentJourney} before @param {ApiTopology} initial */
export function isResumedApiProcess(candidate, before, initial) {
  return matchingApiTopology(candidate, before)
    && candidate.apiContainerId === initial.apiContainerId
    && typeof initial.apiRestartCount === "number"
    && candidate.apiRestartCount === initial.apiRestartCount + 1
    && candidate.apiStartedAt !== initial.apiStartedAt;
}

/** @param {CurrentJourney} before @param {CurrentJourney} after
 * @param {ApiTopology} resumed @param {ApiTopology} finalTopology */
export function assertApiRestartContinuity(before, after, resumed, finalTopology) {
  if (after?.format !== before.format || after.releaseQualified !== false
    || after.apiEgressCanaryDenied !== true || after.apiDnsCanaryDenied !== true
    || !matchingApiTopology(finalTopology, after) || !sameApiProcess(resumed, finalTopology)
    || before.sourceRevision !== after.sourceRevision
    || before.apiContainerId !== after.apiContainerId
    || before.networkId !== after.networkId
    || before.installInventorySha256 !== after.installInventorySha256
    || before.planSha256 !== after.planSha256
    || before.selectedStateSha256 !== after.selectedStateSha256
    || before.registryId !== after.registryId
    || before.currentEpochId !== after.currentEpochId) {
    throw new Error("API signed plan, selected state, or container changed across restart");
  }
}
