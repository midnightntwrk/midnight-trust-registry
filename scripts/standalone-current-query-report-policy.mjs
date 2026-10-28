import { assertCurrentQueryProcessIdentity } from "./standalone-current-query-process-policy.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const BLOCK_HASH = /^0x[0-9a-f]{64}$/u;
/** @typedef {"issuer" | "verifier" | "auditor" | "recognition"} Role */
/** @typedef {"issuer" | "verifier" | "auditor"} AuthorizationRole */
/** @type {Role[]} */
const ROLES = ["issuer", "verifier", "auditor", "recognition"];
/** @type {AuthorizationRole[]} */
const AUTHORIZATION_ROLES = ["issuer", "verifier", "auditor"];
/** @typedef {{
 * format: string, releaseQualified: false, sourceRevision: string, routeReadback: string,
 * planSha256: string, installInventorySha256: string, planContractAddress: string,
 * planExpectedGenesisHash: string, selectedStateSha256: string,
 * sourceFinalizedBlockHash: string, registryId: string, currentEpochId: string,
 * apiContainerId: string, apiStartedAt: string, apiRestartCount: number,
 * networkId: string, counts: Record<Role, number>, resolvedLookups: Record<Role, number>,
 * ambiguousLookups: Record<AuthorizationRole, number>
 * }} CurrentReadReport */
/** @typedef {{
 * kind: string, releaseQualified: false, sourceRevision: string, apiContainerId: string,
 * networkId: string, bridgePositiveControlReachable: true, bridgeDnsCanaryReachable: true,
 * apiCanaryConnectionDenied: true, apiBridgeDnsRouteDenied: true,
 * apiRoutesConfinedToLedgerSubnet: true
 * }} EgressReport */

/** @param {unknown} report @param {Record<string, unknown>} status @returns {CurrentReadReport} */
export function checkedCurrentRead(report, status) {
  assertCurrentQueryProcessIdentity(report);
  const candidate = /** @type {Partial<CurrentReadReport>} */ (report);
  if (candidate.format !== "tr-standalone-api-current-read-probe-v4"
    || candidate.releaseQualified !== false || candidate.sourceRevision !== status.sourceRevision
    || candidate.routeReadback !== "same-container-signed-plan-current-only"
    || !SHA256.test(candidate.planSha256 ?? "")
    || !SHA256.test(candidate.installInventorySha256 ?? "")
    || !BLOCK_HASH.test(candidate.planContractAddress ?? "")
    || /^0x0{64}$/u.test(candidate.planContractAddress ?? "")
    || !BLOCK_HASH.test(candidate.planExpectedGenesisHash ?? "")
    || /^0x0{64}$/u.test(candidate.planExpectedGenesisHash ?? "")
    || !SHA256.test(candidate.selectedStateSha256 ?? "")
    || !BLOCK_HASH.test(candidate.sourceFinalizedBlockHash ?? "")
    || /^0x0{64}$/u.test(candidate.sourceFinalizedBlockHash ?? "")
    || typeof candidate.registryId !== "string" || candidate.registryId.length === 0
    || typeof candidate.currentEpochId !== "string" || candidate.currentEpochId.length === 0
    || typeof candidate.apiContainerId !== "string" || candidate.apiContainerId.length === 0
    || typeof candidate.networkId !== "string" || candidate.networkId.length === 0
    || !ROLES.every((role) => {
      const count = candidate.counts?.[role];
      const resolved = candidate.resolvedLookups?.[role];
      return typeof count === "number" && Number.isSafeInteger(count) && count > 0
        && typeof resolved === "number" && Number.isSafeInteger(resolved)
        && resolved > 0 && resolved <= count;
    })
    || !AUTHORIZATION_ROLES.every((role) => {
      const ambiguous = candidate.ambiguousLookups?.[role];
      const count = candidate.counts?.[role];
      return typeof ambiguous === "number" && Number.isSafeInteger(ambiguous)
        && ambiguous >= 0 && typeof count === "number" && ambiguous <= count;
    })) {
    throw new Error("Live current-query readback is incomplete or has no resolved actor role");
  }
  if (candidate.planContractAddress !== status.deployedContractAddress
    || candidate.planExpectedGenesisHash !== status.approvedGenesisHash
    || candidate.networkId !== status.stackNetworkId
    || candidate.installInventorySha256 !== status.installInventorySha256) {
    throw new Error("Live signed API runtime differs from the approved wizard install, deployment, genesis, or network");
  }
  return /** @type {CurrentReadReport} */ (candidate);
}

/** @param {unknown} report @param {CurrentReadReport} first @returns {EgressReport} */
export function checkedCurrentQueryEgress(report, first) {
  const candidate = /** @type {Partial<EgressReport> | null} */ (report);
  if (candidate?.kind !== "standalone-api-egress-observation"
    || candidate.releaseQualified !== false
    || candidate.sourceRevision !== first.sourceRevision
    || candidate.apiContainerId !== first.apiContainerId
    || candidate.networkId !== first.networkId
    || candidate.bridgePositiveControlReachable !== true
    || candidate.bridgeDnsCanaryReachable !== true
    || candidate.apiCanaryConnectionDenied !== true
    || candidate.apiBridgeDnsRouteDenied !== true
    || candidate.apiRoutesConfinedToLedgerSubnet !== true) {
    throw new Error("Live API egress probe did not preserve the pinned runtime identity and denial");
  }
  return /** @type {EgressReport} */ (candidate);
}
