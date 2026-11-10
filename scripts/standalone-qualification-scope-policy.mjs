/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const BLOCK_HASH = /^0x[0-9a-f]{64}$/u;
const ZERO_BLOCK_HASH = /^0x0{64}$/u;
export const CURRENT_QUERY_SCOPE = "Live signed-plan current-only API role and recognition queries with API-container TCP/DNS canary denial; not a governed mutation or complete actor journey";
export const API_RESTART_SCOPE = "Same pinned API container and selected current state survived one restart with API-container egress denial; not node, wallet, browser, backup/restore, governed-write, or independently authenticated finality evidence";
const CURRENT_QUERY_KEYS = new Set(["format", "sourceRevision", "apiContainerId", "networkId",
  "installInventorySha256", "planSha256", "selectedStateSha256", "planContractAddress",
  "planExpectedGenesisHash", "registryId", "currentEpochId", "finalizedCheckpoints",
  "counts", "resolvedLookups", "ambiguousLookups", "apiEgressCanaryDenied",
  "apiDnsCanaryDenied", "scope", "actorJourneys", "hostAndBrowserEgress",
  "independentFinality", "planToDeploymentBinding", "releaseQualified"]);
const API_RESTART_KEYS = new Set(["format", "sourceRevision", "apiContainerId", "networkId",
  "installInventorySha256", "planSha256", "selectedStateSha256", "beforeStartedAt",
  "afterStartedAt", "beforeRestartCount", "afterRestartCount", "finalizedCheckpoints",
  "apiEgressCanaryDenied", "apiDnsCanaryDenied", "scope", "releaseQualified"]);

/** @param {unknown} value @param {RegExp} pattern */
const matches = (value, pattern) => typeof value === "string" && pattern.test(value);
/** @param {unknown} value */
const nonzeroBlockHash = (value) => typeof value === "string"
  && BLOCK_HASH.test(value) && !ZERO_BLOCK_HASH.test(value);

/** @param {unknown} report */
function hasConsistentLookupCounts(report) {
  if (!isRecord(report) || !isRecord(report.counts)
    || !isRecord(report.resolvedLookups) || !isRecord(report.ambiguousLookups)) return false;
  const { counts, resolvedLookups, ambiguousLookups } = report;
  return ["issuer", "verifier", "auditor", "recognition"].every((role) => {
    const count = counts[role];
    const resolved = resolvedLookups[role];
    const ambiguous = ambiguousLookups[role];
    return typeof count === "number" && Number.isSafeInteger(count) && count > 0
      && typeof resolved === "number" && Number.isSafeInteger(resolved)
      && resolved > 0 && resolved <= count
      && (role === "recognition" || (typeof ambiguous === "number"
        && Number.isSafeInteger(ambiguous) && ambiguous >= 0 && ambiguous <= count));
  });
}

/** A read-only API probe cannot upgrade unobserved release gates.
 * @param {unknown} report
 * @returns {asserts report is Record<string, unknown>}
 */
export function assertCurrentQueryScope(report) {
  if (!isRecord(report)
    || Object.keys(report).some((key) => !CURRENT_QUERY_KEYS.has(key))
    || report.scope !== CURRENT_QUERY_SCOPE
    || report.format !== "tr-standalone-current-query-journey-v2"
    || !matches(report.sourceRevision, SHA)
    || !matches(report.apiContainerId, SHA256)
    || !matches(report.networkId, SHA256)
    || !matches(report.installInventorySha256, SHA256)
    || !matches(report.planSha256, SHA256)
    || !matches(report.selectedStateSha256, SHA256)
    || !nonzeroBlockHash(report.planContractAddress)
    || !nonzeroBlockHash(report.planExpectedGenesisHash)
    || typeof report.registryId !== "string" || report.registryId.length === 0
    || typeof report.currentEpochId !== "string" || report.currentEpochId.length === 0
    || !Array.isArray(report.finalizedCheckpoints)
    || report.finalizedCheckpoints.length !== 2
    || !report.finalizedCheckpoints.every(nonzeroBlockHash)
    || report.releaseQualified !== false
    || report.apiEgressCanaryDenied !== true
    || report.apiDnsCanaryDenied !== true
    || report.actorJourneys !== "not-run"
    || report.hostAndBrowserEgress !== "not-verified"
    || report.independentFinality !== "not-verified"
    || report.planToDeploymentBinding !== "not-verified"
    || !hasConsistentLookupCounts(report)) {
    throw new Error("Current-query observer disagrees with the approved evidence scope");
  }
}

/** A container restart proves only the recorded API egress checks.
 * @param {unknown} report
 * @returns {asserts report is Record<string, unknown>}
 */
export function assertApiRestartScope(report) {
  if (!isRecord(report)
    || Object.keys(report).some((key) => !API_RESTART_KEYS.has(key))
    || report.scope !== API_RESTART_SCOPE
    || report.releaseQualified !== false
    || report.apiEgressCanaryDenied !== true
    || report.apiDnsCanaryDenied !== true) {
    throw new Error("API restart observer returned an incompatible evidence scope");
  }
}
