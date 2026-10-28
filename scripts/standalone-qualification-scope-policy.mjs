/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const SHA = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const BLOCK_HASH = /^0x[0-9a-f]{64}$/u;
const ZERO_BLOCK_HASH = /^0x0{64}$/u;

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
 */
export function assertCurrentQueryScope(report) {
  if (!isRecord(report)
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
 */
export function assertApiRestartScope(report) {
  if (!isRecord(report)
    || report.releaseQualified !== false
    || report.apiEgressCanaryDenied !== true
    || report.apiDnsCanaryDenied !== true) {
    throw new Error("API restart observer returned an incompatible evidence scope");
  }
}
