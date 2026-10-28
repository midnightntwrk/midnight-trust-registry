/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/** @param {unknown} report */
function hasConsistentLookupCounts(report) {
  if (!isRecord(report) || !isRecord(report.counts)
    || !isRecord(report.resolvedLookups) || !isRecord(report.ambiguousLookups)) return false;
  return ["issuer", "verifier", "auditor", "recognition"].every((role) => {
    const count = report.counts[role];
    const resolved = report.resolvedLookups[role];
    const ambiguous = report.ambiguousLookups[role];
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
