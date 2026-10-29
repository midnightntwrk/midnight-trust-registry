/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

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
    || report.planToDeploymentBinding !== "not-verified") {
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
