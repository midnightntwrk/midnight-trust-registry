const CONTAINER_ID = /^[0-9a-f]{64}$/u;

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/** The two current reads must identify a real process before continuity is compared.
 * @param {unknown} report
 */
export function assertCurrentQueryProcessIdentity(report) {
  if (!isRecord(report)
    || typeof report.apiContainerId !== "string"
    || !CONTAINER_ID.test(report.apiContainerId)
    || typeof report.apiStartedAt !== "string"
    || !Number.isFinite(Date.parse(report.apiStartedAt))
    || !Number.isSafeInteger(report.apiRestartCount)
    || /** @type {number} */ (report.apiRestartCount) < 0) {
    throw new Error("Current-query process identity is incomplete");
  }
}
