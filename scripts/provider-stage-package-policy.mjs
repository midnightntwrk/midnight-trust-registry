const ARCHIVE_NAME = /^[a-z0-9][a-z0-9.-]*\.tgz$/u;
const SHA256 = /^[0-9a-f]{64}$/u;

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/**
 * Selects only the verified package catalog expected by the provider stage.
 * @param {unknown} manifest
 * @param {readonly string[]} expectedWorkspaces
 * @returns {Array<{workspace: string, filename: string, sha256: string}>}
 */
export function providerStagePackageEntries(manifest, expectedWorkspaces) {
  const packages = isRecord(manifest) ? manifest.packages : undefined;
  if (!Array.isArray(packages) || packages.length !== expectedWorkspaces.length
    || new Set(expectedWorkspaces).size !== expectedWorkspaces.length
    || packages.some((item) => !isRecord(item)
      || typeof item.workspace !== "string" || !expectedWorkspaces.includes(item.workspace)
      || typeof item.filename !== "string" || !ARCHIVE_NAME.test(item.filename)
      || typeof item.sha256 !== "string" || !SHA256.test(item.sha256))) {
    throw new Error("Verified bundle has an incomplete or unsafe provider package catalog");
  }
  /** @type {Array<{workspace: string, filename: string, sha256: string}>} */
  const entries = packages;
  if (new Set(entries.map((item) => item.workspace)).size !== entries.length
    || new Set(entries.map((item) => item.filename)).size !== entries.length) {
    throw new Error("Verified bundle has an incomplete or unsafe provider package catalog");
  }
  return entries;
}
