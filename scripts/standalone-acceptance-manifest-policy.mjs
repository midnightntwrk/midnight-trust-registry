const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const ADDRESS = /^0x[0-9a-f]{64}$/u;
const NONZERO_HEX = /[1-9a-f]/u;

export const ACCEPTANCE_CASES = Object.freeze([
  "L01", "L02", "A01", "A02", "A03", "A04", "N01", "O01", "R01", "S01",
]);

/** @typedef {{ path: string, sha256: string }} AcceptanceEvidenceItem */
/** @typedef {{ status: "pass" | "fail" | "not-run", evidence: AcceptanceEvidenceItem[] }} AcceptanceCase */
/** @typedef {{ format: "tr-standalone-acceptance-evidence-v1", sourceRevision: string,
 *   installInventorySha256: string, signedPlanSha256: string, genesisHash: string,
 *   contractAddress: string, cases: Record<string, AcceptanceCase> }} AcceptanceManifest */

/** @param {unknown} value @param {readonly string[]} keys */
function exactKeys(value, keys) {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.keys(value).length === keys.length
    && keys.every((key) => Object.hasOwn(value, key));
}

/**
 * Validate only the untrusted manifest's shape and identity. Evidence bytes and
 * decision history are checked separately before any attachment or verdict.
 * @param {unknown} value
 * @returns {AcceptanceManifest}
 */
export function parseStandaloneAcceptanceManifest(value) {
  if (!exactKeys(value, ["format", "sourceRevision", "installInventorySha256",
    "signedPlanSha256", "genesisHash", "contractAddress", "cases"])) {
    throw new Error("Acceptance manifest must pin one source, install, plan, genesis, deployment, and all cases");
  }
  const manifest = /** @type {Record<string, unknown>} */ (value);
  if (manifest.format !== "tr-standalone-acceptance-evidence-v1"
    || typeof manifest.sourceRevision !== "string" || !REVISION.test(manifest.sourceRevision)
    || !NONZERO_HEX.test(manifest.sourceRevision)
    || typeof manifest.installInventorySha256 !== "string"
    || !SHA256.test(manifest.installInventorySha256)
    || !NONZERO_HEX.test(manifest.installInventorySha256)
    || typeof manifest.signedPlanSha256 !== "string" || !SHA256.test(manifest.signedPlanSha256)
    || !NONZERO_HEX.test(manifest.signedPlanSha256)
    || typeof manifest.genesisHash !== "string" || !ADDRESS.test(manifest.genesisHash)
    || !NONZERO_HEX.test(manifest.genesisHash.slice(2))
    || typeof manifest.contractAddress !== "string" || !ADDRESS.test(manifest.contractAddress)
    || !NONZERO_HEX.test(manifest.contractAddress.slice(2))
    || !exactKeys(manifest.cases, ACCEPTANCE_CASES)) {
    throw new Error("Acceptance manifest must pin one source, install, plan, genesis, deployment, and all cases");
  }
  const cases = /** @type {Record<string, unknown>} */ (manifest.cases);
  for (const id of ACCEPTANCE_CASES) {
    const entry = cases[id];
    if (!exactKeys(entry, ["status", "evidence"])) {
      throw new Error(`${id} requires status pass/fail/not-run and raw evidence for pass`);
    }
    const record = /** @type {Record<string, unknown>} */ (entry);
    if (!(["pass", "fail", "not-run"].includes(/** @type {string} */ (record.status)))
      || !Array.isArray(record.evidence)) {
      throw new Error(`${id} requires status pass/fail/not-run and raw evidence for pass`);
    }
    for (const item of record.evidence) {
      if (!exactKeys(item, ["path", "sha256"]) || typeof item.path !== "string"
        || typeof item.sha256 !== "string" || !SHA256.test(item.sha256)) {
        throw new Error(`${id} evidence requires a relative path and SHA-256`);
      }
    }
  }
  return /** @type {AcceptanceManifest} */ (manifest);
}
