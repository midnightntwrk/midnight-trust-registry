import { STANDALONE_IMAGE_REFERENCE } from "./standalone-image-reference.mjs";
import { exactStringSet } from "./standalone-exact-fields-policy.mjs";

const ROLES = ["node", "indexer", "proof-server"];
const SHA256 = /^[0-9a-f]{64}$/u;

/** @param {unknown} value @returns {value is Record<string, unknown>} */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Check the image inventory before reading any archives. Archive paths and
 * contents are verified separately by the install-bundle verifier.
 * @param {unknown} value
 * @returns {Array<{role: string, reference: string, archive: string, archiveSha256: string}>}
 */
export function pinnedStandaloneInventoryImages(value) {
  if (!Array.isArray(value) || value.length !== ROLES.length
    || value.some((image) => !isRecord(image))
    || !exactStringSet(value.map((image) => image.role), ROLES)) {
    throw new Error("Standalone install inventory must pin node, indexer, and proof-server exactly once");
  }
  const images = /** @type {Array<Record<string, unknown>>} */ (value);
  if (images.some((image) => typeof image.archive !== "string")
    || new Set(images.map((image) => image.archive)).size !== images.length) {
    throw new Error("Each container role requires a distinct pinned archive");
  }
  for (const image of images) {
    if (typeof image.reference !== "string" || !STANDALONE_IMAGE_REFERENCE.test(image.reference)
      || typeof image.archiveSha256 !== "string" || !SHA256.test(image.archiveSha256)) {
      throw new Error(`Unpinned or invalid container image: ${String(image.role)}`);
    }
  }
  return /** @type {Array<{role: string, reference: string, archive: string, archiveSha256: string}>} */ (images);
}
