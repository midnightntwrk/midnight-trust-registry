import { STANDALONE_IMAGE_REFERENCE } from "./standalone-image-reference.mjs";

const ROLES = ["node", "indexer", "proof-server"];
const PROJECT_NAME = "${TR_STACK_NAME:-tr-standalone-local-smoke}";

/** @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/**
 * Validate the base Compose image mapping before matching it to the install inventory.
 * This does not validate runtime topology, overlays, or Docker's merged Compose model.
 * @param {unknown} compose
 */
export function pinnedStandaloneImagePolicy(compose) {
  if (!isRecord(compose) || compose.name !== PROJECT_NAME) {
    throw new Error("Standalone Compose must name the dedicated project and exactly three services");
  }
  const services = compose.services;
  if (!isRecord(services)
    || Object.keys(services).sort().join("\0") !== [...ROLES].sort().join("\0")) {
    throw new Error("Standalone Compose must name the dedicated project and exactly three services");
  }
  return ROLES.map((role) => {
    const service = services[role];
    const reference = isRecord(service) ? service.image : undefined;
    if (typeof reference !== "string" || !STANDALONE_IMAGE_REFERENCE.test(reference)) {
      throw new Error(`Standalone image is not digest pinned: ${role}`);
    }
    return { role, reference };
  });
}
