const SHA = /^[0-9a-f]{40}$/u;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;

/** @param {{sourceRevision?: string}} verified */
export function pinnedKeylessApiImageTag(verified) {
  if (!SHA.test(verified?.sourceRevision ?? "")) {
    throw new Error("Verified install source revision is required for the API image tag");
  }
  return `tr-standalone/api:sha-${verified.sourceRevision}`;
}

/** @param {{apiRuntime?: {imageId?: string, configId?: string} | null}} verified
 * @param {string} loadedId */
export function selectPinnedKeylessApiImageId(verified, loadedId) {
  const imageId = verified?.apiRuntime?.imageId;
  const configId = verified?.apiRuntime?.configId;
  if (!IMAGE_ID.test(imageId ?? "") || !IMAGE_ID.test(configId ?? "")) {
    throw new Error("Verified API image IDs are required for keyless generation");
  }
  if (loadedId !== imageId && loadedId !== configId) {
    throw new Error("Loaded API image differs from the verified install");
  }
  return loadedId;
}
