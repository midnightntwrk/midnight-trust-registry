import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

import { matchesApprovedRuntimeHealthcheck } from "./runtime-healthcheck.mjs";

const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const FINGERPRINT = /^[0-9A-F]{40}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const IMAGE = /^[a-z0-9][a-z0-9./_:-]*@sha256:[0-9a-f]{64}$/u;

/** @param {unknown} value @returns {Record<string, unknown> | null} */
const record = (value) => value !== null && typeof value === "object" && !Array.isArray(value)
  ? /** @type {Record<string, unknown>} */ (value) : null;

/** @param {unknown} value @returns {unknown[] | null} */
const array = (value) => Array.isArray(value) ? /** @type {unknown[]} */ (value) : null;

/** @param {string} archive @param {string} member @returns {unknown} */
function archiveJson(archive, member) {
  return JSON.parse(execFileSync("tar", ["-xOf", archive, member], {
    encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  }));
}

/** @param {string} archive @param {string} digest @returns {unknown} */
function verifiedBlob(archive, digest) {
  if (!IMAGE_ID.test(digest)) throw new Error("Invalid OCI blob digest");
  const bytes = execFileSync("tar", ["-xOf", archive, `blobs/sha256/${digest.slice(7)}`], {
    timeout: 30_000, maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (createHash("sha256").update(bytes).digest("hex") !== digest.slice(7)) {
    throw new Error("OCI blob hash mismatch");
  }
  return JSON.parse(bytes.toString("utf8"));
}

/** @param {string} archive @param {string} role @param {string} revision @param {boolean} [requireOci] */
export function staticImageIdentityFromArchive(archive, role, revision, requireOci = false) {
  if (!["admin", "applicant"].includes(role) || !REVISION.test(revision)) {
    throw new Error("Static image role or source revision is invalid");
  }
  /** @type {unknown} */
  let legacy;
  try {
    legacy = archiveJson(archive, "manifest.json");
  } catch {
    throw new Error(`${role} image archive has no readable Docker manifest`);
  }
  const legacyEntries = array(legacy);
  const legacyEntry = legacyEntries?.length === 1 ? record(legacyEntries[0]) : null;
  const configPath = legacyEntry?.Config;
  const configDigest = /^blobs\/sha256\/([0-9a-f]{64})$/u.exec(
    typeof configPath === "string" ? configPath : "")?.[1];
  const repoTags = legacyEntry?.RepoTags;
  if (!configDigest || (repoTags !== null && (array(repoTags)?.length ?? -1) !== 0)) {
    throw new Error(`${role} image archive has an invalid config or implicit tag`);
  }
  let configBytes;
  try {
    configBytes = execFileSync("tar", ["-xOf", archive, /** @type {string} */ (configPath)], {
      timeout: 30_000, maxBuffer: 1024 * 1024,
    });
  } catch {
    throw new Error(`${role} image archive lacks its config blob`);
  }
  if (createHash("sha256").update(configBytes).digest("hex") !== configDigest) {
    throw new Error(`${role} image archive config hash mismatch`);
  }
  const config = record(/** @type {unknown} */ (JSON.parse(configBytes.toString("utf8"))));
  const runtime = record(config?.config);
  const labels = record(runtime?.Labels);
  const environment = array(runtime?.Env);
  if (config?.os !== "linux" || config.architecture !== "arm64"
    || labels?.["org.opencontainers.image.revision"] !== revision
    || runtime?.User !== "1000:1000"
    || runtime?.WorkingDir !== "/app"
    || (runtime?.Entrypoint != null && array(runtime.Entrypoint)?.length !== 0)
    || environment === null
    || environment.filter((entry) => typeof entry === "string"
      && entry.startsWith("TR_STATIC_ROLE=")).length !== 1
    || !environment.includes(`TR_STATIC_ROLE=${role}`)
    || (requireOci && (environment.some((entry) => typeof entry !== "string"
      || /^(?:NODE_OPTIONS|NODE_PATH|LD_PRELOAD|LD_LIBRARY_PATH)=/u.test(entry))
      || !matchesApprovedRuntimeHealthcheck(runtime?.Healthcheck, role)
      || runtime?.OnBuild != null
      || runtime?.Volumes != null))
    || JSON.stringify(runtime?.Cmd)
      !== JSON.stringify(["node", "/app/entrypoint.mjs", "--host", "0.0.0.0", "--port", "4173"])) {
    throw new Error(`${role} image archive config disagrees with the approved runtime`);
  }
  const acceptedIds = [`sha256:${configDigest}`];
  const members = execFileSync("tar", ["-tf", archive], {
    encoding: "utf8", timeout: 30_000, maxBuffer: 4 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  }).split("\n");
  if (!members.includes("index.json") && !members.includes("./index.json")) {
    if (requireOci) throw new Error(`${role} image archive requires an OCI index`);
    return { configId: `sha256:${configDigest}`, acceptedIds };
  }
  const index = record(archiveJson(archive, "index.json"));
  const indexManifests = array(index?.manifests);
  const indexEntry = indexManifests?.length === 1 ? record(indexManifests[0]) : null;
  if (index?.schemaVersion !== 2 || indexEntry === null
    || (requireOci && (index.annotations !== undefined
      || indexEntry.annotations !== undefined))
    || typeof indexEntry.digest !== "string" || !IMAGE_ID.test(indexEntry.digest)) {
    throw new Error(`${role} OCI index is malformed`);
  }
  const topDigest = indexEntry.digest;
  const top = record(verifiedBlob(archive, topDigest));
  let imageDigest = topDigest;
  /** @type {unknown} */
  let imageManifest = top;
  const topManifests = array(top?.manifests);
  if (topManifests !== null) {
    const entries = topManifests.map(record);
    const candidates = entries.filter((entry) => {
      const platform = record(entry?.platform);
      return platform?.os === "linux" && platform.architecture === "arm64";
    });
    const selected = candidates.length === 1 ? candidates[0] : null;
    const selectedDigest = selected?.digest;
    if (selected === null || typeof selectedDigest !== "string" || !IMAGE_ID.test(selectedDigest)
      || (requireOci && (top?.annotations !== undefined
        || selected.annotations !== undefined
        || entries.filter((entry) => entry !== selected).length > 1
        || entries.some((entry) => {
          if (entry === selected) return false;
          const platform = record(entry?.platform);
          const annotations = record(entry?.annotations);
          return platform?.os !== "unknown" || platform.architecture !== "unknown"
            || annotations?.["vnd.docker.reference.type"] !== "attestation-manifest"
            || annotations?.["vnd.docker.reference.digest"] !== selectedDigest
            || annotations === null || Object.keys(annotations).sort().join(",")
              !== "vnd.docker.reference.digest,vnd.docker.reference.type";
        })))) {
      throw new Error(`${role} OCI index does not select one arm64 image`);
    }
    imageDigest = selectedDigest;
    imageManifest = verifiedBlob(archive, imageDigest);
  } else if (requireOci) {
    throw new Error(`${role} image archive requires an OCI image index`);
  }
  const manifest = record(imageManifest);
  const manifestConfig = record(manifest?.config);
  const layers = array(manifest?.layers);
  const layerPaths = layers?.map((layer) => {
    const digest = record(layer)?.digest;
    return typeof digest === "string" && IMAGE_ID.test(digest)
      ? `blobs/sha256/${digest.slice(7)}` : null;
  });
  if (manifest?.schemaVersion !== 2
    || manifestConfig?.digest !== `sha256:${configDigest}`
    || (requireOci && (layerPaths === undefined || layerPaths.some((path) => path === null)
      || JSON.stringify(legacyEntry?.Layers) !== JSON.stringify(layerPaths)))) {
    throw new Error(`${role} OCI image manifest disagrees with the Docker config`);
  }
  return { configId: `sha256:${configDigest}`, topDigest,
    acceptedIds: [...new Set([...acceptedIds, imageDigest, topDigest])] };
}

/** @param {unknown} manifest @param {string} role @param {string} revision @param {string} archiveSha256 */
export function validateStaticImageManifest(manifest, role, revision, archiveSha256) {
  const value = record(manifest);
  const assets = array(value?.assets);
  if (value?.format !== "tr-static-runtime-image-v1" || value.role !== role
    || value.sourceRevision !== revision || value.platform !== "linux/arm64"
    || typeof value.approvedSignerFingerprint !== "string"
    || !FINGERPRINT.test(value.approvedSignerFingerprint)
    || typeof value.baseImage !== "string" || !IMAGE.test(value.baseImage)
    || typeof value.assetsSha256 !== "string" || !SHA256.test(value.assetsSha256)
    || typeof value.imageId !== "string" || !IMAGE_ID.test(value.imageId)
    || value.archiveName !== `${role}.image.tar`
    || value.archiveSha256 !== archiveSha256
    || assets === null || assets.length === 0
    || assets.some((asset) => {
      const item = record(asset);
      return typeof item?.path !== "string"
        || !/^[a-zA-Z0-9][a-zA-Z0-9._/-]*\.(?:html|js|css)$/u.test(item.path)
        || item.path.split("/").some((part) => part === ".." || part === "." || part === "")
        || !Number.isSafeInteger(item.size) || /** @type {number} */ (item.size) < 1
        || /** @type {number} */ (item.size) > 32 * 1024 * 1024
        || typeof item.sha256 !== "string" || !SHA256.test(item.sha256);
    })
    || createHash("sha256").update(JSON.stringify(assets)).digest("hex")
      !== value.assetsSha256) {
    throw new Error(`${role} static image manifest is invalid`);
  }
}
