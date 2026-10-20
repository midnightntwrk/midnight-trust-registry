import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";

const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const FINGERPRINT = /^[0-9A-F]{40}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const IMAGE = /^[a-z0-9][a-z0-9./_:-]*@sha256:[0-9a-f]{64}$/u;

function archiveJson(archive, member) {
  return JSON.parse(execFileSync("tar", ["-xOf", archive, member], {
    encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  }));
}

function verifiedBlob(archive, digest) {
  if (!IMAGE_ID.test(digest)) throw new Error("Invalid OCI blob digest");
  const bytes = execFileSync("tar", ["-xOf", archive, `blobs/sha256/${digest.slice(7)}`], {
    timeout: 30_000, maxBuffer: 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
  if (createHash("sha256").update(bytes).digest("hex") !== digest.slice(7)) {
    throw new Error("OCI blob hash mismatch");
  }
  return JSON.parse(bytes);
}

export function staticImageIdentityFromArchive(archive, role, revision, requireOci = false) {
  if (!["admin", "applicant"].includes(role) || !REVISION.test(revision)) {
    throw new Error("Static image role or source revision is invalid");
  }
  let legacy;
  try {
    legacy = archiveJson(archive, "manifest.json");
  } catch {
    throw new Error(`${role} image archive has no readable Docker manifest`);
  }
  const configPath = legacy?.length === 1 ? legacy[0]?.Config : undefined;
  const configDigest = /^blobs\/sha256\/([0-9a-f]{64})$/u.exec(configPath ?? "")?.[1];
  if (!configDigest || (legacy[0].RepoTags !== null && legacy[0].RepoTags?.length !== 0)) {
    throw new Error(`${role} image archive has an invalid config or implicit tag`);
  }
  let configBytes;
  try {
    configBytes = execFileSync("tar", ["-xOf", archive, configPath], {
      timeout: 30_000, maxBuffer: 1024 * 1024,
    });
  } catch {
    throw new Error(`${role} image archive lacks its config blob`);
  }
  if (createHash("sha256").update(configBytes).digest("hex") !== configDigest) {
    throw new Error(`${role} image archive config hash mismatch`);
  }
  const config = JSON.parse(configBytes);
  if (config?.os !== "linux" || config.architecture !== "arm64"
    || config.config?.Labels?.["org.opencontainers.image.revision"] !== revision
    || config.config?.User !== "1000:1000"
    || config.config?.WorkingDir !== "/app"
    || (config.config?.Entrypoint != null && config.config.Entrypoint.length !== 0)
    || !config.config?.Env?.includes(`TR_STATIC_ROLE=${role}`)
    || (requireOci && (config.config.Env.some((entry) => typeof entry !== "string"
      || /^(?:NODE_OPTIONS|NODE_PATH|LD_PRELOAD|LD_LIBRARY_PATH)=/u.test(entry))
      || config.config.Healthcheck != null || config.config.OnBuild != null))
    || JSON.stringify(config.config?.Cmd)
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
  const index = archiveJson(archive, "index.json");
  if (index?.schemaVersion !== 2 || index.manifests?.length !== 1
    || (requireOci && (index.annotations !== undefined
      || index.manifests[0]?.annotations !== undefined))
    || !IMAGE_ID.test(index.manifests[0]?.digest)) {
    throw new Error(`${role} OCI index is malformed`);
  }
  const topDigest = index.manifests[0].digest;
  const top = verifiedBlob(archive, topDigest);
  let imageDigest = topDigest;
  let imageManifest = top;
  if (Array.isArray(top.manifests)) {
    const candidates = top.manifests.filter((entry) => entry.platform?.os === "linux"
      && entry.platform?.architecture === "arm64");
    if (candidates.length !== 1 || !IMAGE_ID.test(candidates[0].digest)
      || (requireOci && (top.annotations !== undefined
        || candidates[0].annotations !== undefined
        || top.manifests.some((entry) => entry !== candidates[0]
          && (entry.platform?.os !== "unknown" || entry.platform?.architecture !== "unknown"
            || entry.annotations?.["vnd.docker.reference.type"] !== "attestation-manifest"
            || entry.annotations?.["vnd.docker.reference.digest"] !== candidates[0].digest))))) {
      throw new Error(`${role} OCI index does not select one arm64 image`);
    }
    imageDigest = candidates[0].digest;
    imageManifest = verifiedBlob(archive, imageDigest);
  } else if (requireOci) {
    throw new Error(`${role} image archive requires an OCI image index`);
  }
  if (imageManifest?.schemaVersion !== 2
    || imageManifest.config?.digest !== `sha256:${configDigest}`
    || (requireOci && (!Array.isArray(imageManifest.layers)
      || imageManifest.layers.some((layer) => !IMAGE_ID.test(layer?.digest))
      || JSON.stringify(legacy[0].Layers) !== JSON.stringify(imageManifest.layers.map((layer) =>
        `blobs/sha256/${layer.digest.slice(7)}`))))) {
    throw new Error(`${role} OCI image manifest disagrees with the Docker config`);
  }
  return { configId: `sha256:${configDigest}`,
    acceptedIds: [...new Set([...acceptedIds, imageDigest, topDigest])] };
}

export function validateStaticImageManifest(manifest, role, revision, archiveSha256) {
  if (manifest?.format !== "tr-static-runtime-image-v1" || manifest.role !== role
    || manifest.sourceRevision !== revision || manifest.platform !== "linux/arm64"
    || !FINGERPRINT.test(manifest.approvedSignerFingerprint ?? "")
    || !IMAGE.test(manifest.baseImage ?? "")
    || !SHA256.test(manifest.assetsSha256 ?? "")
    || !IMAGE_ID.test(manifest.imageId ?? "")
    || manifest.archiveName !== `${role}.image.tar`
    || manifest.archiveSha256 !== archiveSha256
    || !Array.isArray(manifest.assets) || manifest.assets.length === 0
    || manifest.assets.some((asset) => typeof asset?.path !== "string"
      || !/^[a-zA-Z0-9][a-zA-Z0-9._/-]*\.(?:html|js|css)$/u.test(asset.path)
      || asset.path.split("/").some((part) => part === ".." || part === "." || part === "")
      || !Number.isSafeInteger(asset.size) || asset.size < 1 || asset.size > 32 * 1024 * 1024
      || !SHA256.test(asset.sha256 ?? ""))
    || createHash("sha256").update(JSON.stringify(manifest.assets)).digest("hex")
      !== manifest.assetsSha256) {
    throw new Error(`${role} static image manifest is invalid`);
  }
}
