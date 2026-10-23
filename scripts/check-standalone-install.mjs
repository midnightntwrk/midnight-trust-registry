#!/usr/bin/env node

import { createReadStream } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

import { verifyReleaseCandidateArtifacts } from "./release-candidate-manifest.mjs";
import { staticImageIdentityFromArchive, validateStaticImageManifest } from "./static-runtime-archive.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const ROLES = ["node", "indexer", "proof-server"];
const IMAGE = /^[a-z0-9][a-z0-9./_:-]*@sha256:[0-9a-f]{64}$/u;
const IMAGE_ID = /^sha256:[0-9a-f]{64}$/u;
const FINGERPRINT = /^[0-9A-F]{40}$/u;

export function pinnedStandaloneImages(composeSource) {
  const compose = yaml.load(composeSource);
  if (compose?.name !== "${TR_STACK_NAME:-tr-standalone-local-smoke}"
    || Object.keys(compose?.services ?? {}).sort().join("\0") !== [...ROLES].sort().join("\0")) {
    throw new Error("Standalone Compose must name the dedicated project and exactly three services");
  }
  return ROLES.map((role) => {
    const reference = compose.services[role]?.image;
    if (typeof reference !== "string" || !IMAGE.test(reference)) {
      throw new Error(`Standalone image is not digest pinned: ${role}`);
    }
    return { role, reference };
  });
}
export const STANDALONE_PROOF_PARAMETER_PATHS = Object.freeze([
  ...[10, 11, 12, 13, 14, 15].map((k) => `bls_midnight_2p${k}`),
  ...["spend.prover", "spend.verifier", "spend.bzkir"].map((name) => `dust/9/${name}`),
  ...["spend", "output", "sign"].flatMap((circuit) =>
    ["prover", "verifier", "bzkir"].map((extension) => `zswap/9/${circuit}.${extension}`)),
].sort());

function bundlePath(root, name) {
  if (typeof name !== "string" || name.length === 0 || isAbsolute(name)
    || name.split("/").some((part) => part === ".." || part === "." || part === "")
    || name.includes("\\")) {
    throw new Error(`Unsafe install-bundle path: ${String(name)}`);
  }
  return join(root, name);
}

async function regularBundleFile(root, name) {
  const path = bundlePath(root, name);
  const stat = await lstat(path);
  if (!stat.isFile() || stat.size === 0) throw new Error(`Install file is missing or not regular: ${name}`);
  const actual = await realpath(path);
  if (actual !== root && !actual.startsWith(`${root}${sep}`)) {
    throw new Error(`Install file escapes bundle: ${name}`);
  }
  return path;
}

async function sha256(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

function archiveMember(archive, member) {
  return execFileSync("tar", ["-xOf", archive, member], {
    encoding: "utf8", timeout: 30_000, maxBuffer: 1024 * 1024,
  });
}

function verifiedArchiveBlob(archive, digest) {
  if (!IMAGE_ID.test(digest)) throw new Error("Container archive blob digest is malformed");
  const bytes = archiveMember(archive, `blobs/sha256/${digest.slice(7)}`);
  if (createHash("sha256").update(bytes).digest("hex") !== digest.slice(7)) {
    throw new Error("Container archive blob bytes disagree with the OCI digest");
  }
  return bytes;
}

/** Checks the saved API image identity without Docker or a registry. */
export function installedApiImageIdFromArchive(archive, manifest, sourceRevision) {
  if (!["tr-api-runtime-image-v1", "tr-api-runtime-image-v2"].includes(manifest?.format)
    || manifest.sourceRevision !== sourceRevision
    || !REVISION.test(manifest.sourceRevision)
    || !FINGERPRINT.test(manifest.approvedSignerFingerprint)
    || manifest.platform !== "linux/arm64"
    || !IMAGE.test(manifest.baseImage)
    || !SHA256.test(manifest.lockfileSha256)
    || !SHA256.test(manifest.dockerfileSha256)
    || !SHA256.test(manifest.payload?.sha256)
    || !Number.isSafeInteger(manifest.payload?.fileCount)
    || manifest.payload.fileCount <= 0
    || !IMAGE_ID.test(manifest.imageId)
    || manifest.archiveName !== "api.image.tar"
    || !SHA256.test(manifest.archiveSha256)) {
    throw new Error("API image manifest is malformed or disagrees with install source");
  }
  if (manifest.format === "tr-api-runtime-image-v2"
    && (Object.keys(manifest.portals ?? {}).sort().join("\0") !== "admin\0applicant"
      || ["admin", "applicant"].some((role) => {
        const portal = manifest.portals[role];
        return !Number.isSafeInteger(portal?.fileCount) || portal.fileCount < 2
          || !SHA256.test(portal?.sha256)
          || Object.keys(portal).sort().join("\0") !== "fileCount\0sha256";
      }))) {
    throw new Error("API image portal manifest is malformed");
  }
  let index;
  try {
    index = JSON.parse(archiveMember(archive, "index.json"));
  } catch {
    throw new Error("API archive lacks a readable OCI index");
  }
  if (index?.schemaVersion !== 2 || index.manifests?.length !== 1
    || index.annotations !== undefined || index.manifests[0]?.annotations !== undefined
    || index.manifests[0]?.digest !== manifest.imageId) {
    throw new Error("API archive OCI index disagrees with the image manifest");
  }
  const imageIndex = JSON.parse(verifiedArchiveBlob(archive, manifest.imageId));
  const architecture = manifest.platform.split("/")[1];
  const imageDescriptors = imageIndex?.manifests?.filter((entry) =>
    entry.platform?.os === "linux" && entry.platform?.architecture === architecture);
  const otherDescriptors = imageIndex?.manifests?.filter((entry) => !imageDescriptors.includes(entry));
  if (imageIndex?.schemaVersion !== 2 || imageIndex.annotations !== undefined
    || imageDescriptors?.length !== 1 || imageDescriptors[0].annotations !== undefined
    || otherDescriptors?.length > 1
    || otherDescriptors?.some((entry) => entry.platform?.os !== "unknown"
      || entry.platform?.architecture !== "unknown"
      || entry.annotations?.["vnd.docker.reference.type"] !== "attestation-manifest"
      || entry.annotations?.["vnd.docker.reference.digest"] !== imageDescriptors[0].digest
      || Object.keys(entry.annotations).sort().join(",")
        !== "vnd.docker.reference.digest,vnd.docker.reference.type")) {
    throw new Error("API archive must contain exactly one image for the approved platform");
  }
  const imageManifest = JSON.parse(verifiedArchiveBlob(archive, imageDescriptors[0].digest));
  if (imageManifest?.schemaVersion !== 2 || !IMAGE_ID.test(imageManifest.config?.digest)
    || !Array.isArray(imageManifest.layers)
    || imageManifest.layers.some((layer) => !IMAGE_ID.test(layer?.digest))) {
    throw new Error("API archive image manifest is malformed");
  }
  const configBytes = verifiedArchiveBlob(archive, imageManifest.config.digest);
  const config = JSON.parse(configBytes);
  const environment = config?.config?.Env ?? [];
  const legacy = JSON.parse(archiveMember(archive, "manifest.json"));
  if (legacy?.length !== 1
    || legacy[0]?.RepoTags !== null
    || legacy[0]?.Config !== `blobs/sha256/${imageManifest.config.digest.slice(7)}`
    || JSON.stringify(legacy[0]?.Layers) !== JSON.stringify(imageManifest.layers?.map((layer) =>
      `blobs/sha256/${layer.digest?.slice(7)}`))) {
    throw new Error("API archive legacy manifest disagrees with OCI image or imports a tag");
  }
  if (config?.os !== "linux" || config.architecture !== architecture
    || config.config?.Labels?.["org.opencontainers.image.revision"] !== sourceRevision
    || config.config?.User !== "1000:1000"
    || config.config?.WorkingDir !== "/app"
    || JSON.stringify(config.config?.Entrypoint) !== JSON.stringify(["node", "/app/bin/trust-registry-api.mjs"])
    || config.config?.Cmd != null || config.config?.Healthcheck != null
    || config.config?.OnBuild != null || config.config?.Volumes != null
    || !Array.isArray(environment) || environment.some((entry) => typeof entry !== "string"
      || /^(?:NODE_OPTIONS|NODE_PATH|LD_PRELOAD|LD_LIBRARY_PATH)=/u.test(entry))) {
    throw new Error("API archive runtime config disagrees with the approved source or entrypoint");
  }
  return { imageId: manifest.imageId, configId: imageManifest.config.digest };
}

export function installedImageIdFromArchive(archive, reference) {
  const expected = reference.split("@sha256:")[1];
  const source = reference.split("@sha256:")[0];
  let index;
  try {
    index = JSON.parse(archiveMember(archive, "index.json"));
  } catch {
    throw new Error("Container archive lacks a readable OCI index");
  }
  const annotations = index?.manifests?.[0]?.annotations;
  const approvedSource = annotations === undefined
    || (Object.keys(annotations).length === 1
      && annotations["containerd.io/distribution.source.docker.io"] === source);
  if (index?.schemaVersion !== 2 || index.manifests?.length !== 1
    || index.annotations !== undefined || !approvedSource
    || index.manifests[0]?.digest !== `sha256:${expected}`) {
    throw new Error("Container archive OCI manifest digest disagrees with the approved image pin");
  }
  const manifest = archiveMember(archive, `blobs/sha256/${expected}`);
  if (createHash("sha256").update(manifest).digest("hex") !== expected) {
    throw new Error("Container archive OCI manifest bytes disagree with the approved image pin");
  }
  let legacy;
  let oci;
  try {
    legacy = JSON.parse(archiveMember(archive, "manifest.json"));
    oci = JSON.parse(manifest);
  } catch {
    throw new Error("Container archive lacks a readable image config manifest");
  }
  const configPath = legacy?.length === 1 ? legacy[0]?.Config : undefined;
  const configDigest = /^blobs\/sha256\/([0-9a-f]{64})$/u.exec(configPath ?? "")?.[1];
  if (!configDigest || oci?.config?.digest !== `sha256:${configDigest}`) {
    throw new Error("Container archive config digest disagrees with the OCI manifest");
  }
  if (legacy[0].RepoTags !== null && legacy[0].RepoTags?.length !== 0) {
    throw new Error("Container archive must not contain implicit image tags");
  }
  const config = archiveMember(archive, configPath);
  if (createHash("sha256").update(config).digest("hex") !== configDigest) {
    throw new Error("Container archive image config bytes disagree with the OCI manifest");
  }
  if (JSON.parse(config)?.architecture !== "arm64") {
    throw new Error("Container archive must contain the approved arm64 image");
  }
  return `sha256:${configDigest}`;
}

async function regularFiles(directory, prefix = "") {
  const files = [];
  for (const entry of await readdir(join(directory, prefix), { withFileTypes: true })) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...await regularFiles(directory, name));
    else if (entry.isFile()) files.push(name);
    else throw new Error(`Proof parameter inventory contains a non-regular entry: ${name}`);
  }
  return files.sort();
}

/** Verifies staged bytes only. It does not prove image provenance, deployment, or offline behavior. */
export async function verifyStandaloneInstallBundle(bundleRoot, verifyPackages = verifyReleaseCandidateArtifacts) {
  const root = await realpath(resolve(bundleRoot));
  const inventoryBytes = await readFile(await regularBundleFile(root, "install-inventory.json"));
  const inventorySha256 = createHash("sha256").update(inventoryBytes).digest("hex");
  const inventory = JSON.parse(inventoryBytes.toString("utf8"));
  if (!["tr-standalone-install-v2", "tr-standalone-install-v3", "tr-standalone-install-v4",
    "tr-standalone-install-v5", "tr-standalone-install-v6"].includes(inventory?.format)
    || !REVISION.test(inventory.sourceRevision)
    || typeof inventory.packageManifest !== "string"
    || typeof inventory.artifactDirectory !== "string"
    || !Array.isArray(inventory.images)
    || inventory.images.length !== ROLES.length
    || typeof inventory.proofParameters?.directory !== "string"
    || !Array.isArray(inventory.proofParameters?.files)) {
    throw new Error("Standalone install inventory format or required roles are invalid");
  }
  let runtimeComposeSha256 = null;
  let runtimeOfflineComposeSha256 = null;
  if (["tr-standalone-install-v3", "tr-standalone-install-v4",
    "tr-standalone-install-v5", "tr-standalone-install-v6"].includes(inventory.format)) {
    if (inventory.runtimeCompose?.path !== "compose.yml"
      || !SHA256.test(inventory.runtimeCompose.sha256)
      || inventory.runtimeCompose.offlinePath !== "compose.offline.yml"
      || !SHA256.test(inventory.runtimeCompose.offlineSha256)) {
      throw new Error("Standalone runtime Compose pin is missing or malformed");
    }
    const composeFile = await regularBundleFile(root, inventory.runtimeCompose.path);
    const offlineComposeFile = await regularBundleFile(root, inventory.runtimeCompose.offlinePath);
    if (await sha256(composeFile) !== inventory.runtimeCompose.sha256
      || await sha256(offlineComposeFile) !== inventory.runtimeCompose.offlineSha256) {
      throw new Error("Standalone runtime Compose bytes disagree with the install pin");
    }
    const pinnedImages = pinnedStandaloneImages(await readFile(composeFile, "utf8"));
    if (pinnedImages.some(({ role, reference }) => !inventory.images.some((image) =>
      image?.role === role && image.reference === reference))) {
      throw new Error("Standalone image inventory disagrees with the runtime Compose pin");
    }
    runtimeComposeSha256 = inventory.runtimeCompose.sha256;
    runtimeOfflineComposeSha256 = inventory.runtimeCompose.offlineSha256;
  }
  const imageRoles = inventory.images.map((image) => image?.role).sort();
  if (imageRoles.join("\0") !== [...ROLES].sort().join("\0")) {
    throw new Error("Standalone install inventory must pin node, indexer, and proof-server exactly once");
  }
  if (new Set(inventory.images.map((image) => image.archive)).size !== inventory.images.length) {
    throw new Error("Each container role requires a distinct pinned archive");
  }
  const packageManifestBytes = await readFile(await regularBundleFile(root, inventory.packageManifest));
  const packageManifestSha256 = createHash("sha256").update(packageManifestBytes).digest("hex");
  if (inventory.format !== "tr-standalone-install-v2"
    && (!SHA256.test(inventory.packageManifestSha256 ?? "")
      || packageManifestSha256 !== inventory.packageManifestSha256)) {
    throw new Error("Standalone release manifest bytes disagree with the install pin");
  }
  const packageManifest = JSON.parse(packageManifestBytes.toString("utf8"));
  if (packageManifest.sourceRevision !== inventory.sourceRevision) {
    throw new Error("Standalone install source revision disagrees with the package manifest");
  }
  const artifactDirectory = bundlePath(root, inventory.artifactDirectory);
  const artifactRoot = await realpath(artifactDirectory);
  if (artifactRoot !== root && !artifactRoot.startsWith(`${root}${sep}`)) {
    throw new Error("Artifact directory escapes the install bundle");
  }
  verifyPackages(packageManifest, artifactRoot);
  const verifiedImages = [];
  for (const image of inventory.images) {
    if (!IMAGE.test(image.reference) || !SHA256.test(image.archiveSha256)) {
      throw new Error(`Unpinned or invalid container image: ${image.role}`);
    }
    const archive = await regularBundleFile(root, image.archive);
    if (await sha256(archive) !== image.archiveSha256) {
      throw new Error(`Container archive hash mismatch: ${image.role}`);
    }
    const configId = installedImageIdFromArchive(archive, image.reference);
    verifiedImages.push({ role: image.role, reference: image.reference, configId,
      acceptedIds: [...new Set([configId, `sha256:${image.reference.split("@sha256:")[1]}`])] });
  }
  let apiRuntime = null;
  let apiManifest = null;
  if (["tr-standalone-install-v4", "tr-standalone-install-v5",
    "tr-standalone-install-v6"].includes(inventory.format)) {
    if (inventory.apiRuntime?.manifest !== "images/api.manifest.json"
      || inventory.apiRuntime.archive !== "images/api.image.tar"
      || !SHA256.test(inventory.apiRuntime.manifestSha256)
      || !SHA256.test(inventory.apiRuntime.archiveSha256)) {
      throw new Error("Standalone API image pin is missing or malformed");
    }
    const manifestPath = await regularBundleFile(root, inventory.apiRuntime.manifest);
    const archivePath = await regularBundleFile(root, inventory.apiRuntime.archive);
    if (await sha256(manifestPath) !== inventory.apiRuntime.manifestSha256
      || await sha256(archivePath) !== inventory.apiRuntime.archiveSha256) {
      throw new Error("Standalone API image bytes disagree with the install pin");
    }
    apiManifest = JSON.parse(await readFile(manifestPath, "utf8"));
    if (apiManifest.archiveSha256 !== inventory.apiRuntime.archiveSha256) {
      throw new Error("Standalone API image archive disagrees with its build manifest");
    }
    apiRuntime = { ...installedApiImageIdFromArchive(archivePath, apiManifest,
      inventory.sourceRevision), platform: apiManifest.platform };
  }
  let portalRuntimes = null;
  if (["tr-standalone-install-v5", "tr-standalone-install-v6"].includes(inventory.format)) {
    if (Object.keys(inventory.portalRuntimes ?? {}).sort().join("\0") !== "admin\0applicant") {
      throw new Error("Standalone v5/v6 install requires both portal image pins");
    }
    portalRuntimes = {};
    for (const role of ["admin", "applicant"]) {
      const pin = inventory.portalRuntimes[role];
      if (pin?.manifest !== `images/${role}.manifest.json`
        || pin.archive !== `images/${role}.image.tar`
        || !SHA256.test(pin.manifestSha256) || !SHA256.test(pin.archiveSha256)) {
        throw new Error(`${role} portal image pin is missing or malformed`);
      }
      const manifestPath = await regularBundleFile(root, pin.manifest);
      const archivePath = await regularBundleFile(root, pin.archive);
      if (await sha256(manifestPath) !== pin.manifestSha256
        || await sha256(archivePath) !== pin.archiveSha256) {
        throw new Error(`${role} portal image bytes disagree with the install pin`);
      }
      const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
      validateStaticImageManifest(manifest, role, inventory.sourceRevision, pin.archiveSha256);
      if (apiManifest?.format === "tr-api-runtime-image-v2"
        && (apiManifest.portals[role].fileCount !== manifest.assets.length
          || apiManifest.portals[role].sha256 !== manifest.assetsSha256)) {
        throw new Error(`${role} API portal assets disagree with pinned static portal image`);
      }
      const identity = staticImageIdentityFromArchive(archivePath, role,
        inventory.sourceRevision, true);
      if (manifest.imageId !== identity.topDigest) {
        throw new Error(`${role} portal archive OCI identity disagrees with its manifest`);
      }
      portalRuntimes[role] = { ...identity, imageId: manifest.imageId,
        archiveSha256: pin.archiveSha256, platform: manifest.platform };
    }
  }
  let installRelay = null;
  if (inventory.format === "tr-standalone-install-v6") {
    if (inventory.installRelay?.path !== "install-relay.py"
      || !SHA256.test(inventory.installRelay.sha256)
      || inventory.installRelay.imageRole !== "node") {
      throw new Error("Standalone installation relay pin is missing or malformed");
    }
    const relayPath = await regularBundleFile(root, inventory.installRelay.path);
    if (await sha256(relayPath) !== inventory.installRelay.sha256) {
      throw new Error("Standalone installation relay bytes disagree with the install pin");
    }
    installRelay = { path: relayPath, sha256: inventory.installRelay.sha256,
      image: verifiedImages.find((image) => image.role === "node") };
  }
  const proofDirectory = bundlePath(root, inventory.proofParameters.directory);
  if (!(await lstat(proofDirectory)).isDirectory()) {
    throw new Error("Proof parameter directory must be a regular directory");
  }
  const proofRoot = await realpath(proofDirectory);
  if (proofRoot !== root && !proofRoot.startsWith(`${root}${sep}`)) {
    throw new Error("Proof parameter directory escapes the install bundle");
  }
  const parameterFiles = inventory.proofParameters.files;
  const pinnedNames = parameterFiles.map((file) => file?.path).sort();
  if (pinnedNames.join("\0") !== STANDALONE_PROOF_PARAMETER_PATHS.join("\0")
    || (await regularFiles(proofRoot)).join("\0") !== STANDALONE_PROOF_PARAMETER_PATHS.join("\0")) {
    throw new Error("Standalone proof parameter inventory is incomplete or has extra files");
  }
  for (const file of parameterFiles) {
    if (!SHA256.test(file.sha256)) throw new Error(`Invalid proof parameter hash: ${file.path}`);
    const path = await regularBundleFile(root, `${inventory.proofParameters.directory}/${file.path}`);
    if (await sha256(path) !== file.sha256) {
      throw new Error(`Proof parameter hash mismatch: ${file.path}`);
    }
  }
  return {
    sourceRevision: inventory.sourceRevision,
    inventorySha256,
    packageManifestSha256,
    packageCount: packageManifest.packages?.length,
    imageRoles,
    proofParameterCount: parameterFiles.length,
    runtimeComposeSha256,
    runtimeOfflineComposeSha256,
    images: verifiedImages,
    apiRuntime,
    portalRuntimes,
    installRelay,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    throw new Error("Usage: node scripts/check-standalone-install.mjs <bundle-directory>");
  }
  console.log(JSON.stringify(await verifyStandaloneInstallBundle(process.argv[2])));
}
