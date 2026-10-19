#!/usr/bin/env node

import { createReadStream } from "node:fs";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

import { verifyReleaseCandidateArtifacts } from "./release-candidate-manifest.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const ROLES = ["node", "indexer", "proof-server"];
const IMAGE = /^[a-z0-9][a-z0-9./_:-]*@sha256:[0-9a-f]{64}$/u;
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

export function installedImageIdFromArchive(archive, reference) {
  const expected = reference.split("@sha256:")[1];
  let index;
  try {
    index = JSON.parse(archiveMember(archive, "index.json"));
  } catch {
    throw new Error("Container archive lacks a readable OCI index");
  }
  if (index?.schemaVersion !== 2 || index.manifests?.length !== 1
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
  const inventory = JSON.parse(await readFile(await regularBundleFile(root, "install-inventory.json"), "utf8"));
  if (!["tr-standalone-install-v2", "tr-standalone-install-v3"].includes(inventory?.format)
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
  if (inventory.format === "tr-standalone-install-v3") {
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
      image.role === role && image.reference === reference))) {
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
  const packageManifest = JSON.parse(await readFile(
    await regularBundleFile(root, inventory.packageManifest), "utf8",
  ));
  if (packageManifest.sourceRevision !== inventory.sourceRevision) {
    throw new Error("Standalone install source revision disagrees with the package manifest");
  }
  const artifactDirectory = bundlePath(root, inventory.artifactDirectory);
  const artifactRoot = await realpath(artifactDirectory);
  if (artifactRoot !== root && !artifactRoot.startsWith(`${root}${sep}`)) {
    throw new Error("Artifact directory escapes the install bundle");
  }
  verifyPackages(packageManifest, artifactRoot);
  for (const image of inventory.images) {
    if (!IMAGE.test(image.reference) || !SHA256.test(image.archiveSha256)) {
      throw new Error(`Unpinned or invalid container image: ${image.role}`);
    }
    const archive = await regularBundleFile(root, image.archive);
    if (await sha256(archive) !== image.archiveSha256) {
      throw new Error(`Container archive hash mismatch: ${image.role}`);
    }
    installedImageIdFromArchive(archive, image.reference);
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
    packageCount: packageManifest.packages?.length,
    imageRoles,
    proofParameterCount: parameterFiles.length,
    runtimeComposeSha256,
    runtimeOfflineComposeSha256,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    throw new Error("Usage: node scripts/check-standalone-install.mjs <bundle-directory>");
  }
  console.log(JSON.stringify(await verifyStandaloneInstallBundle(process.argv[2])));
}
