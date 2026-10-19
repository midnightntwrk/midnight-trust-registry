#!/usr/bin/env node

import { createReadStream } from "node:fs";
import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyReleaseCandidateArtifacts } from "./release-candidate-manifest.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const ROLES = ["node", "indexer", "proof-server"];
const IMAGE = /^[a-z0-9][a-z0-9./_:-]*@sha256:[0-9a-f]{64}$/u;
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
  if (inventory?.format !== "tr-standalone-install-v2"
    || !REVISION.test(inventory.sourceRevision)
    || typeof inventory.packageManifest !== "string"
    || typeof inventory.artifactDirectory !== "string"
    || !Array.isArray(inventory.images)
    || inventory.images.length !== ROLES.length
    || typeof inventory.proofParameters?.directory !== "string"
    || !Array.isArray(inventory.proofParameters?.files)) {
    throw new Error("Standalone install inventory format or required roles are invalid");
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
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    throw new Error("Usage: node scripts/check-standalone-install.mjs <bundle-directory>");
  }
  console.log(JSON.stringify(await verifyStandaloneInstallBundle(process.argv[2])));
}
