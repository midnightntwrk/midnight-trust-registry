#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { constants as fsConstants, createReadStream } from "node:fs";
import {
  copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { KEYLESS_KEYGEN_PARAMETER_PATHS, PROTOCOL_KEY_PATHS, STANDALONE_PROOF_PARAMETER_PATHS,
  pinnedStandaloneImages, verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { buildReleaseCandidateManifest } from "./release-candidate-manifest.mjs";
import { artifactWorkspaces, packageManifestCatalog } from "./trust-registry-workspace-catalog.mjs";
import { verifyKeylessZkirAgainstFullSource } from "./keyless-zkir-bundle.mjs";

export { pinnedStandaloneImages } from "./check-standalone-install.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** @typedef {{outputRoot?: string, proofSource?: string, apiImageDirectory?: string,
 * adminImageDirectory?: string, applicantImageDirectory?: string,
 * keylessDirectory?: string, keylessManifestSha256?: string, keygenBinary?: string}} StandaloneInstallBuildOptions */

/** @param {string} program @param {string[]} args */
function command(program, args) {
  return execFileSync(program, args, {
    cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
    timeout: 30 * 60_000, maxBuffer: 8 * 1024 * 1024,
  }).trim();
}

/** @param {string} path */
async function sha256(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

function verifiedSourceRevision() {
  if (command("git", ["status", "--porcelain", "--untracked-files=normal"]) !== "") {
    throw new Error("Build the install bundle from a clean source tree");
  }
  command("git", ["verify-commit", "HEAD"]);
  if (!/^Signed-off-by: .+ <[^>]+>$/mu.test(command("git", ["log", "-1", "--format=%B"]))) {
    throw new Error("Install source commit requires a DCO sign-off");
  }
  command("node", ["scripts/check-full-contract-artifacts.mjs"]);
  return command("git", ["rev-parse", "HEAD"]);
}

/** @param {string} repoRoot @param {typeof artifactWorkspaces} [workspaces] */
export function assertRequiredWorkspaceFiles(repoRoot, workspaces = artifactWorkspaces) {
  for (const workspace of workspaces) {
    const required = packageManifestCatalog.get(workspace)?.requiredPackedPaths;
    if (!Array.isArray(required) || required.length === 0) {
      throw new Error(`Install package has no required-path catalog: ${workspace}`);
    }
    for (const path of required) {
      const file = join(repoRoot, workspace, path);
      if (!existsSync(file) || !lstatSync(file).isFile()) {
        throw new Error(`${workspace}: required package file is missing before install build: ${path}`);
      }
    }
  }
}

/** @param {string} inputDirectory @param {string} sourceRevision */
export function validateApiRuntimeImageInput(inputDirectory, sourceRevision) {
  if (!isAbsolute(inputDirectory)) throw new Error("API image directory must be absolute");
  const source = resolve(inputDirectory);
  const manifestSource = join(source, "manifest.json");
  const archiveSource = join(source, "api.image.tar");
  if (!lstatSync(manifestSource).isFile() || !lstatSync(archiveSource).isFile()) {
    throw new Error("API image input must contain regular manifest and archive files");
  }
  const apiManifest = JSON.parse(readFileSync(manifestSource, "utf8"));
  if (apiManifest.sourceRevision !== sourceRevision || apiManifest.archiveName !== "api.image.tar") {
    throw new Error("API image source revision or archive name disagrees with install source");
  }
  return { manifestSource, archiveSource };
}

/** @param {string} inputDirectory @param {string} destination @param {string} sourceRevision */
export async function stageApiRuntimeImage(inputDirectory, destination, sourceRevision) {
  const { manifestSource, archiveSource } = validateApiRuntimeImageInput(inputDirectory, sourceRevision);
  const manifest = "images/api.manifest.json";
  const archive = "images/api.image.tar";
  copyFileSync(manifestSource, join(destination, manifest), fsConstants.COPYFILE_EXCL);
  copyFileSync(archiveSource, join(destination, archive), fsConstants.COPYFILE_EXCL);
  return { manifest, manifestSha256: await sha256(join(destination, manifest)),
    archive, archiveSha256: await sha256(join(destination, archive)) };
}

/** @param {string} inputDirectory @param {string} role @param {string} sourceRevision */
export function validateStaticRuntimeImageInput(inputDirectory, role, sourceRevision) {
  if (!isAbsolute(inputDirectory) || !["admin", "applicant"].includes(role)) {
    throw new Error("Static image directory must be absolute and role must be approved");
  }
  const source = resolve(inputDirectory);
  const manifestSource = join(source, "manifest.json");
  const archiveSource = join(source, `${role}.image.tar`);
  if (!lstatSync(manifestSource).isFile() || !lstatSync(archiveSource).isFile()) {
    throw new Error(`${role} static image input must contain regular manifest and archive files`);
  }
  const manifest = JSON.parse(readFileSync(manifestSource, "utf8"));
  if (manifest.role !== role || manifest.sourceRevision !== sourceRevision
    || manifest.archiveName !== `${role}.image.tar`) {
    throw new Error(`${role} static image source, role, or archive name disagrees with install source`);
  }
  return { manifestSource, archiveSource };
}

/** @param {string} inputDirectory @param {string} destination @param {string} role
 * @param {string} sourceRevision */
export async function stageStaticRuntimeImage(inputDirectory, destination, role, sourceRevision) {
  const { manifestSource, archiveSource } = validateStaticRuntimeImageInput(
    inputDirectory, role, sourceRevision);
  const manifest = `images/${role}.manifest.json`;
  const archive = `images/${role}.image.tar`;
  copyFileSync(manifestSource, join(destination, manifest), fsConstants.COPYFILE_EXCL);
  copyFileSync(archiveSource, join(destination, archive), fsConstants.COPYFILE_EXCL);
  return { manifest, manifestSha256: await sha256(join(destination, manifest)),
    archive, archiveSha256: await sha256(join(destination, archive)) };
}

/** @param {StandaloneInstallBuildOptions} options @param {string} sourceRevision
 * @param {(reference: string) => unknown} [inspectImage] */
export function validateStandaloneInstallInputs(options, sourceRevision, inspectImage = (reference) =>
  JSON.parse(command("docker", ["image", "inspect", reference, "--format", "{{json .RepoDigests}}"]))) {
  const { apiImageDirectory, adminImageDirectory, applicantImageDirectory,
    keylessDirectory, keylessManifestSha256, keygenBinary } = options;
  if ([keylessDirectory, keylessManifestSha256, keygenBinary].some((value) => value !== undefined)) {
    if (!keylessDirectory || !keylessManifestSha256 || !keygenBinary
      || !isAbsolute(keylessDirectory) || !isAbsolute(keygenBinary)
      || !/^[0-9a-f]{64}$/u.test(keylessManifestSha256)
      || !lstatSync(join(keylessDirectory, "keyless-manifest.json")).isFile()
      || !lstatSync(keygenBinary).isFile()
      || !apiImageDirectory || !adminImageDirectory || !applicantImageDirectory) {
      throw new Error("Keyless v7 install requires a complete absolute manifest, generator, and three runtime image directories");
    }
  }
  const staticDirectories = [adminImageDirectory, applicantImageDirectory];
  if (staticDirectories.some((directory) => directory !== undefined)
    && (staticDirectories.some((directory) => directory === undefined)
      || apiImageDirectory === undefined)) {
    throw new Error("A v5 install requires API, admin, and applicant image directories together");
  }
  if (apiImageDirectory !== undefined) {
    validateApiRuntimeImageInput(apiImageDirectory, sourceRevision);
  }
  if (adminImageDirectory !== undefined && applicantImageDirectory !== undefined) {
    validateStaticRuntimeImageInput(adminImageDirectory, "admin", sourceRevision);
    validateStaticRuntimeImageInput(applicantImageDirectory, "applicant", sourceRevision);
  }
  const outputRoot = resolve(options.outputRoot ?? join(root, "artifacts/standalone-install"));
  const proofSource = resolve(options.proofSource ?? join(root, "artifacts/standalone-proof-params"));
  if ((options.outputRoot && !isAbsolute(options.outputRoot))
    || (options.proofSource && !isAbsolute(options.proofSource))) {
    throw new Error("Explicit install paths must be absolute");
  }
  const destination = join(outputRoot, sourceRevision);
  if (existsSync(destination)) throw new Error("Install bundle already exists; do not overwrite release bytes");
  const proofCatalog = keylessDirectory === undefined ? STANDALONE_PROOF_PARAMETER_PATHS
    : [...KEYLESS_KEYGEN_PARAMETER_PATHS, ...PROTOCOL_KEY_PATHS];
  for (const name of proofCatalog) {
    const source = join(proofSource, name);
    if (!existsSync(source) || !lstatSync(source).isFile()) {
      throw new Error(`Proof parameter is missing or not a regular file: ${name}`);
    }
  }
  const pinned = pinnedStandaloneImages(readFileSync(join(root, "deploy/standalone/compose.yml"), "utf8"));
  for (const { role, reference } of pinned) {
    const digests = inspectImage(reference);
    if (!Array.isArray(digests) || !digests.includes(reference)) {
      throw new Error(`Local image does not retain approved repository digest: ${role}`);
    }
  }
  return { sourceRevision, outputRoot, proofSource, destination, pinned,
    apiImageDirectory, adminImageDirectory, applicantImageDirectory,
    keylessDirectory, keylessManifestSha256, keygenBinary };
}

/** @param {StandaloneInstallBuildOptions} [options] */
export function preflightStandaloneInstall(options = {}) {
  const sourceRevision = verifiedSourceRevision();
  assertRequiredWorkspaceFiles(root);
  return validateStandaloneInstallInputs(options, sourceRevision);
}

/** Creates a fresh bundle only; failed output is retained for inspection. */
/** @param {StandaloneInstallBuildOptions} [options] */
export async function buildStandaloneInstall(options = {}) {
  const { sourceRevision, outputRoot, proofSource, destination, pinned,
    apiImageDirectory, adminImageDirectory, applicantImageDirectory,
    keylessDirectory, keylessManifestSha256, keygenBinary } = preflightStandaloneInstall(options);
  let keyless = null;
  if (keylessDirectory !== undefined && keylessManifestSha256 !== undefined
    && keygenBinary !== undefined) {
    keyless = await verifyKeylessZkirAgainstFullSource(keylessDirectory,
      join(root, "contracts/trust-registry/dist/managed/trust-registry"),
      keylessManifestSha256, sourceRevision);
    if (keyless.manifest.platform !== "linux/arm64"
      || await sha256(keygenBinary) !== keyless.manifest.keygenSha256) {
      throw new Error("Keyless release requires the pinned Linux/arm64 generator binary");
    }
  }
  mkdirSync(outputRoot, { recursive: true });
  mkdirSync(destination, { mode: 0o700 });
  const packages = join(destination, "packages");
  mkdirSync(packages);
  command("node", ["scripts/pack-artifacts.mjs", "--output-dir", packages,
    ...(keyless === null || keylessDirectory === undefined || keylessManifestSha256 === undefined
      ? [] : ["--keyless-dir", keylessDirectory,
        "--keyless-manifest-sha256", keylessManifestSha256])]);
  const manifest = buildReleaseCandidateManifest({ repoRoot: root, artifactDir: packages,
    revision: sourceRevision, ...(keyless === null ? {} : { keylessManifestSha256 }) });
  writeFileSync(join(destination, "release-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`,
    { flag: "wx", mode: 0o600 });
  const composeSource = join(root, "deploy/standalone/compose.yml");
  const composeTarget = join(destination, "compose.yml");
  copyFileSync(composeSource, composeTarget, fsConstants.COPYFILE_EXCL);
  const offlineComposeTarget = join(destination, "compose.offline.yml");
  copyFileSync(join(root, "deploy/standalone/compose.offline.yml"), offlineComposeTarget,
    fsConstants.COPYFILE_EXCL);
  let apiComposeTarget;
  if (apiImageDirectory !== undefined) {
    apiComposeTarget = join(destination, "compose.api.yml");
    copyFileSync(join(root, "deploy/standalone/compose.api.yml"), apiComposeTarget,
      fsConstants.COPYFILE_EXCL);
  }
  const runtimeCompose = {
    path: "compose.yml", sha256: await sha256(composeTarget),
    offlinePath: "compose.offline.yml", offlineSha256: await sha256(offlineComposeTarget),
    ...(apiComposeTarget === undefined ? {} : {
      apiPath: "compose.api.yml", apiSha256: await sha256(apiComposeTarget),
    }),
  };

  const proofDirectory = join(destination, "proof-params");
  const proofFiles = [];
  for (const name of keyless === null ? STANDALONE_PROOF_PARAMETER_PATHS
    : KEYLESS_KEYGEN_PARAMETER_PATHS) {
    const source = join(proofSource, name);
    if (!lstatSync(source).isFile()) throw new Error(`Proof parameter is not a regular file: ${name}`);
    const target = join(proofDirectory, name);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(source, target);
    proofFiles.push({ path: name, sha256: await sha256(target) });
  }

  const images = [];
  const stagedPinned = pinnedStandaloneImages(readFileSync(composeTarget, "utf8"));
  if (JSON.stringify(stagedPinned) !== JSON.stringify(pinned)) {
    throw new Error("Runtime Compose image pins changed after preflight");
  }
  mkdirSync(join(destination, "images"));
  for (const { role, reference } of pinned) {
    const digests = JSON.parse(command("docker", ["image", "inspect", reference,
      "--format", "{{json .RepoDigests}}"]));
    if (!Array.isArray(digests) || !digests.includes(reference)) {
      throw new Error(`Local image does not retain approved repository digest: ${role}`);
    }
    const archive = `images/${role}.tar`;
    const partial = join(destination, `${archive}.partial`);
    command("docker", ["save", "--output", partial, reference]);
    renameSync(partial, join(destination, archive));
    images.push({ role, reference, archive, archiveSha256: await sha256(join(destination, archive)) });
  }

  let apiRuntime;
  if (apiImageDirectory !== undefined) {
    apiRuntime = await stageApiRuntimeImage(apiImageDirectory, destination, sourceRevision);
  }
  let portalRuntimes;
  if (adminImageDirectory !== undefined && applicantImageDirectory !== undefined) {
    portalRuntimes = {
      admin: await stageStaticRuntimeImage(adminImageDirectory, destination,
        "admin", sourceRevision),
      applicant: await stageStaticRuntimeImage(applicantImageDirectory, destination,
        "applicant", sourceRevision),
    };
  }

  let installRelay;
  if (portalRuntimes) {
    const path = "install-relay.mjs";
    copyFileSync(join(root, "deploy/standalone/local-install-relay.mjs"), join(destination, path),
      fsConstants.COPYFILE_EXCL);
    installRelay = { path, sha256: await sha256(join(destination, path)), imageRole: "api" };
  }

  let keylessRuntime;
  if (keyless !== null && keygenBinary !== undefined) {
    const path = "keygen/zkir";
    mkdirSync(join(destination, "keygen"));
    copyFileSync(keygenBinary, join(destination, path), fsConstants.COPYFILE_EXCL);
    keylessRuntime = { path, sha256: await sha256(join(destination, path)),
      platform: "linux/arm64", manifestSha256: keylessManifestSha256,
      protocolKeys: Object.fromEntries(await Promise.all(PROTOCOL_KEY_PATHS.map(async (name) =>
        [name, await sha256(join(proofSource, name))]))),
    };
  }

  const inventory = {
    format: keylessRuntime ? "tr-standalone-install-v7"
      : portalRuntimes ? "tr-standalone-install-v6"
      : apiRuntime ? "tr-standalone-install-v4" : "tr-standalone-install-v3", sourceRevision,
    packageManifest: "release-manifest.json",
    packageManifestSha256: await sha256(join(destination, "release-manifest.json")),
    artifactDirectory: "packages",
    runtimeCompose, images, proofParameters: { directory: "proof-params", files: proofFiles },
    ...(apiRuntime ? { apiRuntime } : {}),
    ...(portalRuntimes ? { portalRuntimes } : {}),
    ...(installRelay ? { installRelay } : {}),
    ...(keylessRuntime ? { keylessRuntime } : {}),
  };
  writeFileSync(join(destination, "install-inventory.json"), `${JSON.stringify(inventory, null, 2)}\n`,
    { flag: "wx", mode: 0o600 });
  await verifyStandaloneInstallBundle(destination);
  return { kind: "standalone-install-bundle-verification", sourceRevision, path: destination,
    packageCount: manifest.packages.length,
    imageCount: images.length + (apiRuntime ? 1 : 0) + (portalRuntimes ? 2 : 0),
    proofParameterCount: proofFiles.length };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const preflight = args[0] === "--preflight";
  if (preflight) args.shift();
  if (args.length !== 0 && (args.length !== 2 || args[0] !== "--api-image-dir")
    && (args.length !== 6 || args[0] !== "--api-image-dir"
      || args[2] !== "--admin-image-dir" || args[4] !== "--applicant-image-dir")
    && (args.length !== 12 || args[0] !== "--api-image-dir"
      || args[2] !== "--admin-image-dir" || args[4] !== "--applicant-image-dir"
      || args[6] !== "--keyless-dir" || args[8] !== "--keyless-manifest-sha256"
      || args[10] !== "--keygen-bin")) {
    throw new Error("Usage: node scripts/build-standalone-install.mjs [--preflight] [--api-image-dir <dir> --admin-image-dir <dir> --applicant-image-dir <dir> [--keyless-dir <dir> --keyless-manifest-sha256 <sha256> --keygen-bin <linux-arm64-zkir>]]");
  }
  const options = { apiImageDirectory: args[1], adminImageDirectory: args[3],
    applicantImageDirectory: args[5], keylessDirectory: args[7],
    keylessManifestSha256: args[9], keygenBinary: args[11] };
  console.log(JSON.stringify(preflight ? preflightStandaloneInstall(options)
    : await buildStandaloneInstall(options)));
}
