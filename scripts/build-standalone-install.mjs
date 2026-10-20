#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { constants as fsConstants, createReadStream } from "node:fs";
import {
  copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { STANDALONE_PROOF_PARAMETER_PATHS, pinnedStandaloneImages, verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { buildReleaseCandidateManifest } from "./release-candidate-manifest.mjs";

export { pinnedStandaloneImages } from "./check-standalone-install.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function command(program, args, options = {}) {
  return execFileSync(program, args, {
    cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
    timeout: 30 * 60_000, maxBuffer: 8 * 1024 * 1024, ...options,
  }).trim();
}

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

export async function stageApiRuntimeImage(inputDirectory, destination, sourceRevision) {
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
  const manifest = "images/api.manifest.json";
  const archive = "images/api.image.tar";
  copyFileSync(manifestSource, join(destination, manifest), fsConstants.COPYFILE_EXCL);
  copyFileSync(archiveSource, join(destination, archive), fsConstants.COPYFILE_EXCL);
  return { manifest, manifestSha256: await sha256(join(destination, manifest)),
    archive, archiveSha256: await sha256(join(destination, archive)) };
}

/** Creates a fresh bundle only; failed output is retained for inspection. */
export async function buildStandaloneInstall(options = {}) {
  const sourceRevision = verifiedSourceRevision();
  const outputRoot = resolve(options.outputRoot ?? join(root, "artifacts/standalone-install"));
  const proofSource = resolve(options.proofSource ?? join(root, "artifacts/standalone-proof-params"));
  if ((options.outputRoot && !isAbsolute(options.outputRoot))
    || (options.proofSource && !isAbsolute(options.proofSource))) {
    throw new Error("Explicit install paths must be absolute");
  }
  const destination = join(outputRoot, sourceRevision);
  mkdirSync(outputRoot, { recursive: true });
  if (existsSync(destination)) throw new Error("Install bundle already exists; do not overwrite release bytes");
  mkdirSync(destination, { mode: 0o700 });
  const packages = join(destination, "packages");
  mkdirSync(packages);
  command("node", ["scripts/pack-artifacts.mjs", "--output-dir", packages]);
  const manifest = buildReleaseCandidateManifest({ repoRoot: root, artifactDir: packages,
    revision: sourceRevision });
  writeFileSync(join(destination, "release-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`,
    { flag: "wx", mode: 0o600 });
  const composeSource = join(root, "deploy/standalone/compose.yml");
  const composeTarget = join(destination, "compose.yml");
  copyFileSync(composeSource, composeTarget, fsConstants.COPYFILE_EXCL);
  const offlineComposeTarget = join(destination, "compose.offline.yml");
  copyFileSync(join(root, "deploy/standalone/compose.offline.yml"), offlineComposeTarget,
    fsConstants.COPYFILE_EXCL);
  const runtimeCompose = {
    path: "compose.yml", sha256: await sha256(composeTarget),
    offlinePath: "compose.offline.yml", offlineSha256: await sha256(offlineComposeTarget),
  };

  const proofDirectory = join(destination, "proof-params");
  const proofFiles = [];
  for (const name of STANDALONE_PROOF_PARAMETER_PATHS) {
    const source = join(proofSource, name);
    if (!lstatSync(source).isFile()) throw new Error(`Proof parameter is not a regular file: ${name}`);
    const target = join(proofDirectory, name);
    mkdirSync(dirname(target), { recursive: true });
    copyFileSync(source, target);
    proofFiles.push({ path: name, sha256: await sha256(target) });
  }

  const images = [];
  const pinned = pinnedStandaloneImages(readFileSync(composeTarget, "utf8"));
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
  if (options.apiImageDirectory !== undefined) {
    apiRuntime = await stageApiRuntimeImage(options.apiImageDirectory, destination, sourceRevision);
  }

  const inventory = {
    format: apiRuntime ? "tr-standalone-install-v4" : "tr-standalone-install-v3", sourceRevision,
    packageManifest: "release-manifest.json", artifactDirectory: "packages",
    runtimeCompose, images, proofParameters: { directory: "proof-params", files: proofFiles },
    ...(apiRuntime ? { apiRuntime } : {}),
  };
  writeFileSync(join(destination, "install-inventory.json"), `${JSON.stringify(inventory, null, 2)}\n`,
    { flag: "wx", mode: 0o600 });
  await verifyStandaloneInstallBundle(destination);
  return { kind: "standalone-install-bundle-verification", sourceRevision, path: destination,
    packageCount: manifest.packages.length, imageCount: images.length + (apiRuntime ? 1 : 0),
    proofParameterCount: proofFiles.length };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2 && (process.argv.length !== 4 || process.argv[2] !== "--api-image-dir")) {
    throw new Error("Usage: node scripts/build-standalone-install.mjs [--api-image-dir <absolute-directory>]");
  }
  console.log(JSON.stringify(await buildStandaloneInstall({ apiImageDirectory: process.argv[3] })));
}
