#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createReadStream } from "node:fs";
import {
  copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, writeFileSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import yaml from "js-yaml";

import { STANDALONE_PROOF_PARAMETER_PATHS, verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { buildReleaseCandidateManifest } from "./release-candidate-manifest.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const ROLES = ["node", "indexer", "proof-server"];
const IMAGE = /^[a-z0-9][a-z0-9./_:-]*@sha256:[0-9a-f]{64}$/u;

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
  const pinned = pinnedStandaloneImages(readFileSync(join(root, "deploy/standalone/compose.yml"), "utf8"));
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

  const inventory = {
    format: "tr-standalone-install-v2", sourceRevision,
    packageManifest: "release-manifest.json", artifactDirectory: "packages",
    images, proofParameters: { directory: "proof-params", files: proofFiles },
  };
  writeFileSync(join(destination, "install-inventory.json"), `${JSON.stringify(inventory, null, 2)}\n`,
    { flag: "wx", mode: 0o600 });
  await verifyStandaloneInstallBundle(destination);
  return { kind: "standalone-install-bundle-verification", sourceRevision, path: destination,
    packageCount: manifest.packages.length, imageCount: images.length, proofParameterCount: proofFiles.length };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 2) throw new Error("Usage: node scripts/build-standalone-install.mjs");
  console.log(JSON.stringify(await buildStandaloneInstall()));
}
