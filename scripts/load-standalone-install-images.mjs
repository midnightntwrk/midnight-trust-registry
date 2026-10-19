#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, readFile, realpath } from "node:fs/promises";
import { join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { installedImageIdFromArchive, verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";

const REVISION = /^[0-9a-f]{40}$/u;

function docker(args) {
  return execFileSync("docker", args, { encoding: "utf8", timeout: 30 * 60_000,
    maxBuffer: 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function inspectOptionalTag(tag, runDocker) {
  try {
    return runDocker(["image", "inspect", tag, "--format", "{{.Id}}"]).trim();
  } catch (error) {
    if (error.status === 1 && /No such image/u.test(String(error.stderr))) return null;
    throw error;
  }
}

async function verifiedArchivePath(root, image) {
  const archive = resolve(root, image.archive);
  if (!archive.startsWith(`${root}${sep}`) || !(await lstat(archive)).isFile()) {
    throw new Error("Install image archive path is not a regular bundle file");
  }
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(archive)) hash.update(chunk);
  if (hash.digest("hex") !== image.archiveSha256) {
    throw new Error("Install image archive changed after bundle verification");
  }
  return archive;
}

/** Loads only previously verified archive bytes; never pulls from a registry. */
export async function loadStandaloneInstallImages(bundlePath, dependencies = {}) {
  const root = await realpath(resolve(bundlePath));
  await (dependencies.verify ?? verifyStandaloneInstallBundle)(root);
  const inventory = JSON.parse(await readFile(join(root, "install-inventory.json"), "utf8"));
  if (!REVISION.test(inventory.sourceRevision)) throw new Error("Install inventory source is invalid");
  const runDocker = dependencies.docker ?? docker;
  const inspectArchive = dependencies.imageId ?? installedImageIdFromArchive;
  const tags = {};
  for (const image of inventory.images) {
    const archive = await (dependencies.archivePath ?? verifiedArchivePath)(root, image);
    const configId = inspectArchive(archive, image.reference);
    const manifestId = `sha256:${image.reference.split("@sha256:")[1]}`;
    const acceptedIds = new Set([configId, manifestId]);
    const tag = `tr-standalone/${image.role}:sha-${inventory.sourceRevision}`;
    const existing = inspectOptionalTag(tag, runDocker);
    if (existing !== null && !acceptedIds.has(existing)) {
      throw new Error(`Offline image tag is already bound to different bytes: ${image.role}`);
    }
    const loaded = runDocker(["load", "--input", archive]);
    const ids = [...loaded.matchAll(/Loaded image ID: (sha256:[0-9a-f]{64})/gu)].map((match) => match[1]);
    if (ids.length !== 1 || !acceptedIds.has(ids[0])) {
      throw new Error(`Loaded image ID disagrees with the bundle: ${image.role}`);
    }
    const loadedId = runDocker(["image", "inspect", ids[0], "--format", "{{.Id}}"]).trim();
    if (loadedId !== ids[0] || (existing !== null && existing !== loadedId)) {
      throw new Error(`Loaded image ID disagrees with the bundle: ${image.role}`);
    }
    if (existing === null) runDocker(["tag", loadedId, tag]);
    tags[image.role] = tag;
  }
  return { kind: "local-image-load-observation", sourceRevision: inventory.sourceRevision,
    tags, freshDaemon: "not-verified", pullDisabledRestart: "not-run" };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    throw new Error("Usage: node scripts/load-standalone-install-images.mjs <verified-bundle-directory>");
  }
  console.log(JSON.stringify(await loadStandaloneInstallImages(process.argv[2])));
}
