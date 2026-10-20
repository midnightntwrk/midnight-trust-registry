#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { constants as fsConstants, createReadStream } from "node:fs";
import { copyFile, lstat, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
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

async function stagedArchivePath(root, image, staging) {
  const archive = resolve(root, image.archive);
  if (!archive.startsWith(`${root}${sep}`) || !(await lstat(archive)).isFile()) {
    throw new Error("Install image archive path is not a regular bundle file");
  }
  const actual = await realpath(archive);
  if (!actual.startsWith(`${root}${sep}`)) {
    throw new Error("Install image archive escapes the bundle");
  }
  const staged = join(staging, `${image.role}.tar`);
  await copyFile(archive, staged, fsConstants.COPYFILE_EXCL);
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(staged)) hash.update(chunk);
  if (hash.digest("hex") !== image.archiveSha256) {
    throw new Error("Install image archive changed after bundle verification");
  }
  return staged;
}

/** Loads only previously verified archive bytes; never pulls from a registry. */
export async function loadStandaloneInstallImages(bundlePath, dependencies = {}) {
  const root = await realpath(resolve(bundlePath));
  const verified = await (dependencies.verify ?? verifyStandaloneInstallBundle)(root);
  const inventoryBytes = await readFile(join(root, "install-inventory.json"));
  if (createHash("sha256").update(inventoryBytes).digest("hex") !== verified?.inventorySha256) {
    throw new Error("Install inventory changed after bundle verification");
  }
  const inventory = JSON.parse(inventoryBytes.toString("utf8"));
  if (!REVISION.test(inventory.sourceRevision)) throw new Error("Install inventory source is invalid");
  const apiImageId = inventory.format === "tr-standalone-install-v4" ? verified?.apiRuntime?.imageId : null;
  const apiConfigId = inventory.format === "tr-standalone-install-v4" ? verified?.apiRuntime?.configId : null;
  if (inventory.format === "tr-standalone-install-v4"
    && (!/^sha256:[0-9a-f]{64}$/u.test(apiImageId ?? "")
      || !/^sha256:[0-9a-f]{64}$/u.test(apiConfigId ?? ""))) {
    throw new Error("Verified API image IDs are missing");
  }
  const runDocker = dependencies.docker ?? docker;
  const inspectArchive = dependencies.imageId ?? installedImageIdFromArchive;
  const tags = {};
  const staging = await mkdtemp(join(tmpdir(), "tr-install-image-load-"));
  async function load(image, acceptedIds, archive) {
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
  try {
    for (const image of inventory.images) {
      const archive = await (dependencies.archivePath ?? stagedArchivePath)(root, image, staging);
      const configId = inspectArchive(archive, image.reference);
      const manifestId = `sha256:${image.reference.split("@sha256:")[1]}`;
      await load(image, new Set([configId, manifestId]), archive);
    }
    if (inventory.format === "tr-standalone-install-v4") {
      const image = { role: "api", archive: inventory.apiRuntime.archive,
        archiveSha256: inventory.apiRuntime.archiveSha256 };
      const archive = await (dependencies.archivePath ?? stagedArchivePath)(root, image, staging);
      await load(image, new Set([apiImageId, apiConfigId]), archive);
    }
    return { kind: "local-image-load-observation", sourceRevision: inventory.sourceRevision,
      tags, freshDaemon: "not-verified", pullDisabledRestart: "not-run" };
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    throw new Error("Usage: node scripts/load-standalone-install-images.mjs <verified-bundle-directory>");
  }
  console.log(JSON.stringify(await loadStandaloneInstallImages(process.argv[2])));
}
