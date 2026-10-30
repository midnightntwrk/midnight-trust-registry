#!/usr/bin/env node

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SHA256 = /^[0-9a-f]{64}$/u;

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/** Recheck the one tarball about to be handed to npm, after the full manifest gate. */
/** @param {string} manifestPath @param {string} tarballPath @param {string} name @param {string} version */
export async function checkPublishTarball(manifestPath, tarballPath, name, version) {
  /** @type {unknown} */
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const packages = isRecord(manifest) && Array.isArray(manifest.packages)
    ? /** @type {unknown[]} */ (manifest.packages) : [];
  const matches = packages.filter((entry) => isRecord(entry)
    && entry.name === name && entry.version === version);
  const match = matches.length === 1 && isRecord(matches[0]) ? matches[0] : null;
  if (!isRecord(manifest) || manifest.format !== "tr-release-candidate-manifest-v2"
    || match === null || match.filename !== basename(tarballPath)
    || typeof match.sha256 !== "string" || !SHA256.test(match.sha256)
    || typeof match.sizeBytes !== "number"
    || !Number.isSafeInteger(match.sizeBytes) || match.sizeBytes <= 0) {
    throw new Error("Publish tarball is not uniquely pinned by the verified release manifest");
  }
  const file = await open(tarballPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size !== BigInt(match.sizeBytes)) {
      throw new Error("Publish tarball is missing, linked, or differs in size from the manifest");
    }
    const hash = createHash("sha256");
    const buffer = Buffer.alloc(1024 * 1024);
    let offset = 0;
    while (offset < match.sizeBytes) {
      const { bytesRead } = await file.read(buffer, 0,
        Math.min(buffer.length, match.sizeBytes - offset), offset);
      if (bytesRead === 0) throw new Error("Publish tarball changed during verification");
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const after = await file.stat({ bigint: true });
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size
      || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs
      || hash.digest("hex") !== match.sha256) {
      throw new Error("Publish tarball bytes differ from the verified release manifest");
    }
  } finally {
    await file.close();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 6) {
      throw new Error("Usage: check-publish-tarball.mjs <manifest> <tarball> <package-name> <version>");
    }
    await checkPublishTarball(process.argv[2], process.argv[3], process.argv[4], process.argv[5]);
  } catch (error) {
    console.error(`Publish tarball check failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
