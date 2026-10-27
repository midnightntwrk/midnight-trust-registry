#!/usr/bin/env node

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SHA256 = /^[0-9a-f]{64}$/u;

/** Recheck the one tarball about to be handed to npm, after the full manifest gate. */
export async function checkPublishTarball(manifestPath, tarballPath, name, version) {
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  const matches = Array.isArray(manifest?.packages)
    ? manifest.packages.filter((entry) => entry?.name === name && entry.version === version) : [];
  if (manifest?.format !== "tr-release-candidate-manifest-v2"
    || !Array.isArray(matches) || matches.length !== 1
    || matches[0].filename !== basename(tarballPath)
    || !SHA256.test(matches[0].sha256)
    || !Number.isSafeInteger(matches[0].sizeBytes) || matches[0].sizeBytes <= 0) {
    throw new Error("Publish tarball is not uniquely pinned by the verified release manifest");
  }
  const file = await open(tarballPath, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size !== BigInt(matches[0].sizeBytes)) {
      throw new Error("Publish tarball is missing, linked, or differs in size from the manifest");
    }
    const hash = createHash("sha256");
    const buffer = Buffer.alloc(1024 * 1024);
    let offset = 0;
    while (offset < matches[0].sizeBytes) {
      const { bytesRead } = await file.read(buffer, 0,
        Math.min(buffer.length, matches[0].sizeBytes - offset), offset);
      if (bytesRead === 0) throw new Error("Publish tarball changed during verification");
      hash.update(buffer.subarray(0, bytesRead));
      offset += bytesRead;
    }
    const after = await file.stat({ bigint: true });
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size
      || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs
      || hash.digest("hex") !== matches[0].sha256) {
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
    await checkPublishTarball(...process.argv.slice(2));
  } catch (error) {
    console.error(`Publish tarball check failed: ${error.message}`);
    process.exitCode = 1;
  }
}
