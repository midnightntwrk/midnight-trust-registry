#!/usr/bin/env node

import { createHash, timingSafeEqual } from "node:crypto";
import { createReadStream } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SHA512_SRI = /^sha512-([A-Za-z0-9+/]+={0,2})$/u;

/**
 * An existing immutable version may be skipped only when its registry bytes match this tarball.
 * @param {string} tarballPath
 * @param {unknown} registryDist
 */
export async function assertPublishedPackageIntegrity(tarballPath, registryDist) {
  if (registryDist === null || typeof registryDist !== "object" || Array.isArray(registryDist)
    || !("integrity" in registryDist) || typeof registryDist.integrity !== "string") {
    throw new Error("Published package has no SHA-512 integrity metadata");
  }
  const match = SHA512_SRI.exec(registryDist.integrity);
  if (!match) throw new Error("Published package requires one SHA-512 integrity value");
  const expected = Buffer.from(match[1], "base64");
  if (expected.length !== 64 || expected.toString("base64") !== match[1]) {
    throw new Error("Published package SHA-512 integrity is malformed");
  }
  const digest = createHash("sha512");
  for await (const chunk of createReadStream(tarballPath)) digest.update(chunk);
  if (!timingSafeEqual(digest.digest(), expected)) {
    throw new Error("Published package integrity differs from the reviewed release tarball");
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4) {
      throw new Error("Usage: check-published-package-integrity.mjs <tarball> <registry-dist-json>");
    }
    await assertPublishedPackageIntegrity(process.argv[2], JSON.parse(process.argv[3]));
  } catch (error) {
    console.error(`Published package check failed: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
