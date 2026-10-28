#!/usr/bin/env node

import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const SHA256 = /^[0-9a-f]{64}$/u;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const IDENTITY_FIELDS = ["dev", "ino", "nlink", "size", "mode", "uid", "mtimeNs", "ctimeNs"];

export async function checkReviewedManifestDigest(path, expectedSha256) {
  if (typeof path !== "string" || path.length === 0 || !SHA256.test(expectedSha256)) {
    throw new Error("Reviewed manifest path or SHA-256 is invalid");
  }
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.size === 0n
      || before.size > BigInt(MAX_MANIFEST_BYTES)) {
      throw new Error("Reviewed manifest must be a bounded single-link regular file");
    }
    const bytes = await file.readFile();
    const after = await file.stat({ bigint: true });
    if (bytes.length !== Number(before.size)
      || IDENTITY_FIELDS.some((field) => before[field] !== after[field])) {
      throw new Error("Reviewed manifest changed during digest verification");
    }
    if (createHash("sha256").update(bytes).digest("hex") !== expectedSha256) {
      throw new Error("Reviewed manifest bytes differ from the prepared SHA-256");
    }
  } finally {
    await file.close();
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4) throw new Error("Usage: check-reviewed-manifest-digest.mjs path sha256");
    await checkReviewedManifestDigest(process.argv[2], process.argv[3]);
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
