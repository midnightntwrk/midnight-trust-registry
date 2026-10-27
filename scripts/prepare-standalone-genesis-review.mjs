#!/usr/bin/env node

import { createHash, randomUUID } from "node:crypto";
import { lstat, link, open, realpath, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { validateGenesisReviewEvidence } from "./standalone-genesis-review-policy.mjs";
export { validateGenesisReviewEvidence } from "./standalone-genesis-review-policy.mjs";
import { renderGenesisReviewPacket } from "./standalone-genesis-review-packet.mjs";
export { renderGenesisReviewPacket } from "./standalone-genesis-review-packet.mjs";
import { regularBytes } from "./standalone-setup-wizard.mjs";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

export async function prepareStandaloneGenesisReviewPacket(directory,
  dependencies = {}) {
  const requested = resolve(directory);
  const stat = await lstat(requested);
  if (!stat.isDirectory() || (stat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && stat.uid !== process.getuid())) {
    throw new Error("Review packet requires an owned mode-0700 setup directory");
  }
  const root = await realpath(requested);
  const [recordBytes, candidateBytes, pinBytes] = await Promise.all([
    regularBytes(join(root, "setup-record.json"), { privateFile: true }),
    regularBytes(join(root, "genesis-candidate.untrusted.json"), { privateFile: true }),
    regularBytes(join(root, "genesis-pin.proposed.json"), { privateFile: true }),
  ]);
  const record = JSON.parse(recordBytes.toString("utf8"));
  const candidate = JSON.parse(candidateBytes.toString("utf8"));
  const pin = JSON.parse(pinBytes.toString("utf8"));
  const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(record.install.bundle);
  const evidence = validateGenesisReviewEvidence(record, candidate, pin, verified);
  const output = join(root, "genesis-review-packet.md");
  const temporary = `${output}.${process.pid}.${randomUUID()}.tmp`;
  const file = await open(temporary, "wx", 0o600);
  try {
    try {
      await file.writeFile(renderGenesisReviewPacket(evidence,
        digest(candidateBytes), digest(pinBytes)));
      await file.sync();
    } finally {
      await file.close();
    }
    await link(temporary, output);
  } finally {
    await unlink(temporary).catch(() => {});
  }
  return { path: output, sourceRevision: evidence.sourceRevision,
    candidateSha256: digest(candidateBytes), pinSha256: digest(pinBytes),
    status: "untrusted-human-review-required", releaseQualified: false };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3) {
    throw new Error("Usage: node scripts/prepare-standalone-genesis-review.mjs <private-setup-dir>");
  }
  console.log(JSON.stringify(await prepareStandaloneGenesisReviewPacket(process.argv[2])));
}
