import { createHash, randomUUID } from "node:crypto";
import { lstat, link, open, realpath, unlink } from "node:fs/promises";
import { join, resolve } from "node:path";

import { validateGenesisReviewEvidence } from "./standalone-genesis-review-policy.mjs";
import { renderGenesisReviewPacket } from "./standalone-genesis-review-packet.mjs";
import { regularBytes } from "./standalone-private-file-bytes.mjs";

/** @param {Uint8Array} bytes */
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

/** @param {unknown} value @returns {value is Record<string, unknown>} */
const isRecord = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/**
 * Keep private file and output-byte decisions strict without importing the
 * broader, still non-strict install-bundle verifier into this boundary.
 * @param {string} directory
 * @param {(path: string) => Promise<unknown>} verifyBundle
 */
export async function prepareStandaloneGenesisReviewPacketBytes(directory, verifyBundle) {
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
  /** @type {unknown} */
  const record = JSON.parse(recordBytes.toString("utf8"));
  /** @type {unknown} */
  const candidate = JSON.parse(candidateBytes.toString("utf8"));
  /** @type {unknown} */
  const pin = JSON.parse(pinBytes.toString("utf8"));
  const bundle = isRecord(record) && isRecord(record.install) ? record.install.bundle : null;
  if (typeof bundle !== "string" || bundle.length === 0) {
    throw new Error("Review packet requires a recorded install bundle path");
  }
  const verified = await verifyBundle(bundle);
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
