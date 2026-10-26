import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { pathToFileURL } from "node:url";

const MAX_MODULE_BYTES = 16 * 1024 * 1024;
const IDENTITY_FIELDS = ["dev", "ino", "nlink", "size", "mode", "uid", "mtimeNs", "ctimeNs"];

/** Bind an entry module to one regular inode, not just a mutable path. */
export async function readApprovedProviderIdentity(path, expectedSha256) {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.size === 0n || before.size > BigInt(MAX_MODULE_BYTES)
      || before.nlink !== 1n) {
      throw new Error("Approved provider must be a bounded, unlinked regular file");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (IDENTITY_FIELDS.some((field) => before[field] !== after[field])
      || bytes.length !== Number(before.size)) {
      throw new Error("Approved provider changed during identity read");
    }
    const sha256 = createHash("sha256").update(bytes).digest("hex");
    if (sha256 !== expectedSha256) {
      throw new Error("Provider module bytes disagree with the approved SHA-256");
    }
    return Object.fromEntries(IDENTITY_FIELDS.map((field) => [field, before[field]]));
  } finally {
    await handle.close();
  }
}

/** This narrows the hash-to-import window; immutable dependencies remain a separate gate. */
export async function loadRecheckedApprovedProvider(path, expectedSha256, initialIdentity,
  loadProvider = (modulePath) => import(pathToFileURL(modulePath).href)) {
  const current = await readApprovedProviderIdentity(path, expectedSha256);
  if (IDENTITY_FIELDS.some((field) => current[field] !== initialIdentity[field])) {
    throw new Error("Approved provider path or inode changed before import");
  }
  return loadProvider(path);
}
