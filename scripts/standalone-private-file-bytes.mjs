import { constants } from "node:fs";
import { open } from "node:fs/promises";

/**
 * Read a bounded setup input without following its final symlink or accepting
 * a changed inode. Private approvals also require single-link owned files.
 * @param {string} path
 * @param {{privateFile?: boolean}} options
 * @returns {Promise<Buffer>}
 */
export async function regularBytes(path, { privateFile = false } = {}) {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await file.stat({ bigint: true });
    if (!before.isFile() || before.size === 0n || before.size > 16n * 1024n * 1024n
      || (privateFile && (before.nlink !== 1n || (before.mode & 0o077n) !== 0n
        || (typeof process.getuid === "function" && before.uid !== BigInt(process.getuid()))))) {
      throw new Error("Setup input must be a bounded regular file with required ownership");
    }
    const bytes = Buffer.alloc(Number(before.size));
    let count = 0;
    while (count < bytes.length) {
      const result = await file.read(bytes, count, bytes.length - count, count);
      if (result.bytesRead === 0) break;
      count += result.bytesRead;
    }
    const after = await file.stat({ bigint: true });
    if (count !== bytes.length || after.size !== before.size || after.dev !== before.dev
      || after.ino !== before.ino || after.nlink !== before.nlink
      || after.mtimeNs !== before.mtimeNs || after.ctimeNs !== before.ctimeNs) {
      throw new Error("Setup input changed during read");
    }
    return bytes;
  } finally {
    await file.close();
  }
}
