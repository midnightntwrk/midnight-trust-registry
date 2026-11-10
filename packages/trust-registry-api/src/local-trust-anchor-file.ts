import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { dirname, isAbsolute, relative, resolve, sep } from "node:path";

const MAX_ANCHOR_BYTES = 64 * 1024;

type ReaderOptions = { trustedUid?: number; boundary?: string };

/** Read an operator-installed anchor from a root-owned, non-replaceable tree. */
export async function readProtectedLocalTrustAnchor(
  filePath: string,
  options: ReaderOptions = {},
): Promise<Buffer> {
  const trustedUid = options.trustedUid ?? 0;
  const boundary = resolve(options.boundary ?? "/");
  if (!isAbsolute(filePath) || !isAbsolute(options.boundary ?? "/")
    || !Number.isSafeInteger(trustedUid) || trustedUid < 0) {
    throw new Error("Local API trust anchor requires an absolute protected path");
  }
  const path = resolve(filePath);
  const remainder = relative(boundary, path);
  if (path === boundary || remainder === ".." || remainder.startsWith(`..${sep}`)) {
    throw new Error("Local API trust anchor is outside its protected boundary");
  }
  for (let directory = dirname(path); ; directory = dirname(directory)) {
    const stat = await lstat(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== trustedUid
      || (stat.mode & 0o022) !== 0) {
      throw new Error(`Local API trust anchor has an unsafe ancestor: ${directory}`);
    }
    if (directory === boundary) break;
  }
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat({ bigint: true });
    if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(trustedUid)
      || (before.mode & 0o022n) !== 0n
      || before.size === 0n || before.size > BigInt(MAX_ANCHOR_BYTES)) {
      throw new Error("Local API trust anchor is not a bounded protected regular file");
    }
    const bytes = await handle.readFile();
    const after = await handle.stat({ bigint: true });
    if (bytes.length !== Number(before.size)
      || ["dev", "ino", "nlink", "size", "mode", "uid", "mtimeNs", "ctimeNs"]
        .some((field) => before[field as keyof typeof before] !== after[field as keyof typeof after])) {
      throw new Error("Local API trust anchor changed while being read");
    }
    return bytes;
  } finally {
    await handle.close();
  }
}
