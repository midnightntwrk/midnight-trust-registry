import { lstatSync, readdirSync } from "node:fs";
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";

const MAX_ENTRIES = 500_000;

function within(root, path) {
  const remainder = relative(root, path);
  return remainder === "" || (remainder !== ".." && !remainder.startsWith(`..${sep}`));
}

/**
 * Check the filesystem invariant needed by a root-owned provider installation.
 * Root and administrative updates are trusted; this protects a non-root runner.
 * This does not itself constrain module resolution; the execution boundary must
 * also reject imports outside this tree before it can qualify a deployment.
 */
export function assertImmutableProviderTree(rootPath, options = {}) {
  if (!isAbsolute(rootPath)) throw new Error("Provider code root must be absolute");
  const root = resolve(rootPath);
  const boundary = options.boundary ?? parse(root).root;
  const trustedUid = options.trustedUid ?? 0;
  if (!isAbsolute(boundary) || !within(resolve(boundary), root)
    || !Number.isSafeInteger(trustedUid) || trustedUid < 0) {
    throw new Error("Provider tree trust boundary is invalid");
  }
  const stop = resolve(boundary);
  if (root === stop) throw new Error("Provider code root must be below its trust boundary");

  for (let path = root; ; path = dirname(path)) {
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink()
      || stat.uid !== trustedUid || (stat.mode & 0o022) !== 0) {
      throw new Error(`Provider ancestor is not a trusted directory: ${path}`);
    }
    if (path === stop) break;
  }

  let files = 0;
  let directories = 0;
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== trustedUid
      || (stat.mode & 0o022) !== 0) {
      throw new Error(`Provider tree contains a mutable or linked directory: ${directory}`);
    }
    directories += 1;
    for (const name of readdirSync(directory)) {
      if (files + directories + pending.length >= MAX_ENTRIES) {
        throw new Error("Provider code tree exceeds the bounded entry count");
      }
      const path = join(directory, name);
      const entry = lstatSync(path);
      if (entry.isSymbolicLink() || entry.uid !== trustedUid
        || (entry.mode & 0o022) !== 0) {
        throw new Error(`Provider tree contains a mutable or linked entry: ${path}`);
      }
      if (entry.isDirectory()) {
        pending.push(path);
      } else if (entry.isFile() && entry.nlink === 1) {
        files += 1;
      } else {
        throw new Error(`Provider tree contains a non-regular or hard-linked entry: ${path}`);
      }
    }
  }
  if (files === 0) throw new Error("Provider code tree has no files");
  return { root, files, directories };
}

/** A missing root is a hard stop for the real CLI, not an implicit dev waiver. */
export function assertApprovedProviderTree(providerPath, rootPath, options = {}) {
  if (typeof process.getuid !== "function" || process.getuid() === 0) {
    throw new Error("Real provider loading must run as a non-root user");
  }
  if (typeof rootPath !== "string" || !isAbsolute(rootPath)
    || typeof providerPath !== "string" || !isAbsolute(providerPath)) {
    throw new Error("Real provider loading requires an absolute TR_IMMUTABLE_PROVIDER_ROOT");
  }
  const root = resolve(rootPath);
  const provider = resolve(providerPath);
  if (provider === root || !within(root, provider)) {
    throw new Error("Approved provider module is outside the immutable code root");
  }
  return assertImmutableProviderTree(root, options);
}
