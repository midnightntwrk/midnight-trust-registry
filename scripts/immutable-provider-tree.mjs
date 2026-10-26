import { lstatSync, opendirSync, readlinkSync, realpathSync } from "node:fs";
import { registerHooks } from "node:module";
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const MAX_ENTRIES = 500_000;
const IMPORT_BOUNDARY = Symbol.for("tr.approved-provider-import-boundary");

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
  const maxEntries = options.maxEntries ?? MAX_ENTRIES;
  if (!isAbsolute(boundary) || !within(resolve(boundary), root)
    || !Number.isSafeInteger(trustedUid) || trustedUid < 0
    || !Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > MAX_ENTRIES) {
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
  let links = 0;
  let entries = 1;
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    const stat = lstatSync(directory);
    if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== trustedUid
      || (stat.mode & 0o022) !== 0) {
      throw new Error(`Provider tree contains a mutable or linked directory: ${directory}`);
    }
    directories += 1;
    const handle = opendirSync(directory);
    try {
      for (let item = handle.readSync(); item !== null; item = handle.readSync()) {
        if (entries >= maxEntries) {
          throw new Error("Provider code tree exceeds the bounded entry count");
        }
        entries += 1;
        const path = join(directory, item.name);
        const entry = lstatSync(path);
        if (entry.uid !== trustedUid) {
          throw new Error(`Provider tree contains a mutable or linked entry: ${path}`);
        }
        if (entry.isSymbolicLink()) {
          // A link's mode is not its replacement authority; the scanned parent
          // controls replacement, and the resolved in-tree target is scanned too.
          const target = readlinkSync(path);
          const lexical = resolve(directory, target);
          if (isAbsolute(target) || !within(root, lexical)
            || !within(root, realpathSync(path))) {
            throw new Error(`Provider link escapes the approved code tree: ${path}`);
          }
          links += 1;
        } else if ((entry.mode & 0o022) !== 0) {
          throw new Error(`Provider tree contains a mutable or linked entry: ${path}`);
        } else if (entry.isDirectory()) {
          pending.push(path);
        } else if (entry.isFile() && entry.nlink === 1) {
          files += 1;
        } else {
          throw new Error(`Provider tree contains a non-regular or hard-linked entry: ${path}`);
        }
      }
    } finally {
      handle.closeSync();
    }
  }
  if (files === 0) throw new Error("Provider code tree has no files");
  return { root, files, directories, links };
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

/** Register before loading the CLI entry point so ESM and CJS dependencies are covered. */
export function registerApprovedProviderImportBoundary(rootPath) {
  if (!isAbsolute(rootPath)) throw new Error("Approved import root must be absolute");
  const root = resolve(rootPath);
  const checkUrl = (url) => {
    if (url.startsWith("node:")) return;
    if (!url.startsWith("file:")) {
      throw new Error(`Module import is outside the approved code tree: ${url}`);
    }
    if (!within(root, fileURLToPath(url))) {
      throw new Error(`Module import is outside the approved code tree: ${url}`);
    }
  };
  const hooks = registerHooks({
    resolve(specifier, context, nextResolve) {
      const result = nextResolve(specifier, context);
      checkUrl(result.url);
      return result;
    },
    load(url, context, nextLoad) {
      checkUrl(url);
      return nextLoad(url, context);
    },
  });
  globalThis[IMPORT_BOUNDARY] = root;
  return hooks;
}

export function assertApprovedProviderImportBoundary(rootPath) {
  if (!isAbsolute(rootPath) || globalThis[IMPORT_BOUNDARY] !== resolve(rootPath)) {
    throw new Error("Real provider loading requires the approved import preloader");
  }
}
