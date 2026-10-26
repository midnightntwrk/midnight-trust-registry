#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { constants, copyFileSync, createReadStream, existsSync, lstatSync, mkdirSync, mkdtempSync, opendirSync,
  readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { getuid } from "node:process";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";
import { assertImmutableProviderTree } from "./immutable-provider-tree.mjs";
import { assertCanonicalPackedPaths, packedEntries } from "./release-candidate-manifest.mjs";
import { artifactWorkspaces } from "./trust-registry-workspace-catalog.mjs";

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const SHA = /^[0-9a-f]{40}$/u;
const ARCHIVE_NAME = /^[a-z0-9][a-z0-9.-]*\.tgz$/u;
const REQUIRED_ENTRYPOINTS = ["package.json", "pnpm-lock.yaml", "pnpm-workspace.yaml",
  "scripts/approved-provider-preload.mjs",
  "scripts/immutable-provider-tree.mjs", "scripts/local-ledger-deploy.mjs",
  "scripts/local-ledger-insert-verifier-key.mjs"];
const within = (root, path) => {
  const remainder = relative(root, path);
  return remainder === "" || (remainder !== ".." && !remainder.startsWith(`..${sep}`));
};

function command(file, args, cwd = sourceRoot) {
  return execFileSync(file, args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"],
    maxBuffer: 16 * 1024 * 1024 }).trim();
}

function signedCleanRevision(root, run = command) {
  const revision = run("git", ["rev-parse", "HEAD"], root);
  if (!SHA.test(revision) || run("git", ["status", "--porcelain", "--untracked-files=all"], root) !== "") {
    throw new Error("Provider staging requires a clean signed source commit");
  }
  run("git", ["verify-commit", revision], root);
  return revision;
}

function assertArchiveSourceEntries(root, revision, run, requiredEntrypoints) {
  const entries = run("git", ["ls-tree", "-r", "-z", revision], root).split("\0").filter(Boolean);
  const paths = new Map();
  for (const entry of entries) {
    const match = /^(100644|100755) blob ([0-9a-f]{40})\t(.+)$/su.exec(entry);
    if (match === null) {
      throw new Error("Signed source contains a linked, non-regular, or unsafe archive entry");
    }
    const path = match[3];
    if (path === undefined || path.startsWith("/") || path.includes("\\")
      || path.split("/").some((part) => part === "" || part === "." || part === "..")) {
      throw new Error("Signed source contains a linked, non-regular, or unsafe archive entry");
    }
    paths.set(path, match[2]);
  }
  if (requiredEntrypoints.some((path) => !paths.has(path))) {
    throw new Error("Signed source is missing a provider runtime entry point");
  }
  return paths;
}

async function assertExtractedSource(root, expected) {
  const found = new Set();
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    if (directory === undefined) throw new Error("Provider archive traversal lost a directory");
    const handle = opendirSync(directory);
    try {
      for (let item = handle.readSync(); item !== null; item = handle.readSync()) {
        const path = join(directory, item.name);
        const stat = lstatSync(path);
        if (stat.isDirectory()) {
          pending.push(path);
          continue;
        }
        const name = relative(root, path).split(sep).join("/");
        const oid = expected.get(name);
        if (!stat.isFile() || stat.nlink !== 1 || oid === undefined || found.has(name)) {
          throw new Error(`Provider source archive has an unexpected entry: ${name}`);
        }
        const hash = createHash("sha1").update(`blob ${stat.size}\0`);
        for await (const chunk of createReadStream(path)) hash.update(chunk);
        const after = lstatSync(path);
        if (after.dev !== stat.dev || after.ino !== stat.ino || after.size !== stat.size
          || after.mtimeMs !== stat.mtimeMs || after.ctimeMs !== stat.ctimeMs
          || hash.digest("hex") !== oid) {
          throw new Error(`Provider source archive differs from the signed commit: ${name}`);
        }
        found.add(name);
      }
    } finally {
      handle.closeSync();
    }
  }
  if (found.size !== expected.size) {
    throw new Error("Provider source archive omitted files from the signed commit");
  }
}

function packageEntries(manifest, expectedWorkspaces) {
  const packages = manifest?.packages;
  if (!Array.isArray(packages) || packages.length !== expectedWorkspaces.length
    || new Set(packages.map((item) => item?.workspace)).size !== packages.length
    || new Set(packages.map((item) => item?.filename)).size !== packages.length
    || packages.some((item) => !item || !expectedWorkspaces.includes(item.workspace)
      || typeof item.filename !== "string" || !ARCHIVE_NAME.test(item.filename)
      || !/^[0-9a-f]{64}$/u.test(item.sha256 ?? ""))) {
    throw new Error("Verified bundle has an incomplete or unsafe provider package catalog");
  }
  return packages;
}

async function sha256File(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

/** Stages reviewed source and verified packages; ownership transfer is an operator action. */
export async function stageProviderRuntime(bundleDirectory, destination, dependencies = {}) {
  if (typeof getuid !== "function" || getuid() === 0) {
    throw new Error("Provider staging must run as a non-root user");
  }
  if (!isAbsolute(bundleDirectory) || !isAbsolute(destination)) {
    throw new Error("Provider bundle and staging destination must be absolute paths");
  }
  const bundleInput = resolve(bundleDirectory);
  if (!lstatSync(bundleInput).isDirectory()) {
    throw new Error("Verified install bundle must be a real directory");
  }
  const bundle = realpathSync(bundleInput);
  const parent = resolve(dirname(destination));
  const canonicalParent = realpathSync(parent);
  const target = join(canonicalParent, basename(destination));
  const root = realpathSync(dependencies.sourceRoot ?? sourceRoot);
  if (within(root, target) || within(bundle, target)) {
    throw new Error("Provider stage must be outside the source checkout and install bundle");
  }
  const parentStat = lstatSync(parent);
  if (!parentStat.isDirectory() || parentStat.isSymbolicLink()
    || parentStat.uid !== getuid() || (parentStat.mode & 0o077) !== 0) {
    throw new Error("Provider staging parent must be a private directory owned by the current user");
  }
  const run = dependencies.command ?? command;
  const sourceRevision = signedCleanRevision(root, run);
  const requiredEntrypoints = dependencies.requiredEntrypoints ?? REQUIRED_ENTRYPOINTS;
  const sourceEntries = assertArchiveSourceEntries(root, sourceRevision, run, requiredEntrypoints);
  const verified = await (dependencies.verifyBundle ?? verifyStandaloneInstallBundle)(bundle);
  if (verified.sourceRevision !== sourceRevision || !/^[0-9a-f]{64}$/u.test(verified.inventorySha256 ?? "")) {
    throw new Error("Verified install bundle does not match the signed source commit");
  }
  const manifest = JSON.parse(readFileSync(join(bundle, "release-manifest.json"), "utf8"));
  if (manifest.sourceRevision !== sourceRevision) {
    throw new Error("Release manifest does not match the signed source commit");
  }
  const packages = packageEntries(manifest, dependencies.expectedWorkspaces ?? artifactWorkspaces);
  if (verified.packageCount !== undefined && verified.packageCount !== packages.length) {
    throw new Error("Verified bundle package count differs from the release manifest");
  }
  mkdirSync(target, { mode: 0o700 }); // Never replace an existing stage or its private evidence.
  const temporary = mkdtempSync(join(parent, ".tr-provider-archive-"));
  try {
    const archive = join(temporary, "source.tar");
    run("git", ["archive", `--output=${archive}`, sourceRevision], root);
    run("tar", ["-xf", archive, "-C", target], root);
    await assertExtractedSource(target, sourceEntries);
    for (const path of requiredEntrypoints) {
      if (!existsSync(join(target, path))) {
        throw new Error(`Provider runtime archive omitted a regular entry point: ${path}`);
      }
      const entry = lstatSync(join(target, path));
      if (!entry.isFile() || entry.nlink !== 1) {
        throw new Error(`Provider runtime archive omitted a regular entry point: ${path}`);
      }
    }
    run("pnpm", ["install", "--frozen-lockfile", "--ignore-scripts",
      "--package-import-method=copy"], target);
    for (const item of packages) {
      const source = join(bundle, "packages", item.filename);
      if (!lstatSync(source).isFile()) throw new Error(`Provider package is not a regular file: ${item.filename}`);
      const copy = join(temporary, item.filename);
      copyFileSync(source, copy, constants.COPYFILE_EXCL);
      if (await sha256File(copy) !== item.sha256) {
        throw new Error(`Provider package changed after bundle verification: ${item.filename}`);
      }
      assertCanonicalPackedPaths(packedEntries(copy));
      run("tar", ["-xzf", copy,
        "--strip-components=1", "-C", join(target, item.workspace)], root);
    }
    const evidence = {
      format: "tr-provider-runtime-stage-v1",
      sourceRevision,
      installInventorySha256: verified.inventorySha256,
      packageCount: packages.length,
      sourceSignature: "git-verify-commit-passed-not-independently-approved",
      ownership: "current-user-staging-only",
      releaseQualified: false,
    };
    writeFileSync(join(target, "provider-stage.json"), `${JSON.stringify(evidence, null, 2)}\n`,
      { flag: "wx", mode: 0o600 });
    const tree = assertImmutableProviderTree(target, { boundary: canonicalParent, trustedUid: getuid() });
    return { ...evidence, path: target, tree };
  } finally {
    rmSync(temporary, { recursive: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4) {
      throw new Error("Usage: stage-provider-runtime.mjs <absolute-verified-install-bundle> <absolute-new-private-stage>");
    }
    console.log(JSON.stringify(await stageProviderRuntime(process.argv[2], process.argv[3]), null, 2));
  } catch (error) {
    console.error(`Provider staging failed; inspect any partial stage before cleanup: ${error instanceof Error ? error.message : String(error)}`);
    process.exitCode = 1;
  }
}
