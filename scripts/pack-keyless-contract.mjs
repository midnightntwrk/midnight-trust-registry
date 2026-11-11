#!/usr/bin/env node

import { execFile } from "node:child_process";
import console from "node:console";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { copyFile, link, lstat, mkdir, mkdtemp, readFile, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { assertCanonicalPackedPaths, packedEntries } from "./release-candidate-manifest.mjs";
import { materializeKeylessZkirBundle, verifyKeylessZkirBundle } from "./keyless-zkir-bundle.mjs";

const runFile = promisify(execFile);
const KEY_PREFIX = "dist/managed/trust-registry/keys/";
const MANAGED_PREFIX = "dist/managed/trust-registry/";
const CONTRACT_NAME = "@midnight-ntwrk/trust-registry-contract";
const SHA256 = /^[0-9a-f]{64}$/u;
const repoLicense = resolve(dirname(fileURLToPath(import.meta.url)), "../LICENSE");

/** @param {string} path */
async function hashFile(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

/** @param {string} path */
async function regularFile(path) {
  if (!(await lstat(path)).isFile()) throw new Error(`Expected a regular package file: ${path}`);
  return path;
}

/** @param {string} path */
function safeRelative(path) {
  return typeof path === "string" && path.length > 0 && !isAbsolute(path)
    && !path.includes("\\") && !path.includes("\n")
    && path.split("/").every((part) => part !== "" && part !== "." && part !== "..");
}

/** Pack a contract package without keys, retaining a separately trusted regeneration manifest. */
/** @param {string} packageDirectory @param {string} keylessDirectory
 * @param {string} trustedManifestSha256 @param {string} target */
export async function packKeylessContract(packageDirectory, keylessDirectory,
  trustedManifestSha256, target) {
  const source = resolve(packageDirectory);
  const keyless = resolve(keylessDirectory);
  const destination = resolve(target);
  const { manifest, assets, keys } = await verifyKeylessZkirBundle(keyless,
    trustedManifestSha256);
  const packageJson = JSON.parse(await readFile(await regularFile(join(source, "package.json")), "utf8"));
  if (packageJson.name !== CONTRACT_NAME || typeof packageJson.version !== "string") {
    throw new Error("Contract package name or version is invalid");
  }
  for (const asset of assets) {
    if (await hashFile(await regularFile(join(source, MANAGED_PREFIX, asset))) !== manifest.assets[asset]) {
      throw new Error(`Contract source and trusted ZKIR asset differ: ${asset}`);
    }
  }
  const { stdout } = await runFile("pnpm", ["--config.ignore-scripts=true", "pack", "--dry-run", "--json"],
    { cwd: source, timeout: 60_000, maxBuffer: 4 * 1024 * 1024 });
  const packument = /** @type {{name?: string, version?: string, files?: {path: string}[]}} */ (JSON.parse(stdout));
  if (packument.name !== CONTRACT_NAME || packument.version !== packageJson.version
    || !Array.isArray(packument.files)) {
    throw new Error("Contract package dry-run disagrees with the source package identity");
  }
  const files = packument.files.map((entry) => entry?.path);
  if (files.some((file) => !safeRelative(file)) || new Set(files).size !== files.length) {
    throw new Error("Contract package dry-run contains unsafe or duplicate paths");
  }
  assertCanonicalPackedPaths(files.map((file) => `package/${file}`));
  const packedKeys = files.filter((file) => file.startsWith(KEY_PREFIX));
  const expectedKeys = keys.map((name) => `${KEY_PREFIX}${name}`);
  if (JSON.stringify(packedKeys.sort()) !== JSON.stringify(expectedKeys.sort())
    || files.some((file) => /\.(?:prover|verifier)$/u.test(file) && !file.startsWith(KEY_PREFIX))) {
    throw new Error("Contract package key list differs from the trusted circuit catalog");
  }
  if (files.includes(`${MANAGED_PREFIX}keyless-manifest.json`)) {
    throw new Error("Contract source already contains a keyless release manifest");
  }
  try {
    await lstat(destination);
    throw new Error(`Output already exists: ${destination}`);
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
  }
  await mkdir(dirname(destination), { recursive: true });
  const stage = await mkdtemp(join(dirname(destination), ".tr-keyless-contract-"));
  const partial = join(stage, "keyless.tgz");
  try {
    for (const file of files.filter((name) => !name.startsWith(KEY_PREFIX))) {
      const output = join(stage, "package", file);
      await mkdir(dirname(output), { recursive: true });
      await copyFile(await regularFile(join(source, file)), output);
    }
    if (!files.includes("LICENSE")) {
      await copyFile(await regularFile(repoLicense), join(stage, "package", "LICENSE"));
    }
    const embedded = join(stage, "package", MANAGED_PREFIX, "keyless-manifest.json");
    await copyFile(await regularFile(join(keyless, "keyless-manifest.json")), embedded);
    await runFile("tar", ["--no-xattrs", "-czf", partial, "-C", stage, "package"],
      { timeout: 120_000, maxBuffer: 1024 * 1024,
        env: { ...process.env, COPYFILE_DISABLE: "1" } });
    await link(partial, destination);
  } finally {
    await rm(stage, { recursive: true });
  }
  return { name: CONTRACT_NAME, version: packageJson.version,
    sourceRevision: manifest.sourceRevision, manifestSha256: trustedManifestSha256,
    tarballSha256: await hashFile(destination), tarballBytes: (await lstat(destination)).size };
}

/** @param {string} tarball @param {string} stage @param {string} trustedTarballSha256
 * @param {string} trustedManifestSha256 */
async function inspectPackageArchive(tarball, stage, trustedTarballSha256,
  trustedManifestSha256) {
  if (!SHA256.test(trustedTarballSha256) || !SHA256.test(trustedManifestSha256)) {
    throw new Error("Trusted package and manifest hashes are required");
  }
  const archive = join(stage, "archive.tgz");
  await copyFile(await regularFile(resolve(tarball)), archive);
  if (await hashFile(archive) !== trustedTarballSha256) {
    throw new Error("Keyless contract tarball differs from the trusted release digest");
  }
  const entries = packedEntries(archive);
  assertCanonicalPackedPaths(entries);
  if (entries.some((entry) => entry.startsWith(`package/${KEY_PREFIX}`)
    || /\.(?:prover|verifier)$/u.test(entry))) {
    throw new Error("Keyless contract tarball contains key material");
  }
  const contents = join(stage, "contents");
  await mkdir(contents);
  await runFile("tar", ["-xzf", archive, "-C", contents],
    { timeout: 120_000, maxBuffer: 1024 * 1024 });
  const packageRoot = join(contents, "package");
  const packageJson = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
  if (packageJson.name !== CONTRACT_NAME || typeof packageJson.version !== "string") {
    throw new Error("Keyless package identity is invalid");
  }
  const managed = join(packageRoot, MANAGED_PREFIX);
  const { manifest, names } = await verifyKeylessZkirBundle(managed, trustedManifestSha256);
  return { packageRoot, result: { name: CONTRACT_NAME, version: packageJson.version,
    sourceRevision: manifest.sourceRevision, circuitCount: names.length,
    tarballSha256: trustedTarballSha256, manifestSha256: trustedManifestSha256 } };
}

/** Verify a transported keyless contract package before extracting its contents for use. */
/** @param {string} tarball @param {string} trustedTarballSha256
 * @param {string} trustedManifestSha256 */
export async function verifyKeylessContractPackage(tarball, trustedTarballSha256,
  trustedManifestSha256) {
  const stage = await mkdtemp(join(tmpdir(), "tr-keyless-contract-check-"));
  try {
    return (await inspectPackageArchive(tarball, stage, trustedTarballSha256,
      trustedManifestSha256)).result;
  } finally {
    await rm(stage, { recursive: true });
  }
}

/** Reconstitute a complete local contract package only after all release hashes pass. */
/** @param {string} tarball @param {string} destination @param {string} keygen
 * @param {string} trustedTarballSha256 @param {string} trustedManifestSha256
 * @param {number} [jobs] */
export async function materializeKeylessContractPackage(tarball, destination, keygen,
  trustedTarballSha256, trustedManifestSha256, jobs = 1) {
  const target = resolve(destination);
  try {
    await lstat(target);
    throw new Error(`Output already exists: ${target}`);
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
  }
  await mkdir(dirname(target), { recursive: true });
  const stage = await mkdtemp(join(dirname(target), ".tr-keyless-materialize-"));
  try {
    const { packageRoot } = await inspectPackageArchive(tarball, stage,
      trustedTarballSha256, trustedManifestSha256);
    const managed = join(packageRoot, MANAGED_PREFIX);
    const fullManaged = join(stage, "full-managed");
    const result = await materializeKeylessZkirBundle(managed, fullManaged, keygen,
      trustedManifestSha256, jobs);
    await rm(managed, { recursive: true });
    await rename(fullManaged, managed);
    await rename(packageRoot, target);
    return { ...result, tarballSha256: trustedTarballSha256, packageDirectory: target };
  } finally {
    await rm(stage, { recursive: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, ...args] = process.argv.slice(2);
  const result = command === "pack" && args.length === 4
    ? await packKeylessContract(args[0], args[1], args[2], args[3])
    : command === "verify" && args.length === 3
      ? await verifyKeylessContractPackage(args[0], args[1], args[2])
      : command === "materialize" && (args.length === 5 || args.length === 6)
        ? await materializeKeylessContractPackage(args[0], args[1], args[2], args[3], args[4],
          args[5] === undefined ? 1 : Number(args[5])) : null;
  if (result === null) throw new Error("Usage: pack-keyless-contract.mjs pack <full-contract-package-dir> <keyless-managed-dir> <trusted-manifest-sha256> <new-tarball> | verify <tarball> <trusted-tarball-sha256> <trusted-manifest-sha256> | materialize <tarball> <new-package-dir> <zkir-bin> <trusted-tarball-sha256> <trusted-manifest-sha256> [jobs]");
  console.log(JSON.stringify(result));
}
