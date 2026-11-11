#!/usr/bin/env node

import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { copyFile, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rename, rm } from "node:fs/promises";
import { dirname, join, relative, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { KEYLESS_KEYGEN_PARAMETER_PATHS, PROTOCOL_KEY_PATHS } from "./standalone-proof-parameter-catalog.mjs";

const runFile = promisify(execFile);
const SHA256 = /^[0-9a-f]{64}$/u;
const FULL_PATHS = [...KEYLESS_KEYGEN_PARAMETER_PATHS, ...PROTOCOL_KEY_PATHS].sort();

/** @param {string} path */
async function hashFile(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

/** @param {string} path */
async function regularFile(path) {
  const stat = await lstat(path);
  if (!stat.isFile() || stat.nlink !== 1) throw new Error(`Expected a private regular file: ${path}`);
  return path;
}

/** @param {string} root @param {string} [prefix] @returns {Promise<string[]>} */
async function filesBelow(root, prefix = "") {
  /** @type {string[]} */
  const found = [];
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) found.push(...await filesBelow(root, name));
    else if (entry.isFile()) found.push(name);
    else throw new Error(`Non-regular proof parameter entry: ${name}`);
  }
  return found.sort();
}

/** @param {readonly string[]} actual @param {readonly string[]} expected */
function exactPaths(actual, expected) {
  if (JSON.stringify([...actual].sort()) !== JSON.stringify([...expected].sort())) {
    throw new Error("Proof parameter catalog has missing, extra, or renamed files");
  }
}

/** @param {string} bundle @param {string} trustedInventorySha256 */
async function pins(bundle, trustedInventorySha256) {
  if (!SHA256.test(trustedInventorySha256)) throw new Error("Trusted install inventory hash is required");
  const bytes = await readFile(await regularFile(join(bundle, "install-inventory.json")));
  if (createHash("sha256").update(bytes).digest("hex") !== trustedInventorySha256) {
    throw new Error("Install inventory changed before protocol key generation");
  }
  const inventory = /** @type {{format?: string,
   * proofParameters?: {directory?: string, files?: {path: string, sha256: string}[]},
   * keylessRuntime?: {path?: string, platform?: string, sha256?: string,
   * protocolKeys?: Record<string, string>}}} */ (JSON.parse(bytes.toString("utf8")));
  const runtime = inventory?.keylessRuntime;
  if (inventory?.format !== "tr-standalone-install-v7"
    || inventory.proofParameters?.directory !== "proof-params"
    || runtime?.path !== "keygen/zkir" || runtime.platform !== "linux/arm64"
    || typeof runtime.sha256 !== "string" || !SHA256.test(runtime.sha256)
    || !Array.isArray(inventory.proofParameters.files)
    || inventory.proofParameters.files.length !== KEYLESS_KEYGEN_PARAMETER_PATHS.length
    || !runtime.protocolKeys || typeof runtime.protocolKeys !== "object"
    || Array.isArray(runtime.protocolKeys)) {
    throw new Error("Protocol key generation requires a pinned v7 install");
  }
  const base = Object.fromEntries(inventory.proofParameters.files.map((file) => [file?.path, file?.sha256]));
  exactPaths(Object.keys(base), KEYLESS_KEYGEN_PARAMETER_PATHS);
  exactPaths(Object.keys(runtime.protocolKeys), PROTOCOL_KEY_PATHS);
  if ([...Object.values(base), ...Object.values(runtime.protocolKeys)].some((hash) =>
    typeof hash !== "string" || !SHA256.test(hash))) {
    throw new Error("Protocol key or base parameter hash is malformed");
  }
  return { runtime: /** @type {{sha256: string, platform: string,
    protocolKeys: Record<string, string>}} */ (runtime), base };
}

/** @param {string} bundle @param {string} target @param {string} trustedInventorySha256 */
export async function verifyMaterializedProtocolProofParams(bundle, target, trustedInventorySha256) {
  const source = resolve(bundle);
  const cache = resolve(target);
  const { runtime, base } = await pins(source, trustedInventorySha256);
  const cacheStat = await lstat(cache);
  if (!cacheStat.isDirectory() || (cacheStat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && cacheStat.uid !== process.getuid())) {
    throw new Error("Materialized protocol cache must be an owned private directory");
  }
  const inputs = join(source, "proof-params");
  exactPaths(await filesBelow(inputs), KEYLESS_KEYGEN_PARAMETER_PATHS);
  for (const name of KEYLESS_KEYGEN_PARAMETER_PATHS) {
    if (await hashFile(await regularFile(join(inputs, name))) !== base[name]) {
      throw new Error(`Proof parameter input changed: ${name}`);
    }
  }
  if (await hashFile(await regularFile(join(source, "keygen/zkir"))) !== runtime.sha256) {
    throw new Error("Pinned protocol key generator changed");
  }
  exactPaths(await filesBelow(cache), FULL_PATHS);
  for (const name of FULL_PATHS) {
    const expected = base[name] ?? runtime.protocolKeys[name];
    if (await hashFile(await regularFile(join(cache, name))) !== expected) {
      throw new Error(`Materialized proof parameter hash mismatch: ${name}`);
    }
  }
  return { directory: cache, fileCount: FULL_PATHS.length, inventorySha256: trustedInventorySha256 };
}

/** Reuse only a fully verified private cache; interrupted generation never counts as complete.
 * @param {string} bundle @param {string} target @param {string} trustedInventorySha256
 * @param {() => Promise<unknown>} materialize */
export async function ensureMaterializedProtocolProofParams(bundle, target,
  trustedInventorySha256, materialize) {
  try {
    await lstat(target);
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
    await materialize();
  }
  return verifyMaterializedProtocolProofParams(bundle, target, trustedInventorySha256);
}

/** @param {string} bundle @param {string} destination @param {string} keygen
 * @param {string} trustedInventorySha256 */
export async function materializeStandaloneProofParams(bundle, destination, keygen,
  trustedInventorySha256) {
  const source = resolve(bundle);
  const target = resolve(destination);
  const { runtime, base } = await pins(source, trustedInventorySha256);
  if (`${process.platform}/${process.arch}` !== runtime.platform
    || await hashFile(await regularFile(resolve(keygen))) !== runtime.sha256) {
    throw new Error("Protocol key generator platform or bytes differ from the install pin");
  }
  const parent = dirname(target);
  const parentStat = await lstat(parent);
  if (!parentStat.isDirectory() || (parentStat.mode & 0o077) !== 0
    || (typeof process.getuid === "function" && parentStat.uid !== process.getuid())) {
    throw new Error("Protocol proof cache parent must be a private directory owned by the current user");
  }
  const withinBundle = relative(await realpath(source), await realpath(parent));
  if (withinBundle === "" || !withinBundle.startsWith(`..${sep}`)) {
    throw new Error("Generated protocol keys must not modify the install bundle");
  }
  try {
    await lstat(target);
    throw new Error("Protocol proof cache already exists");
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
  }
  const stage = await mkdtemp(join(parent, ".tr-proof-params-"));
  try {
    const inputs = join(source, "proof-params");
    exactPaths(await filesBelow(inputs), KEYLESS_KEYGEN_PARAMETER_PATHS);
    for (const name of KEYLESS_KEYGEN_PARAMETER_PATHS) {
      const file = await regularFile(join(inputs, name));
      if (await hashFile(file) !== base[name]) throw new Error(`Proof parameter input changed: ${name}`);
      await mkdir(dirname(join(stage, name)), { recursive: true });
      await copyFile(file, join(stage, name));
    }
    for (const name of ["dust/9/spend", "zswap/9/spend", "zswap/9/output", "zswap/9/sign"]) {
      await runFile(keygen, ["compile", join(stage, `${name}.bzkir`),
        join(stage, `${name}.prover`), join(stage, `${name}.verifier`)],
      { timeout: 60 * 60_000, maxBuffer: 1024 * 1024 });
      for (const extension of ["prover", "verifier"]) {
        const key = `${name}.${extension}`;
        if (await hashFile(await regularFile(join(stage, key))) !== runtime.protocolKeys[key]) {
          throw new Error(`Regenerated protocol key hash mismatch: ${key}`);
        }
      }
    }
    exactPaths(await filesBelow(stage), FULL_PATHS);
    await rename(stage, target);
  } catch (error) {
    await rm(stage, { recursive: true });
    throw error;
  }
  return verifyMaterializedProtocolProofParams(source, target, trustedInventorySha256);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, ...args] = process.argv.slice(2);
  const result = command === "materialize" && args.length === 4
    ? await materializeStandaloneProofParams(args[0], args[1], args[2], args[3])
    : command === "verify" && args.length === 3
      ? await verifyMaterializedProtocolProofParams(args[0], args[1], args[2]) : null;
  if (result === null) throw new Error("Usage: materialize-standalone-proof-params.mjs materialize <verified-v7-bundle> <new-private-cache> <pinned-zkir-bin> <trusted-inventory-sha256> | verify <bundle> <cache> <trusted-inventory-sha256>");
  console.log(JSON.stringify(result));
}
