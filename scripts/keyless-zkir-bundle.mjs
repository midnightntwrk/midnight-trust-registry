#!/usr/bin/env node

import { execFile } from "node:child_process";
import { Buffer } from "node:buffer";
import console from "node:console";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { copyFile, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { proofCircuitNames } from "./package-contents-policy.mjs";

const runFile = promisify(execFile);
const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const CIRCUIT = /^[A-Za-z][A-Za-z0-9_]*$/u;
const BASE_ASSETS = ["compiler/contract-info.json", "contract/index.d.ts", "contract/index.js",
  "contract/index.js.map"];
const FORMAT = "tr-keyless-zkir-v1";
/** @typedef {{format: string, sourceRevision: string, compilerVersion: string,
 * platform: string, keygenSha256: string, assets: Record<string, string>,
 * keys: Record<string, string>}} KeylessManifest */

/** @param {string} path */
async function hashFile(path) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

/** @param {string} path */
async function regularFile(path) {
  if (!(await lstat(path)).isFile()) throw new Error(`Expected a regular file: ${path}`);
  return path;
}

/** @param {string} path */
async function directory(path) {
  if (!(await lstat(path)).isDirectory()) throw new Error(`Expected a directory: ${path}`);
  return path;
}

/** @param {string} root @param {string} [prefix] @returns {Promise<string[]>} */
async function filesBelow(root, prefix = "") {
  /** @type {string[]} */
  const names = [];
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) names.push(...await filesBelow(root, name));
    else if (entry.isFile()) names.push(name);
    else throw new Error(`Non-regular bundle entry: ${name}`);
  }
  return names.sort();
}

/** @param {readonly string[]} actual @param {readonly string[]} expected @param {string} label */
function exactNames(actual, expected, label) {
  if (JSON.stringify([...actual].sort()) !== JSON.stringify([...expected].sort())) {
    throw new Error(`${label} differs from the proof-circuit catalog`);
  }
}

/** @param {unknown} info */
function circuitNames(info) {
  const names = proofCircuitNames(info).sort();
  if (names.some((name) => !CIRCUIT.test(name))) {
    throw new Error("Proof-circuit name is not a safe file name");
  }
  return names;
}

/** @param {readonly string[]} names */
function assetNames(names) {
  return [...BASE_ASSETS, ...names.flatMap((name) => [`zkir/${name}.zkir`, `zkir/${name}.bzkir`])].sort();
}

/** @param {readonly string[]} names */
function keyNames(names) {
  return names.flatMap((name) => [`${name}.prover`, `${name}.verifier`]).sort();
}

/** @param {string} from @param {string} to @param {readonly string[]} names */
async function copyAssets(from, to, names) {
  for (const name of names) {
    const source = await regularFile(join(from, name));
    const destination = join(to, name);
    await mkdir(dirname(destination), { recursive: true });
    await copyFile(source, destination);
  }
}

/** @template T @param {string} target @param {(stage: string) => Promise<T>} operation */
async function stagedDirectory(target, operation) {
  const absolute = resolve(target);
  try {
    await lstat(absolute);
    throw new Error(`Output already exists: ${absolute}`);
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
  }
  await directory(dirname(absolute));
  const stage = await mkdtemp(`${absolute}.partial-`);
  try {
    const result = await operation(stage);
    await rename(stage, absolute);
    return result;
  } catch (error) {
    await rm(stage, { recursive: true });
    throw error;
  }
}

/** Make a keyless, source-bound managed-contract directory from retained full outputs. */
/** @param {string} fullManaged @param {string} target @param {string} revision @param {string} keygen */
export async function createKeylessZkirBundle(fullManaged, target, revision, keygen) {
  if (!REVISION.test(revision)) throw new Error("Source revision must be a full lowercase commit SHA");
  const source = await directory(resolve(fullManaged));
  const generator = await regularFile(resolve(keygen));
  const info = JSON.parse(await readFile(await regularFile(join(source, BASE_ASSETS[0])), "utf8"));
  const names = circuitNames(info);
  const assets = assetNames(names);
  const keys = keyNames(names);
  exactNames(await filesBelow(join(source, "zkir")), assets.filter((name) => name.startsWith("zkir/"))
    .map((name) => name.slice("zkir/".length)), "ZKIR assets");
  exactNames(await filesBelow(join(source, "keys")), keys, "Key assets");
  exactNames(await filesBelow(join(source, "compiler")), ["contract-info.json"], "Compiler assets");
  exactNames(await filesBelow(join(source, "contract")), BASE_ASSETS.filter((name) =>
    name.startsWith("contract/")).map((name) => name.slice("contract/".length)), "Contract assets");
  const assetHashes = Object.fromEntries(await Promise.all(assets.map(async (name) =>
    [name, await hashFile(await regularFile(join(source, name)))])));
  const keyHashes = Object.fromEntries(await Promise.all(keys.map(async (name) =>
    [name, await hashFile(await regularFile(join(source, "keys", name)))])));
  const manifest = { format: FORMAT, sourceRevision: revision,
    compilerVersion: info["compiler-version"], platform: `${process.platform}/${process.arch}`,
    keygenSha256: await hashFile(generator), assets: assetHashes, keys: keyHashes };
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  await stagedDirectory(target, async (stage) => {
    await copyAssets(source, stage, assets);
    await writeFile(join(stage, "keyless-manifest.json"), manifestBytes, { mode: 0o600 });
  });
  return { manifestSha256: createHash("sha256").update(manifestBytes).digest("hex"),
    circuitCount: names.length, sourceRevision: revision };
}

/** The caller must supply a trusted manifest digest from the release channel. */
/** @param {string} bundle @param {string} expectedManifestSha256 */
export async function verifyKeylessZkirBundle(bundle, expectedManifestSha256) {
  if (!SHA256.test(expectedManifestSha256)) throw new Error("Trusted manifest SHA-256 is required");
  const source = await directory(resolve(bundle));
  const bytes = await readFile(await regularFile(join(source, "keyless-manifest.json")));
  if (createHash("sha256").update(bytes).digest("hex") !== expectedManifestSha256) {
    throw new Error("Keyless manifest differs from the trusted release digest");
  }
  const manifest = /** @type {KeylessManifest} */ (JSON.parse(bytes.toString("utf8")));
  if (manifest?.format !== FORMAT || !REVISION.test(manifest.sourceRevision)
    || typeof manifest.compilerVersion !== "string" || !manifest.compilerVersion
    || typeof manifest.platform !== "string" || !SHA256.test(manifest.keygenSha256)
    || !manifest.assets || !manifest.keys || Array.isArray(manifest.assets)
    || Array.isArray(manifest.keys)) {
    throw new Error("Keyless manifest is malformed");
  }
  const info = JSON.parse(await readFile(join(source, BASE_ASSETS[0]), "utf8"));
  const names = circuitNames(info);
  const assets = assetNames(names);
  const keys = keyNames(names);
  if (info["compiler-version"] !== manifest.compilerVersion) {
    throw new Error("Keyless compiler version differs from circuit metadata");
  }
  exactNames(Object.keys(manifest.assets), assets, "Manifest assets");
  exactNames(Object.keys(manifest.keys), keys, "Manifest keys");
  exactNames(await filesBelow(source), [...assets, "keyless-manifest.json"], "Keyless bundle files");
  for (const name of assets) {
    if (!SHA256.test(manifest.assets[name])
      || await hashFile(await regularFile(join(source, name))) !== manifest.assets[name]) {
      throw new Error(`Keyless asset hash mismatch: ${name}`);
    }
  }
  if (keys.some((name) => !SHA256.test(manifest.keys[name]))) {
    throw new Error("Keyless expected-key hash is malformed");
  }
  return { manifest, names, assets, keys };
}

/** Bind a transported keyless manifest to the full outputs retained by the release builder. */
/** @param {string} bundle @param {string} fullManaged @param {string} expectedManifestSha256
 * @param {string} expectedRevision */
export async function verifyKeylessZkirAgainstFullSource(bundle, fullManaged, expectedManifestSha256,
  expectedRevision) {
  const verified = await verifyKeylessZkirBundle(bundle, expectedManifestSha256);
  if (!REVISION.test(expectedRevision) || verified.manifest.sourceRevision !== expectedRevision) {
    throw new Error("Keyless manifest source revision differs from the signed release source");
  }
  const full = await directory(resolve(fullManaged));
  exactNames(await filesBelow(join(full, "zkir")), verified.assets.filter((name) =>
    name.startsWith("zkir/")).map((name) => name.slice("zkir/".length)), "Full-source ZKIR assets");
  exactNames(await filesBelow(join(full, "keys")), verified.keys, "Full-source key assets");
  for (const name of verified.assets) {
    if (await hashFile(await regularFile(join(full, name))) !== verified.manifest.assets[name]) {
      throw new Error(`Keyless asset differs from full source: ${name}`);
    }
  }
  for (const name of verified.keys) {
    if (await hashFile(await regularFile(join(full, "keys", name))) !== verified.manifest.keys[name]) {
      throw new Error(`Expected key differs from full source: ${name}`);
    }
  }
  return verified;
}

/** Generate keys before use; a failed or interrupted build never becomes the destination. */
/** @param {string} bundle @param {string} destination @param {string} keygen
 * @param {string} expectedManifestSha256 @param {number} [jobs] */
export async function materializeKeylessZkirBundle(bundle, destination, keygen, expectedManifestSha256,
  jobs = 1) {
  if (!Number.isSafeInteger(jobs) || jobs < 1 || jobs > 4) {
    throw new Error("Key generation jobs must be an integer between 1 and 4");
  }
  const source = resolve(bundle);
  const { manifest, names, assets, keys } = await verifyKeylessZkirBundle(source, expectedManifestSha256);
  const generator = await regularFile(resolve(keygen));
  if (`${process.platform}/${process.arch}` !== manifest.platform
    || await hashFile(generator) !== manifest.keygenSha256) {
    throw new Error("Key generator platform or binary digest differs from the release profile");
  }
  await stagedDirectory(destination, async (stage) => {
    await copyAssets(source, stage, assets);
    await mkdir(join(stage, "keys"));
    let cursor = 0;
    /** @type {Error | null} */
    let failure = null;
    const worker = async () => {
      while (cursor < names.length && failure === null) {
        const name = names[cursor++];
        try {
          await runFile(generator, ["compile", join(stage, "zkir", `${name}.zkir`),
            join(stage, "keys", `${name}.prover`), join(stage, "keys", `${name}.verifier`)],
          { timeout: 60 * 60_000, maxBuffer: 1024 * 1024 });
          for (const extension of ["prover", "verifier"]) {
            const file = `${name}.${extension}`;
            if (await hashFile(await regularFile(join(stage, "keys", file))) !== manifest.keys[file]) {
              throw new Error(`Regenerated key hash mismatch: ${file}`);
            }
          }
        } catch (error) {
          failure ??= error instanceof Error && error.message.startsWith("Regenerated key hash mismatch:")
            ? error : new Error(`Key generation failed for circuit ${name}`);
        }
      }
    };
    await Promise.all(Array.from({ length: jobs }, () => worker()));
    if (failure !== null) throw failure;
    exactNames(await filesBelow(join(stage, "keys")), keys, "Regenerated keys");
  });
  return { sourceRevision: manifest.sourceRevision, circuitCount: names.length,
    manifestSha256: expectedManifestSha256 };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, ...args] = process.argv.slice(2);
  const result = command === "create" && args.length === 4
    ? await createKeylessZkirBundle(args[0], args[1], args[2], args[3])
    : command === "verify" && args.length === 2
      ? await verifyKeylessZkirBundle(args[0], args[1]).then(({ manifest, names }) =>
        ({ sourceRevision: manifest.sourceRevision, circuitCount: names.length }))
      : command === "materialize" && (args.length === 4 || args.length === 5)
        ? await materializeKeylessZkirBundle(args[0], args[1], args[2], args[3],
          args[4] === undefined ? 1 : Number(args[4]))
        : null;
  if (result === null) throw new Error("Usage: keyless-zkir-bundle.mjs create <full-managed> <keyless-dir> <source-sha> <zkir-bin> | verify <keyless-dir> <trusted-manifest-sha256> | materialize <keyless-dir> <destination> <zkir-bin> <trusted-manifest-sha256> [jobs: 1-4]");
  console.log(JSON.stringify(result));
}
