#!/usr/bin/env node

import { execFile } from "node:child_process";
import { Buffer } from "node:buffer";
import console from "node:console";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { copyFile, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import process from "node:process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { proofCircuitNames } from "./package-contents-policy.mjs";

const runFile = promisify(execFile);
const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;
const CIRCUIT = /^[A-Za-z][A-Za-z0-9_]*$/u;
const BASE_ASSETS = ["compiler/contract-info.json", "compiler/contract-manifest.json",
  "contract/index.d.ts", "contract/index.js",
  "contract/index.js.map"];
const FORMAT = "tr-keyless-zkir-v1";
/** @typedef {{type: "file", size: number, hash: string}} CompilerFile */
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
  await directory(join(root, prefix));
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

/** Recreate the metadata that Compact omits under --skip-zk from streamed key outputs.
 * @param {string} stage @param {readonly string[]} names
 * @param {Record<string, CompilerFile>} keyFiles */
export async function completeLightCompile(stage, names, keyFiles) {
  const jsPath = join(stage, "contract/index.js");
  const lightJs = await readFile(jsPath, "utf8");
  const marker = "export const expectedVk = {};";
  if (lightJs.split(marker).length !== 2) throw new Error("Unexpected light Compact verifier table");
  const entries = names.map((name) => `  '${name}': '${keyFiles[`${name}.verifier`].hash}',`);
  const fullJs = lightJs.replace(marker, `export const expectedVk = {\n${entries.join("\n")}\n};`);
  await writeFile(jsPath, fullJs);

  const mapPath = join(stage, "contract/index.js.map");
  const map = await readFile(mapPath, "utf8");
  const mapping = /^  "mappings": "([A-Za-z0-9+/;,]*)"$/mu;
  if (!mapping.test(map) || typeof JSON.parse(map).mappings !== "string") {
    throw new Error("Unexpected Compact source map");
  }
  await writeFile(mapPath, map.replace(mapping, (_, value) =>
    `  "mappings": "${value}${";".repeat(names.length + 1)}"`));

  const manifestPath = join(stage, "compiler/contract-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  if (manifest["manifest-version"] !== "1" || manifest.keys !== undefined
    || manifest.zkir?.type !== "directory" || manifest.contract?.type !== "directory") {
    throw new Error("Unexpected light Compact contract manifest");
  }
  // The repo strips this comment after Compact has recorded the original JS hash.
  const sourceMapComment = "//# sourceMappingURL=index.js.map\n";
  const recordedJs = manifest.contract["index.js"];
  const sourceSuffix = ["", sourceMapComment].find((suffix) => {
    const bytes = Buffer.from(lightJs + suffix);
    return recordedJs?.type === "file" && recordedJs.size === bytes.length
      && recordedJs.hash === createHash("sha256").update(bytes).digest("hex");
  });
  if (sourceSuffix === undefined) throw new Error("Light Compact JavaScript does not match its manifest");
  /** @type {Record<string, CompilerFile | "directory">} */
  const zkir = { type: "directory" };
  /** @type {Record<string, CompilerFile | "directory">} */
  const keys = { type: "directory" };
  for (const name of names) {
    const source = manifest.zkir[`${name}.zkir`];
    if (source?.type !== "file") throw new Error(`Missing light ZKIR manifest entry: ${name}`);
    const binary = join(stage, "zkir", `${name}.bzkir`);
    zkir[`${name}.bzkir`] = { type: "file", size: (await lstat(binary)).size,
      hash: await hashFile(binary) };
    zkir[`${name}.zkir`] = source;
    for (const extension of ["prover", "verifier"]) {
      keys[`${name}.${extension}`] = keyFiles[`${name}.${extension}`];
    }
  }
  exactNames(Object.keys(manifest.zkir), ["type", ...names.map((name) => `${name}.zkir`)],
    "Light Compact ZKIR manifest");
  manifest.zkir = zkir;
  const compilerJs = Buffer.from(fullJs + sourceSuffix);
  manifest.contract["index.js"] = { type: "file", size: compilerJs.length,
    hash: createHash("sha256").update(compilerJs).digest("hex") };
  manifest.contract["index.js.map"] = { type: "file", size: (await lstat(mapPath)).size,
    hash: await hashFile(mapPath) };
  manifest.keys = keys;
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
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
  exactNames(await filesBelow(join(source, "compiler")), ["contract-info.json", "contract-manifest.json"],
    "Compiler assets");
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

/** Build a keyless bundle from a clean --skip-zk compile without retaining proof keys.
 * @param {string} lightManaged @param {string} target @param {string} revision
 * @param {string} keygen @param {string} expectedKeygenSha256 */
export async function createKeylessZkirBundleStreaming(lightManaged, target, revision, keygen,
  expectedKeygenSha256) {
  if (!REVISION.test(revision)) throw new Error("Source revision must be a full lowercase commit SHA");
  if (!SHA256.test(expectedKeygenSha256)) throw new Error("Trusted key generator SHA-256 is required");
  const source = await directory(resolve(lightManaged));
  const info = JSON.parse(await readFile(await regularFile(join(source, BASE_ASSETS[0])), "utf8"));
  const names = circuitNames(info);
  if (names.length === 0) throw new Error("No proof circuits in Compact metadata");
  const zkirNames = names.map((name) => `${name}.zkir`);
  await directory(join(source, "zkir"));
  const presentZkir = await filesBelow(join(source, "zkir"));
  const hasBinaryZkir = presentZkir.includes(`${names[0]}.bzkir`);
  exactNames(presentZkir, hasBinaryZkir
    ? names.flatMap((name) => [`${name}.zkir`, `${name}.bzkir`]) : zkirNames, "ZKIR assets");
  exactNames(await filesBelow(join(source, "compiler")), ["contract-info.json", "contract-manifest.json"],
    "Compiler assets");
  exactNames(await filesBelow(join(source, "contract")), BASE_ASSETS.filter((name) =>
    name.startsWith("contract/")).map((name) => name.slice("contract/".length)), "Contract assets");
  try {
    await directory(join(source, "keys"));
    if ((await filesBelow(join(source, "keys"))).length !== 0) {
      throw new Error("Streaming source must not contain retained proving keys");
    }
  } catch (error) {
    if (!(error instanceof Error) || !("code" in error) || error.code !== "ENOENT") throw error;
  }
  const generatorRoot = await mkdtemp(join(tmpdir(), "tr-zkir-create-"));
  try {
    const generator = join(generatorRoot, "zkir-v3");
    await copyFile(await regularFile(resolve(keygen)), generator);
    if (await hashFile(generator) !== expectedKeygenSha256) {
      throw new Error("Key generator differs from the trusted binary digest");
    }
    return await stagedDirectory(target, async (stage) => {
      await copyAssets(source, stage, [...BASE_ASSETS, ...zkirNames.map((name) => `zkir/${name}`)]);
      /** @type {Record<string, string>} */
      const keyHashes = {};
      /** @type {Record<string, CompilerFile>} */
      const keyFiles = {};
      for (const name of names) {
        const circuit = join(generatorRoot, name);
        await mkdir(circuit);
        try {
          const input = join(circuit, `${name}.zkir`);
          await copyFile(join(stage, "zkir", `${name}.zkir`), input);
          await runFile(generator, ["compile", input, join(circuit, `${name}.prover`),
            join(circuit, `${name}.verifier`)], { timeout: 60 * 60_000, maxBuffer: 1024 * 1024 });
          exactNames(await filesBelow(circuit), [`${name}.zkir`, `${name}.bzkir`,
            `${name}.prover`, `${name}.verifier`], `Generated files for ${name}`);
          for (const extension of ["bzkir", "prover", "verifier"]) {
            if ((await lstat(join(circuit, `${name}.${extension}`))).size === 0) {
              throw new Error(`Generated output is empty: ${name}.${extension}`);
            }
          }
          const binary = join(circuit, `${name}.bzkir`);
          if (hasBinaryZkir && await hashFile(binary) !== await hashFile(join(source, "zkir", `${name}.bzkir`))) {
            throw new Error(`Generated binary ZKIR differs from source: ${name}`);
          }
          await copyFile(binary, join(stage, "zkir", `${name}.bzkir`));
          for (const extension of ["prover", "verifier"]) {
            const path = join(circuit, `${name}.${extension}`);
            const hash = await hashFile(path);
            keyHashes[`${name}.${extension}`] = hash;
            keyFiles[`${name}.${extension}`] = { type: "file", size: (await lstat(path)).size,
              hash };
          }
        } finally {
          await rm(circuit, { recursive: true, force: true });
        }
      }
      await completeLightCompile(stage, names, keyFiles);
      const assets = assetNames(names);
      const assetHashes = Object.fromEntries(await Promise.all(assets.map(async (name) =>
        [name, await hashFile(await regularFile(join(stage, name)))])));
      const manifest = { format: FORMAT, sourceRevision: revision,
        compilerVersion: info["compiler-version"], platform: `${process.platform}/${process.arch}`,
        keygenSha256: expectedKeygenSha256, assets: assetHashes, keys: keyHashes };
      const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
      await writeFile(join(stage, "keyless-manifest.json"), manifestBytes, { mode: 0o600 });
      const manifestSha256 = createHash("sha256").update(manifestBytes).digest("hex");
      await verifyKeylessZkirBundle(stage, manifestSha256);
      return { manifestSha256,
        circuitCount: names.length, sourceRevision: revision };
    });
  } finally {
    await rm(generatorRoot, { recursive: true, force: true });
  }
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

/** Verify key portability without retaining all prover keys on the target platform.
 * @param {string} bundle @param {string} expectedManifestSha256 @param {string} keygen
 * @param {string} expectedKeygenSha256 @param {string} expectedRevision */
export async function verifyKeylessZkirStreaming(bundle, expectedManifestSha256, keygen,
  expectedKeygenSha256, expectedRevision) {
  if (!SHA256.test(expectedKeygenSha256)) throw new Error("Trusted key generator SHA-256 is required");
  if (!REVISION.test(expectedRevision)) throw new Error("Expected source revision is invalid");
  const { manifest, names } = await verifyKeylessZkirBundle(bundle, expectedManifestSha256);
  if (manifest.sourceRevision !== expectedRevision) {
    throw new Error("Keyless manifest source revision differs from expected source");
  }
  const stageRoot = await mkdtemp(join(tmpdir(), "tr-zkir-stream-"));
  try {
    const generator = join(stageRoot, "zkir-v3");
    await copyFile(await regularFile(resolve(keygen)), generator);
    if (await hashFile(generator) !== expectedKeygenSha256) {
      throw new Error("Key generator differs from the trusted binary digest");
    }
    for (const name of names) {
      const stage = join(stageRoot, name);
      await mkdir(stage);
      try {
        const input = join(stage, `${name}.zkir`);
        await copyFile(await regularFile(join(resolve(bundle), "zkir", `${name}.zkir`)), input);
        if (await hashFile(input) !== manifest.assets[`zkir/${name}.zkir`]) {
          throw new Error(`Copied ZKIR asset hash mismatch: ${name}`);
        }
        await runFile(generator, ["compile", input, join(stage, `${name}.prover`),
          join(stage, `${name}.verifier`)], { timeout: 60 * 60_000, maxBuffer: 1024 * 1024 });
        exactNames(await filesBelow(stage), [`${name}.zkir`, `${name}.bzkir`,
          `${name}.prover`, `${name}.verifier`], `Generated files for ${name}`);
        for (const [file, hash] of [
          [`${name}.bzkir`, manifest.assets[`zkir/${name}.bzkir`]],
          [`${name}.prover`, manifest.keys[`${name}.prover`]],
          [`${name}.verifier`, manifest.keys[`${name}.verifier`]],
        ]) {
          if (await hashFile(await regularFile(join(stage, file))) !== hash) {
            throw new Error(`Regenerated key or binary ZKIR hash mismatch: ${file}`);
          }
        }
      } finally {
        await rm(stage, { recursive: true, force: true });
      }
    }
  } finally {
    await rm(stageRoot, { recursive: true, force: true });
  }
  return { sourceRevision: expectedRevision, circuitCount: names.length,
    sourcePlatform: manifest.platform, generatorPlatform: `${process.platform}/${process.arch}`,
    keygenSha256: expectedKeygenSha256, matched: true };
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
    : command === "create-streaming" && args.length === 5
      ? await createKeylessZkirBundleStreaming(args[0], args[1], args[2], args[3], args[4])
    : command === "verify" && args.length === 2
      ? await verifyKeylessZkirBundle(args[0], args[1]).then(({ manifest, names }) =>
        ({ sourceRevision: manifest.sourceRevision, circuitCount: names.length }))
      : command === "verify-streaming" && args.length === 5
        ? await verifyKeylessZkirStreaming(args[0], args[1], args[2], args[3], args[4])
      : command === "materialize" && (args.length === 4 || args.length === 5)
        ? await materializeKeylessZkirBundle(args[0], args[1], args[2], args[3],
          args[4] === undefined ? 1 : Number(args[4]))
        : null;
  if (result === null) throw new Error("Usage: keyless-zkir-bundle.mjs create <full-managed> <keyless-dir> <source-sha> <zkir-bin> | create-streaming <light-managed> <keyless-dir> <source-sha> <zkir-bin> <trusted-zkir-bin-sha256> | verify <keyless-dir> <trusted-manifest-sha256> | verify-streaming <keyless-dir> <trusted-manifest-sha256> <zkir-bin> <trusted-zkir-bin-sha256> <source-sha> | materialize <keyless-dir> <destination> <zkir-bin> <trusted-manifest-sha256> [jobs: 1-4]");
  console.log(JSON.stringify(result));
}
