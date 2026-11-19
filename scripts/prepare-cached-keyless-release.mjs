import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, readFile, readdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import process from "node:process";

import { reuseKeylessZkirReference, verifyKeylessZkirBundle } from "./keyless-zkir-bundle.mjs";

const SHARDS = 12;
const REFERENCE_DIGEST = "d95f9a92fbffa5be4fe6f63be25d380f1188bd1bbe8754de7f64b2f162fc7b58";
const REFERENCE_REVISION = "929c07982f1c16571b5ce0f5eee8ed70501677d5";

async function hash(path) {
  if (!(await lstat(path)).isFile()) throw new Error(`Expected a regular cache file: ${path}`);
  const digest = createHash("sha256");
  for await (const chunk of createReadStream(path)) digest.update(chunk);
  return digest.digest("hex");
}

function shardNames(names, shard) {
  return names.filter((_, index) => index % SHARDS === shard);
}

const [mode, reference, ...args] = process.argv.slice(2);
try {
  const { manifest, names } = await verifyKeylessZkirBundle(reference, REFERENCE_DIGEST);
  if (manifest.sourceRevision !== REFERENCE_REVISION || manifest.platform !== "linux/x64") {
    throw new Error("Unexpected Linux proof reference");
  }
  if (mode === "shard" && args.length === 3 && /^(?:[0-9]|1[01])$/u.test(args[0])) {
    const [index, cached, receipt] = args;
    const shard = Number(index);
    const circuits = shardNames(names, shard);
    const entries = await readdir(cached);
    const expected = ["zkir-key-manifest.json", ...circuits.flatMap((name) =>
      [`${name}.prover`, `${name}.verifier`])].sort();
    if (JSON.stringify(entries.sort()) !== JSON.stringify(expected)) {
      throw new Error(`Cache shard ${shard} has missing or unexpected files`);
    }
    for (const name of circuits) {
      for (const extension of ["prover", "verifier"]) {
        const file = `${name}.${extension}`;
        if (await hash(join(cached, file)) !== manifest.keys[file]) {
          throw new Error(`Cache shard ${shard} key differs from the trusted inventory: ${file}`);
        }
      }
    }
    const result = { shard, circuits, reused: circuits.length, generated: 0,
      referenceSha256: REFERENCE_DIGEST };
    await writeFile(receipt, `${JSON.stringify(result)}\n`, { flag: "wx" });
    console.log(`Shard ${shard}: ${result.reused} reused, 0 generated`);
  } else if (mode === "assemble" && args.length === 4) {
    const [receipts, light, output, revision] = args;
    const expectedFiles = Array.from({ length: SHARDS }, (_, shard) => `shard-${shard}.json`);
    if (JSON.stringify((await readdir(receipts)).sort()) !== JSON.stringify(expectedFiles.toSorted())) {
      throw new Error("Expected exactly 12 cache restoration receipts");
    }
    for (const [shard, file] of expectedFiles.entries()) {
      const circuits = shardNames(names, shard);
      const value = JSON.parse(await readFile(join(receipts, file), "utf8"));
      if (value.shard !== shard || value.generated !== 0 || value.reused !== circuits.length
        || value.referenceSha256 !== REFERENCE_DIGEST
        || JSON.stringify(value.circuits) !== JSON.stringify(circuits)) {
        throw new Error(`Cache restoration receipt does not cover shard ${shard}`);
      }
    }
    const manifestSha256 = await reuseKeylessZkirReference(light, reference, REFERENCE_DIGEST, output, revision);
    console.log(JSON.stringify({ sourceRevision: revision, manifestSha256, restoredShards: SHARDS,
      reused: names.length, generated: 0 }));
  } else {
    throw new Error("Usage: prepare-cached-keyless-release.mjs shard <reference> <index> <cache> <receipt> | assemble <reference> <receipts> <light> <output> <revision>");
  }
} catch (error) {
  console.error(error instanceof Error ? error.message : "Cached preparation failed");
  process.exitCode = 1;
}
