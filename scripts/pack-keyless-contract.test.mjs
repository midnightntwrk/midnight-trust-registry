import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmod, lstat, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { gunzipSync } from "node:zlib";

import { createKeylessZkirBundle } from "./keyless-zkir-bundle.mjs";
import { materializeKeylessContractPackage, packKeylessContract,
  verifyKeylessContractPackage } from "./pack-keyless-contract.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "tr-keyless-package-test-"));
  t.after(() => rm(root, { recursive: true }));
  const source = join(root, "contract");
  const full = join(source, "dist/managed/trust-registry");
  const keyless = join(root, "keyless");
  const tarball = join(root, "keyless.tgz");
  const restored = join(root, "restored");
  const generator = join(root, "zkir");
  for (const part of ["compiler", "contract", "zkir", "keys"]) {
    await mkdir(join(full, part), { recursive: true });
  }
  await writeFile(join(source, "package.json"), JSON.stringify({
    name: "@midnight-ntwrk/trust-registry-contract", version: "0.1.0-rc1",
    files: ["dist/**"],
  }));
  await writeFile(join(source, "dist/index.js"), "export const packageReady = true;\n");
  await writeFile(join(full, "compiler/contract-info.json"), JSON.stringify({
    "compiler-version": "0.31.1", circuits: [{ name: "demoCircuit", proof: true }],
  }));
  await writeFile(join(full, "contract/index.js"), "export const demo = true;\n");
  if (process.platform === "darwin") {
    execFileSync("xattr", ["-w", "com.example.keyless-test", "metadata",
      join(full, "contract/index.js")]);
  }
  await writeFile(join(full, "contract/index.js.map"), "{}\n");
  await writeFile(join(full, "contract/index.d.ts"), "export declare const demo: boolean;\n");
  await writeFile(join(full, "zkir/demoCircuit.zkir"), "sample-zkir\n");
  await writeFile(join(full, "zkir/demoCircuit.bzkir"), "sample-bzkir\n");
  await writeFile(join(full, "keys/demoCircuit.prover"), "sample-zkir\n");
  await writeFile(join(full, "keys/demoCircuit.verifier"), "sample-zkir\n");
  await writeFile(generator, "#!/bin/sh\n[ \"$1\" = compile ] || exit 2\ncp \"$2\" \"$3\"\ncp \"$2\" \"$4\"\n");
  await chmod(generator, 0o700);
  const created = await createKeylessZkirBundle(full, keyless, "a".repeat(40), generator);
  return { root, source, keyless, tarball, restored, generator, manifestSha256: created.manifestSha256 };
}

test("keyless contract package excludes keys and restores a verified local package", async (t) => {
  const paths = await fixture(t);
  const packed = await packKeylessContract(paths.source, paths.keyless,
    paths.manifestSha256, paths.tarball);
  assert.equal(packed.name, "@midnight-ntwrk/trust-registry-contract");
  const listing = execFileSync("tar", ["-tzf", paths.tarball], { encoding: "utf8" });
  assert.match(listing, /package\/dist\/managed\/trust-registry\/keyless-manifest\.json/u);
  assert.match(listing, /package\/LICENSE/u);
  assert.doesNotMatch(listing, /\.prover|\.verifier/u);
  const rawArchive = gunzipSync(await readFile(paths.tarball));
  assert.equal(rawArchive.includes(Buffer.from("LIBARCHIVE.xattr.")), false);
  assert.equal(rawArchive.includes(Buffer.from("._package")), false);
  const verified = await verifyKeylessContractPackage(paths.tarball,
    packed.tarballSha256, paths.manifestSha256);
  assert.equal(verified.circuitCount, 1);
  await materializeKeylessContractPackage(paths.tarball, paths.restored, paths.generator,
    packed.tarballSha256, paths.manifestSha256);
  assert.equal(await readFile(join(paths.restored, "LICENSE"), "utf8"),
    await readFile(new URL("../LICENSE", import.meta.url), "utf8"));
  assert.equal(await readFile(join(paths.restored,
    "dist/managed/trust-registry/keys/demoCircuit.prover"), "utf8"), "sample-zkir\n");
  assert.equal(await readFile(join(paths.restored, "dist/index.js"), "utf8"),
    "export const packageReady = true;\n");
  await assert.rejects(lstat(join(paths.restored,
    "dist/managed/trust-registry/keyless-manifest.json")), { code: "ENOENT" });
});

test("untrusted archive, manifest, or keygen cannot produce an accepted package", async (t) => {
  const paths = await fixture(t);
  const packed = await packKeylessContract(paths.source, paths.keyless,
    paths.manifestSha256, paths.tarball);
  await assert.rejects(materializeKeylessContractPackage(paths.tarball, paths.restored,
    paths.generator, "b".repeat(64), paths.manifestSha256), /trusted release digest/u);
  await assert.rejects(materializeKeylessContractPackage(paths.tarball, paths.restored,
    paths.generator, packed.tarballSha256, "c".repeat(64)), /trusted release digest/u);
  await writeFile(paths.generator, "#!/bin/sh\nexit 0\n");
  await assert.rejects(materializeKeylessContractPackage(paths.tarball, paths.restored,
    paths.generator, packed.tarballSha256, paths.manifestSha256), /binary digest/u);
  await assert.rejects(lstat(paths.restored), { code: "ENOENT" });
});

test("a modified package archive fails before extraction", async (t) => {
  const paths = await fixture(t);
  const packed = await packKeylessContract(paths.source, paths.keyless,
    paths.manifestSha256, paths.tarball);
  const bytes = await readFile(paths.tarball);
  await writeFile(paths.tarball, Buffer.concat([bytes, Buffer.from("tampered") ]));
  assert.notEqual(sha256(await readFile(paths.tarball)), packed.tarballSha256);
  await assert.rejects(verifyKeylessContractPackage(paths.tarball,
    packed.tarballSha256, paths.manifestSha256), /trusted release digest/u);
});
