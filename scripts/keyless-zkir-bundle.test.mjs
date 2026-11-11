import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chmod, lstat, mkdir, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { createKeylessZkirBundle, materializeKeylessZkirBundle,
  verifyKeylessZkirAgainstFullSource,
  verifyKeylessZkirBundle } from "./keyless-zkir-bundle.mjs";

const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const revision = "a".repeat(40);

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "tr-keyless-test-"));
  t.after(() => rm(root, { recursive: true }));
  const full = join(root, "full");
  const keyless = join(root, "keyless");
  const restored = join(root, "restored");
  const generator = join(root, "zkir");
  for (const part of ["compiler", "contract", "zkir", "keys"]) {
    await mkdir(join(full, part), { recursive: true });
  }
  await writeFile(join(full, "compiler/contract-info.json"), JSON.stringify({
    "compiler-version": "0.31.1", circuits: [{ name: "demoCircuit", proof: true }],
  }));
  await writeFile(join(full, "contract/index.js"), "export const demo = true;\n");
  await writeFile(join(full, "contract/index.js.map"), "{}\n");
  await writeFile(join(full, "contract/index.d.ts"), "export declare const demo: boolean;\n");
  await writeFile(join(full, "zkir/demoCircuit.zkir"), "sample-zkir\n");
  await writeFile(join(full, "zkir/demoCircuit.bzkir"), "sample-bzkir\n");
  await writeFile(join(full, "keys/demoCircuit.prover"), "sample-zkir\n");
  await writeFile(join(full, "keys/demoCircuit.verifier"), "sample-zkir\n");
  await writeFile(generator, "#!/bin/sh\n[ \"$1\" = compile ] || exit 2\ncp \"$2\" \"$3\"\ncp \"$2\" \"$4\"\n");
  await chmod(generator, 0o700);
  return { root, full, keyless, restored, generator };
}

test("keyless bundle excludes keys and regenerates only verified outputs", async (t) => {
  const paths = await fixture(t);
  const created = await createKeylessZkirBundle(paths.full, paths.keyless, revision, paths.generator);
  assert.equal(created.circuitCount, 1);
  assert.equal((await readdir(paths.keyless)).includes("keys"), false);
  assert.equal((await readdir(join(paths.keyless, "zkir"))).length, 2);
  const verified = await verifyKeylessZkirBundle(paths.keyless, created.manifestSha256);
  assert.equal(verified.manifest.keys["demoCircuit.prover"], sha256("sample-zkir\n"));
  await materializeKeylessZkirBundle(paths.keyless, paths.restored, paths.generator,
    created.manifestSha256);
  assert.equal((await readFile(join(paths.restored, "keys/demoCircuit.prover"), "utf8")),
    "sample-zkir\n");
  assert.equal((await readFile(join(paths.restored, "keys/demoCircuit.verifier"), "utf8")),
    "sample-zkir\n");
});

test("trusted digest and ZKIR mutations fail before materialization", async (t) => {
  const paths = await fixture(t);
  const created = await createKeylessZkirBundle(paths.full, paths.keyless, revision, paths.generator);
  await assert.rejects(verifyKeylessZkirBundle(paths.keyless, "b".repeat(64)), /trusted release digest/u);
  await writeFile(join(paths.keyless, "zkir/demoCircuit.zkir"), "different\n");
  await assert.rejects(materializeKeylessZkirBundle(paths.keyless, paths.restored,
    paths.generator, created.manifestSha256), /asset hash mismatch/u);
  await assert.rejects(lstat(paths.restored), { code: "ENOENT" });
});

test("builder rejects a keyless manifest that differs from signed-source outputs", async (t) => {
  const paths = await fixture(t);
  const created = await createKeylessZkirBundle(paths.full, paths.keyless, revision, paths.generator);
  await verifyKeylessZkirAgainstFullSource(paths.keyless, paths.full, created.manifestSha256,
    revision);
  await assert.rejects(verifyKeylessZkirAgainstFullSource(paths.keyless, paths.full,
    created.manifestSha256, "b".repeat(40)), /source revision/u);
  await writeFile(join(paths.full, "keys/demoCircuit.verifier"), "changed\n");
  await assert.rejects(verifyKeylessZkirAgainstFullSource(paths.keyless, paths.full,
    created.manifestSha256, revision), /Expected key differs from full source/u);
});

test("wrong generator and wrong regenerated keys fail closed", async (t) => {
  const paths = await fixture(t);
  const created = await createKeylessZkirBundle(paths.full, paths.keyless, revision, paths.generator);
  await writeFile(paths.generator, "#!/bin/sh\nexit 0\n");
  await assert.rejects(materializeKeylessZkirBundle(paths.keyless, paths.restored,
    paths.generator, created.manifestSha256), /binary digest/u);
  await writeFile(paths.generator, "#!/bin/sh\n[ \"$1\" = compile ] || exit 2\ncp \"$2\" \"$3\"\ncp \"$2\" \"$4\"\n");
  const manifestPath = join(paths.keyless, "keyless-manifest.json");
  const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
  manifest.keys["demoCircuit.prover"] = "c".repeat(64);
  const bytes = `${JSON.stringify(manifest, null, 2)}\n`;
  await writeFile(manifestPath, bytes);
  await assert.rejects(materializeKeylessZkirBundle(paths.keyless, paths.restored,
    paths.generator, sha256(bytes)), /Regenerated key hash mismatch/u);
  assert.deepEqual((await readdir(paths.root)).filter((name) => name.startsWith("restored")), []);
});

test("extra files and symlinks cannot enter the source or release bundle", async (t) => {
  const paths = await fixture(t);
  await writeFile(join(paths.full, "zkir/forged.zkir"), "forged");
  await assert.rejects(createKeylessZkirBundle(paths.full, paths.keyless, revision,
    paths.generator), /ZKIR assets/u);
  await rm(join(paths.full, "zkir/forged.zkir"));
  const created = await createKeylessZkirBundle(paths.full, paths.keyless, revision, paths.generator);
  await symlink(join(paths.full, "keys/demoCircuit.prover"), join(paths.keyless, "leaked.prover"));
  await assert.rejects(verifyKeylessZkirBundle(paths.keyless, created.manifestSha256),
    /Non-regular bundle entry/u);
});

test("a failed later circuit leaves no accepted cache or partial destination", async (t) => {
  const paths = await fixture(t);
  await writeFile(join(paths.full, "compiler/contract-info.json"), JSON.stringify({
    "compiler-version": "0.31.1", circuits: [
      { name: "demoCircuit", proof: true }, { name: "laterCircuit", proof: true },
    ],
  }));
  await writeFile(join(paths.full, "zkir/laterCircuit.zkir"), "later-zkir\n");
  await writeFile(join(paths.full, "zkir/laterCircuit.bzkir"), "later-bzkir\n");
  await writeFile(join(paths.full, "keys/laterCircuit.prover"), "later-zkir\n");
  await writeFile(join(paths.full, "keys/laterCircuit.verifier"), "later-zkir\n");
  await writeFile(paths.generator, "#!/bin/sh\ncase \"$2\" in *laterCircuit*) exit 4;; esac\ncp \"$2\" \"$3\"\ncp \"$2\" \"$4\"\n");
  const created = await createKeylessZkirBundle(paths.full, paths.keyless, revision, paths.generator);
  await assert.rejects(materializeKeylessZkirBundle(paths.keyless, paths.restored,
    paths.generator, created.manifestSha256, 2), /Key generation failed for circuit laterCircuit/u);
  assert.deepEqual((await readdir(paths.root)).filter((name) => name.startsWith("restored")), []);
});
