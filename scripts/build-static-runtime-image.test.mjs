import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { assertApprovedSourceEvidence, assertNoExportAttributes, staticAssetManifest,
  validateStaticImageInput } from "./build-static-runtime-image.mjs";

const base = `docker.io/library/node@sha256:${"a".repeat(64)}`;
const revision = "b".repeat(40);
const fingerprint = "C".repeat(40);

test("static image inputs require explicit digest, supported role, platform, and absolute destination", () => {
  assert.doesNotThrow(() => validateStaticImageInput("admin", base, "linux/arm64", "/tmp/admin-image",
    revision, fingerprint));
  assert.doesNotThrow(() => validateStaticImageInput("admin",
    `registry.local:5000/node@sha256:${"b".repeat(64)}`, "linux/arm64", "/tmp/admin-image",
    revision, fingerprint));
  for (const candidate of [
    ["unknown", base, "linux/arm64", "/tmp/image", revision, fingerprint],
    ["constructor", base, "linux/arm64", "/tmp/image", revision, fingerprint],
    ["admin", "node:24-bookworm-slim", "linux/arm64", "/tmp/image", revision, fingerprint],
    ["admin", base, "linux/ppc64le", "/tmp/image", revision, fingerprint],
    ["applicant", base, "linux/amd64", "relative/image", revision, fingerprint],
    ["admin", base, "linux/arm64", "/tmp/image", "wrong", fingerprint],
    ["admin", base, "linux/arm64", "/tmp/image", revision, "wrong"],
  ]) {
    assert.throws(() => validateStaticImageInput(...candidate), /digest-pinned base/u);
  }
  assert.throws(() => validateStaticImageInput("admin", base, "linux/arm64",
    resolve(fileURLToPath(new URL("..", import.meta.url))), revision, fingerprint),
  /outside the source checkout/u);
});

test("static image output cannot use a symlinked parent inside the checkout", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-static-output-"));
  try {
    await symlink(resolve(fileURLToPath(new URL("..", import.meta.url))),
      join(directory, "source"));
    assert.throws(() => validateStaticImageInput("admin", base, "linux/arm64",
      join(directory, "source", "image"), revision, fingerprint), /outside the source checkout/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("archive export attributes cannot alter signed source bytes", () => {
  assert.doesNotThrow(() => assertNoExportAttributes(
    "package.json\0export-ignore\0unspecified\0package.json\0export-subst\0unspecified\0"));
  assert.throws(() => assertNoExportAttributes(
    "package.json\0export-ignore\0set\0"), /export-modifying Git attribute/u);
  assert.throws(() => assertNoExportAttributes("broken\0export-ignore\0"),
    /Malformed Git attribute output/u);
});

test("source evidence requires exact clean signed DCO revision and approved signing key", () => {
  const evidence = {
    revision,
    status: "",
    validSignature: true,
    verificationOutput: `[GNUPG:] VALIDSIG ${fingerprint} 2026 0 4 0 1 10 00 ${fingerprint}`,
    message: "build(runtime): package static assets\n\nSigned-off-by: Test Operator <operator@example.test>",
  };
  assert.equal(assertApprovedSourceEvidence(evidence, revision, fingerprint), fingerprint);
  assert.throws(() => assertApprovedSourceEvidence({ ...evidence, revision: "a".repeat(40) },
    revision, fingerprint), /clean source revision/u);
  assert.throws(() => assertApprovedSourceEvidence({ ...evidence, status: " M package.json" },
    revision, fingerprint), /clean source revision/u);
  assert.throws(() => assertApprovedSourceEvidence({ ...evidence, validSignature: false },
    revision, fingerprint), /valid OpenPGP signature/u);
  assert.throws(() => assertApprovedSourceEvidence(evidence, revision, "D".repeat(40)),
    /approved signer/u);
  assert.throws(() => assertApprovedSourceEvidence({ ...evidence, message: "unsigned" },
    revision, fingerprint), /DCO-signed/u);
});

test("static asset manifest hashes regular files and rejects symlinks", async () => {
  const directory = await mkdtemp(join(tmpdir(), "tr-static-assets-"));
  try {
    await mkdir(join(directory, "assets"));
    await writeFile(join(directory, "index.html"), "<html></html>");
    await writeFile(join(directory, "assets", "app.js"), "export {};");
    await writeFile(join(directory, "assets", "app.js.map"), "{}");
    await writeFile(join(directory, "assets", "app.d.ts"), "export {};");
    const manifest = await staticAssetManifest(directory);
    assert.deepEqual(manifest.map((record) => record.path), ["assets/app.js", "index.html"]);
    assert.ok(manifest.every((record) => /^[0-9a-f]{64}$/u.test(record.sha256)));
    await writeFile(join(directory, "assets", "secret.txt"), "never serve");
    await assert.rejects(staticAssetManifest(directory), /Unexpected static build output/u);
    await rm(join(directory, "assets", "secret.txt"));
    await symlink(join(directory, "index.html"), join(directory, "assets", "link.html"));
    await assert.rejects(staticAssetManifest(directory), /regular file/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
