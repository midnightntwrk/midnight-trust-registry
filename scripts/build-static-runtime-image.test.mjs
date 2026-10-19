import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { staticAssetManifest, validateStaticImageInput } from "./build-static-runtime-image.mjs";

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
    ["admin", "node:24-bookworm-slim", "linux/arm64", "/tmp/image", revision, fingerprint],
    ["admin", base, "linux/ppc64le", "/tmp/image", revision, fingerprint],
    ["applicant", base, "linux/amd64", "relative/image", revision, fingerprint],
    ["admin", base, "linux/arm64", "/tmp/image", "wrong", fingerprint],
    ["admin", base, "linux/arm64", "/tmp/image", revision, "wrong"],
  ]) {
    assert.throws(() => validateStaticImageInput(...candidate), /digest-pinned base/u);
  }
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
