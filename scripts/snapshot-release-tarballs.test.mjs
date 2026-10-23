import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";

import { snapshotReleaseTarballs } from "./snapshot-release-tarballs.mjs";

const roots = [];
afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const fixture = () => {
  const root = mkdtempSync(join(tmpdir(), "tr-snapshot-packages-"));
  roots.push(root);
  const artifacts = join(root, "artifacts");
  mkdirSync(artifacts);
  const filename = "midnight-ntwrk-trust-registry-contract-0.1.0.tgz";
  const content = Buffer.from("verified-package-bytes\n");
  writeFileSync(join(artifacts, filename), content);
  const manifest = { packages: [{ filename, sizeBytes: content.length,
    sha256: createHash("sha256").update(content).digest("hex") }] };
  return { root, artifacts, filename, manifest, content };
};

test("installs from a private manifest-matched copy, not the mutable staging path", () => {
  const { root, artifacts, filename, manifest, content } = fixture();
  const copied = snapshotReleaseTarballs(manifest, artifacts, join(root, "verified"));
  assert.deepEqual(copied, [join(root, "verified", filename)]);
  writeFileSync(join(artifacts, filename), "changed-after-verification\n");
  assert.deepEqual(readFileSync(copied[0]), content);
});

test("rejects a package replaced between manifest verification and copying", () => {
  const { root, artifacts, filename, manifest } = fixture();
  writeFileSync(join(artifacts, filename), "changed-before-copy\n");
  assert.throws(() => snapshotReleaseTarballs(manifest, artifacts, join(root, "verified")),
    /Release snapshot differs from verified package/u);
});

test("rejects escaping filenames and preexisting snapshot directories", () => {
  const { root, artifacts, manifest } = fixture();
  assert.throws(() => snapshotReleaseTarballs({ packages: [{ ...manifest.packages[0],
    filename: "../escape.tgz" }] }, artifacts, join(root, "verified")),
  /filename is invalid/u);
  assert.throws(() => snapshotReleaseTarballs(manifest, artifacts, join(root, "verified")),
    /EEXIST/u);
});
