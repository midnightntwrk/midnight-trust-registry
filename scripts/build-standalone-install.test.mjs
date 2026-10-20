import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { pinnedStandaloneImages, stageApiRuntimeImage } from "./build-standalone-install.mjs";

const image = `midnightntwrk/test@sha256:${"a".repeat(64)}`;
const compose = `name: \${TR_STACK_NAME:-tr-standalone-local-smoke}
services:
  node: {image: ${image}}
  indexer: {image: ${image}}
  proof-server: {image: ${image}}
`;

test("accepts only three digest-pinned dedicated services", () => {
  assert.deepEqual(pinnedStandaloneImages(compose).map((entry) => entry.role),
    ["node", "indexer", "proof-server"]);
  assert.throws(() => pinnedStandaloneImages(compose.replace("sha256:", "latest-")), /digest pinned/u);
  assert.throws(() => pinnedStandaloneImages(`${compose}  extra: {image: ${image}}\n`), /exactly three/u);
  assert.throws(() => pinnedStandaloneImages(compose.replace("tr-standalone-local-smoke", "other")),
    /dedicated project/u);
  assert.throws(() => pinnedStandaloneImages(compose.replace("TR_STACK_NAME", "UNTRUSTED_PROJECT")),
    /dedicated project/u);
});

test("stages only same-source regular API image files with exact hashes", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-stage-api-test-"));
  try {
    const source = join(root, "source");
    const destination = join(root, "bundle");
    await mkdir(source);
    await mkdir(join(destination, "images"), { recursive: true });
    const revision = "a".repeat(40);
    const manifest = Buffer.from(JSON.stringify({ sourceRevision: revision, archiveName: "api.image.tar" }));
    const archive = Buffer.from("image-archive\n");
    await writeFile(join(source, "manifest.json"), manifest);
    await writeFile(join(source, "api.image.tar"), archive);
    const staged = await stageApiRuntimeImage(source, destination, revision);
    assert.equal(staged.manifestSha256, createHash("sha256").update(manifest).digest("hex"));
    assert.equal(staged.archiveSha256, createHash("sha256").update(archive).digest("hex"));
    assert.deepEqual(await readFile(join(destination, staged.archive)), archive);
    await assert.rejects(stageApiRuntimeImage(source, destination, revision), /EEXIST/u);
    await assert.rejects(stageApiRuntimeImage(source, destination, "b".repeat(40)), /source revision/u);
    await assert.rejects(stageApiRuntimeImage("relative", destination, revision), /absolute/u);
    await rm(join(source, "api.image.tar"));
    await symlink(join(destination, staged.archive), join(source, "api.image.tar"));
    await assert.rejects(stageApiRuntimeImage(source, destination, revision), /regular/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
