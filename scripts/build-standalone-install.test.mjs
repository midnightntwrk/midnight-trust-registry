import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { mkdtemp, mkdir, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";

import { assertRequiredWorkspaceFiles, pinnedStandaloneImages, stageApiRuntimeImage, stageStaticRuntimeImage,
  validateStandaloneInstallInputs, validateStaticRuntimeImageInput } from "./build-standalone-install.mjs";
import { STANDALONE_PROOF_PARAMETER_PATHS } from "./check-standalone-install.mjs";
import { packageManifestCatalog } from "./trust-registry-workspace-catalog.mjs";

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

test("install preflight rejects a missing API package entrypoint", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-install-entrypoints-test-"));
  const workspace = "packages/trust-registry-api";
  try {
    for (const path of packageManifestCatalog.get(workspace).requiredPackedPaths) {
      const target = join(root, workspace, path);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, "fixture\n");
    }
    assert.doesNotThrow(() => assertRequiredWorkspaceFiles(root, [workspace]));
    await rm(join(root, workspace, "dist/index.js"));
    assert.throws(() => assertRequiredWorkspaceFiles(root, [workspace]),
      /required package file is missing before install build: dist\/index.js/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("preflight checks proof and image inputs without creating an install directory", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-install-preflight-test-"));
  try {
    const revision = "a".repeat(40);
    const options = { outputRoot: join(root, "output"), proofSource: join(root, "proof") };
    const inspectImage = (reference) => [reference];
    assert.throws(() => validateStandaloneInstallInputs(options, revision, inspectImage),
      /Proof parameter is missing/u);
    for (const name of STANDALONE_PROOF_PARAMETER_PATHS) {
      const path = join(options.proofSource, name);
      await mkdir(dirname(path), { recursive: true });
      await writeFile(path, "parameter\n");
    }
    const plan = validateStandaloneInstallInputs(options, revision, inspectImage);
    assert.equal(plan.destination, join(options.outputRoot, revision));
    assert.equal(existsSync(options.outputRoot), false);
    assert.throws(() => validateStandaloneInstallInputs(options, revision, () => []),
      /approved repository digest/u);
    const apiImageDirectory = join(root, "api");
    await mkdir(apiImageDirectory);
    await writeFile(join(apiImageDirectory, "manifest.json"), JSON.stringify({
      sourceRevision: "b".repeat(40), archiveName: "api.image.tar",
    }));
    await writeFile(join(apiImageDirectory, "api.image.tar"), "archive\n");
    assert.throws(() => validateStandaloneInstallInputs({ ...options, apiImageDirectory },
      revision, inspectImage), /source revision/u);
    assert.equal(existsSync(options.outputRoot), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("stages both portal roles only from same-source regular image files", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-stage-portals-test-"));
  try {
    const destination = join(root, "bundle");
    await mkdir(join(destination, "images"), { recursive: true });
    const revision = "a".repeat(40);
    for (const role of ["admin", "applicant"]) {
      const source = join(root, role);
      await mkdir(source);
      const manifest = Buffer.from(JSON.stringify({ role, sourceRevision: revision,
        archiveName: `${role}.image.tar` }));
      const archive = Buffer.from(`${role}-archive\n`);
      await writeFile(join(source, "manifest.json"), manifest);
      await writeFile(join(source, `${role}.image.tar`), archive);
      const staged = await stageStaticRuntimeImage(source, destination, role, revision);
      assert.equal(staged.manifestSha256, createHash("sha256").update(manifest).digest("hex"));
      assert.equal(staged.archiveSha256, createHash("sha256").update(archive).digest("hex"));
      assert.deepEqual(await readFile(join(destination, staged.archive)), archive);
      assert.throws(() => validateStaticRuntimeImageInput(source, role, "b".repeat(40)),
        /disagrees/u);
      await rm(join(source, `${role}.image.tar`));
      await symlink(join(destination, staged.archive), join(source, `${role}.image.tar`));
      assert.throws(() => validateStaticRuntimeImageInput(source, role, revision), /regular/u);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
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
