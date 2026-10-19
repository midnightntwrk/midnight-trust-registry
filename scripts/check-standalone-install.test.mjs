import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import { verifyStandaloneInstallBundle } from "./check-standalone-install.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const revision = "a".repeat(40);
const reference = (role) => `example.test/${role}@sha256:${"b".repeat(64)}`;

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "tr-install-inventory-"));
  await mkdir(join(root, "artifacts"));
  await mkdir(join(root, "images"));
  await writeFile(join(root, "release.json"), JSON.stringify({ sourceRevision: revision, packages: [] }));
  const images = [];
  for (const role of ["node", "indexer", "proof-server"]) {
    const bytes = Buffer.from(`${role}-archive`);
    await writeFile(join(root, "images", `${role}.tar`), bytes);
    images.push({ role, reference: reference(role), archive: `images/${role}.tar`, archiveSha256: sha(bytes) });
  }
  const inventory = {
    format: "tr-standalone-install-v1", sourceRevision: revision,
    packageManifest: "release.json", artifactDirectory: "artifacts", images,
  };
  await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
  return { root, inventory };
}

test("verifies pinned package manifest and all three staged image archives", async () => {
  const { root } = await fixture();
  try {
    let verified = false;
    const expectedArtifacts = join(await realpath(root), "artifacts");
    const result = await verifyStandaloneInstallBundle(root, (manifest, artifactDir) => {
      assert.equal(manifest.sourceRevision, revision);
      assert.equal(artifactDir, expectedArtifacts);
      verified = true;
    });
    assert.equal(verified, true);
    assert.deepEqual(result.imageRoles, ["indexer", "node", "proof-server"]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects altered archives, floating tags, missing roles, and source drift", async () => {
  const { root, inventory } = await fixture();
  try {
    await writeFile(join(root, "images/node.tar"), "tampered");
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /archive hash mismatch/u);
    await writeFile(join(root, "images/node.tar"), "node-archive");
    inventory.images[0].reference = "example.test/node:latest";
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /Unpinned/u);
    inventory.images.pop();
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /required roles/u);
    inventory.images.push({ role: "proof-server", reference: reference("proof-server"),
      archive: "images/proof-server.tar", archiveSha256: sha("proof-server-archive") });
    inventory.images[0].reference = reference("node");
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await writeFile(join(root, "release.json"), JSON.stringify({ sourceRevision: "c".repeat(40), packages: [] }));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /source revision disagrees/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("rejects escaping paths and symlinked archives", async () => {
  const { root, inventory } = await fixture();
  try {
    inventory.images[0].archive = "../outside.tar";
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /Unsafe/u);
    inventory.images[0].archive = "images/node.tar";
    await rm(join(root, "images/node.tar"));
    await symlink(join(root, "images/indexer.tar"), join(root, "images/node.tar"));
    await writeFile(join(root, "install-inventory.json"), JSON.stringify(inventory));
    await assert.rejects(verifyStandaloneInstallBundle(root, () => {}), /not regular/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
