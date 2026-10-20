import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { loadStandaloneInstallImages } from "./load-standalone-install-images.mjs";

const root = await mkdtemp(join(tmpdir(), "tr-offline-images-"));
after(() => rm(root, { recursive: true, force: true }));
const revision = "a".repeat(40);
await writeFile(join(root, "install-inventory.json"), JSON.stringify({ sourceRevision: revision, images: [
  { role: "node", reference: "node@sha256:" + "b".repeat(64), archive: "node.tar" },
] }));

test("loads approved bytes, verifies image ID, and tags without a pull", async () => {
  const calls = [];
  const expectedId = `sha256:${"c".repeat(64)}`;
  const result = await loadStandaloneInstallImages(root, {
    verify: async () => { calls.push("verify"); },
    archivePath: (_, image) => join(root, image.archive),
    imageId: () => expectedId,
    docker: (args) => {
      calls.push(args[0]);
      if (args[0] === "image" && args[2].startsWith("tr-standalone/")) {
        throw { status: 1, stderr: "No such image" };
      }
      if (args[0] === "image") return expectedId;
      if (args[0] === "load") return `Loaded image ID: ${expectedId}`;
      return "";
    },
  });
  assert.deepEqual(calls, ["verify", "image", "load", "image", "tag"]);
  assert.equal(result.tags.node, `tr-standalone/node:sha-${revision}`);
  assert.equal(result.freshDaemon, "not-verified");
  assert.equal(result.pullDisabledRestart, "not-run");
});

test("a conflicting local tag blocks loading", async () => {
  let loaded = false;
  await assert.rejects(loadStandaloneInstallImages(root, {
    verify: async () => {}, archivePath: (_, image) => join(root, image.archive),
    imageId: () => `sha256:${"c".repeat(64)}`,
    docker: (args) => {
      if (args[0] === "load") loaded = true;
      return `sha256:${"d".repeat(64)}`;
    },
  }), /different bytes/u);
  assert.equal(loaded, false);
});

test("accepts a containerd manifest ID reported by docker load", async () => {
  const manifestId = `sha256:${"b".repeat(64)}`;
  const result = await loadStandaloneInstallImages(root, {
    verify: async () => {}, archivePath: (_, image) => join(root, image.archive),
    imageId: () => `sha256:${"c".repeat(64)}`,
    docker: (args) => {
      if (args[0] === "image" && args[2].startsWith("tr-standalone/")) {
        throw { status: 1, stderr: "No such image" };
      }
      if (args[0] === "image") return manifestId;
      if (args[0] === "load") return `Loaded image ID: ${manifestId}`;
      return "";
    },
  });
  assert.equal(result.tags.node, `tr-standalone/node:sha-${revision}`);
});

test("loaded image ID mismatch blocks tagging", async () => {
  let tagged = false;
  await assert.rejects(loadStandaloneInstallImages(root, {
    verify: async () => {}, archivePath: (_, image) => join(root, image.archive),
    imageId: () => `sha256:${"c".repeat(64)}`,
    docker: (args) => {
      if (args[0] === "image" && args[2].startsWith("tr-standalone/")) {
        throw { status: 1, stderr: "No such image" };
      }
      if (args[0] === "tag") tagged = true;
      if (args[0] === "image") return `sha256:${"d".repeat(64)}`;
      if (args[0] === "load") return `Loaded image ID: sha256:${"d".repeat(64)}`;
      return "";
    },
  }), /disagrees/u);
  assert.equal(tagged, false);
});

test("v4 loads the verified API archive without a registry pull", async () => {
  const inventoryPath = join(root, "install-inventory.json");
  const original = await readFile(inventoryPath);
  const imageId = `sha256:${"c".repeat(64)}`;
  try {
    const inventory = JSON.parse(original);
    inventory.format = "tr-standalone-install-v4";
    inventory.apiRuntime = { archive: "api.image.tar", archiveSha256: "d".repeat(64) };
    await writeFile(inventoryPath, JSON.stringify(inventory));
    const loads = [];
    const result = await loadStandaloneInstallImages(root, {
      verify: async () => ({ apiRuntime: { imageId } }),
      archivePath: (_, image) => join(root, image.archive),
      imageId: () => imageId,
      docker: (args) => {
        if (args[0] === "image" && args[2].startsWith("tr-standalone/")) {
          throw { status: 1, stderr: "No such image" };
        }
        if (args[0] === "image") return imageId;
        if (args[0] === "load") {
          loads.push(args[2]);
          return `Loaded image ID: ${imageId}`;
        }
        return "";
      },
    });
    assert.deepEqual(loads, [join(root, "node.tar"), join(root, "api.image.tar")]);
    assert.equal(result.tags.api, `tr-standalone/api:sha-${revision}`);
  } finally {
    await writeFile(inventoryPath, original);
  }
});
