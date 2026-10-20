import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
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
const verifiedInventory = async () => ({ inventorySha256: createHash("sha256")
  .update(await readFile(join(root, "install-inventory.json"))).digest("hex") });

test("loads approved bytes, verifies image ID, and tags without a pull", async () => {
  const calls = [];
  const expectedId = `sha256:${"c".repeat(64)}`;
  const result = await loadStandaloneInstallImages(root, {
    verify: async () => { calls.push("verify"); return verifiedInventory(); },
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
    verify: verifiedInventory, archivePath: (_, image) => join(root, image.archive),
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
    verify: verifiedInventory, archivePath: (_, image) => join(root, image.archive),
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
    verify: verifiedInventory, archivePath: (_, image) => join(root, image.archive),
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
      verify: async () => ({ ...await verifiedInventory(), apiRuntime: { imageId, configId: imageId } }),
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

test("v4 accepts the verified config ID reported by a classic Docker store", async () => {
  const inventoryPath = join(root, "install-inventory.json");
  const original = await readFile(inventoryPath);
  const imageId = `sha256:${"c".repeat(64)}`;
  const configId = `sha256:${"d".repeat(64)}`;
  try {
    const inventory = JSON.parse(original);
    inventory.format = "tr-standalone-install-v4";
    inventory.apiRuntime = { archive: "api.image.tar", archiveSha256: "e".repeat(64) };
    await writeFile(inventoryPath, JSON.stringify(inventory));
    const result = await loadStandaloneInstallImages(root, {
      verify: async () => ({ ...await verifiedInventory(), apiRuntime: { imageId, configId } }),
      archivePath: (_, image) => join(root, image.archive), imageId: () => imageId,
      docker: (args) => {
        if (args[0] === "image" && args[2].startsWith("tr-standalone/")) {
          throw { status: 1, stderr: "No such image" };
        }
        if (args[0] === "image") return args[2];
        if (args[0] === "load") return `Loaded image ID: ${args[2].endsWith("api.image.tar") ? configId : imageId}`;
        return "";
      },
    });
    assert.equal(result.tags.api, `tr-standalone/api:sha-${revision}`);
  } finally {
    await writeFile(inventoryPath, original);
  }
});

test("v5 and v6 load both verified portal archives after the ledger and API images", async () => {
  const inventoryPath = join(root, "install-inventory.json");
  const original = await readFile(inventoryPath);
  const imageId = `sha256:${"c".repeat(64)}`;
  try {
    for (const format of ["tr-standalone-install-v5", "tr-standalone-install-v6"]) {
      const inventory = JSON.parse(original);
      inventory.format = format;
      inventory.apiRuntime = { archive: "api.image.tar", archiveSha256: "d".repeat(64) };
      inventory.portalRuntimes = {
        admin: { archive: "admin.image.tar", archiveSha256: "e".repeat(64) },
        applicant: { archive: "applicant.image.tar", archiveSha256: "f".repeat(64) },
      };
      await writeFile(inventoryPath, JSON.stringify(inventory));
      const loads = [];
      const verified = { ...await verifiedInventory(), apiRuntime: { imageId, configId: imageId },
        portalRuntimes: { admin: { imageId, configId: imageId },
          applicant: { imageId, configId: imageId } } };
      const result = await loadStandaloneInstallImages(root, {
        verify: async () => verified,
        archivePath: (_, image) => join(root, image.archive), imageId: () => imageId,
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
      assert.deepEqual(loads.map((path) => path.split("/").at(-1)),
        ["node.tar", "api.image.tar", "admin.image.tar", "applicant.image.tar"]);
      assert.equal(result.tags.admin, `tr-standalone/admin:sha-${revision}`);
      assert.equal(result.tags.applicant, `tr-standalone/applicant:sha-${revision}`);
      await assert.rejects(loadStandaloneInstallImages(root, {
        verify: async () => ({ ...verified, portalRuntimes: { admin: verified.portalRuntimes.admin } }),
      }), /portal image IDs are missing/u);
    }
  } finally {
    await writeFile(inventoryPath, original);
  }
});

test("loads a private hash-checked snapshot, not a mutable bundle archive", async () => {
  const inventoryPath = join(root, "install-inventory.json");
  const original = await readFile(inventoryPath);
  const archive = join(root, "node.tar");
  const bytes = Buffer.from("verified-image-bytes\n");
  const imageId = `sha256:${"c".repeat(64)}`;
  try {
    await writeFile(archive, bytes);
    const inventory = JSON.parse(original);
    inventory.images[0].archiveSha256 = createHash("sha256").update(bytes).digest("hex");
    await writeFile(inventoryPath, JSON.stringify(inventory));
    let loadedPath;
    await loadStandaloneInstallImages(root, {
      verify: verifiedInventory, imageId: () => imageId,
      docker: (args) => {
        if (args[0] === "image" && args[2].startsWith("tr-standalone/")) {
          throw { status: 1, stderr: "No such image" };
        }
        if (args[0] === "image") return imageId;
        if (args[0] === "load") {
          loadedPath = args[2];
          assert.notEqual(loadedPath, archive);
          assert.deepEqual(readFileSync(loadedPath), bytes);
          return `Loaded image ID: ${imageId}`;
        }
        return "";
      },
    });
    assert.equal(loadedPath?.endsWith("/node.tar"), true);
    await assert.rejects(readFile(loadedPath), { code: "ENOENT" });
    let loaded = false;
    await assert.rejects(loadStandaloneInstallImages(root, {
      verify: async () => {
        await writeFile(archive, "substituted image\n");
        return verifiedInventory();
      },
      imageId: () => imageId,
      docker: (args) => { if (args[0] === "load") loaded = true; return imageId; },
    }), /changed after bundle verification/u);
    assert.equal(loaded, false);
  } finally {
    await rm(archive, { force: true });
    await writeFile(inventoryPath, original);
  }
});

test("rejects inventory replacement between verification and loading", async () => {
  const inventoryPath = join(root, "install-inventory.json");
  const original = await readFile(inventoryPath);
  let loaded = false;
  try {
    await assert.rejects(loadStandaloneInstallImages(root, {
      verify: async () => {
        const checked = await verifiedInventory();
        await writeFile(inventoryPath, JSON.stringify({ sourceRevision: revision, images: [] }));
        return checked;
      },
      docker: (args) => { if (args[0] === "load") loaded = true; return ""; },
    }), /inventory changed after bundle verification/u);
    assert.equal(loaded, false);
  } finally {
    await writeFile(inventoryPath, original);
  }
});
