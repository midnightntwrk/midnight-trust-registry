import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { checkStandaloneStaticAssets, verifyStaticAssetDirectory }
  from "./check-standalone-static-assets.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const sourceRevision = "a".repeat(40);

test("static asset readback rejects missing, changed, extra, and linked files", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-static-assets-test-"));
  try {
    const contents = "<html>approved</html>";
    const expected = [{ path: "index.html", size: Buffer.byteLength(contents), sha256: sha(contents) }];
    await writeFile(join(root, "index.html"), contents);
    assert.equal(await verifyStaticAssetDirectory(root, expected), 1);
    await writeFile(join(root, "index.html"), "<html>changed</html>");
    await assert.rejects(verifyStaticAssetDirectory(root, expected), /disagree/u);
    await writeFile(join(root, "index.html"), contents);
    await writeFile(join(root, "extra.js"), "alert(1)");
    await assert.rejects(verifyStaticAssetDirectory(root, expected), /disagree/u);
    await rm(join(root, "extra.js"));
    await symlink("index.html", join(root, "linked.html"));
    await assert.rejects(verifyStaticAssetDirectory(root, expected), /linked/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("v5 readback binds both loaded images to their verified asset lists without starting them", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-static-bundle-test-"));
  try {
    const assets = [{ path: "index.html", size: 2, sha256: sha("ok") }];
    const portalRuntimes = {};
    const verifiedPortals = {};
    for (const [role, digit] of [["admin", "a"], ["applicant", "b"]]) {
      const manifest = { assets, assetsSha256: sha(JSON.stringify(assets)) };
      const bytes = JSON.stringify(manifest);
      await writeFile(join(root, `${role}.json`), bytes);
      portalRuntimes[role] = { manifest: `${role}.json`, manifestSha256: sha(bytes) };
      verifiedPortals[role] = { imageId: `sha256:${digit.repeat(64)}` };
    }
    const inventory = Buffer.from(JSON.stringify({ portalRuntimes }));
    await writeFile(join(root, "install-inventory.json"), inventory);
    const containers = [];
    const result = await checkStandaloneStaticAssets(root, {
      verify: async () => ({ sourceRevision, inventorySha256: sha(inventory),
        portalRuntimes: verifiedPortals }),
      docker: (args) => {
        if (args[0] === "image") return args.at(-1);
        if (args[0] === "create") {
          const id = (containers.length + 1).toString(16).padStart(64, "0");
          containers.push(id);
          assert.deepEqual(args.slice(0, 7), ["create", "--network", "none", "--pull",
            "never", "--read-only", "--entrypoint"]);
          return id;
        }
        if (args[0] === "cp") {
          mkdirSync(args[2]);
          writeFileSync(join(args[2], "index.html"), "ok");
          return "";
        }
        if (args[0] === "rm") return "";
        throw new Error(`Unexpected Docker command: ${args.join(" ")}`);
      },
    });
    assert.equal(result.readback.admin.assetCount, 1);
    assert.equal(result.readback.applicant.assetCount, 1);
    assert.equal(result.offlineJourneyQualified, false);
    assert.equal(result.runtimeStarted, false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
