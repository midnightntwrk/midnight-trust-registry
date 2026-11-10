import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { checkStandaloneStaticAssets } from "./check-standalone-static-assets.mjs";
import { verifyPortalTar } from "./verify-portal-tar.mjs";

const sha = (value) => createHash("sha256").update(value).digest("hex");
const sourceRevision = "a".repeat(40);

function tar(entries) {
  const blocks = [];
  for (const entry of entries) {
    const contents = Buffer.from(entry.contents ?? "");
    const header = Buffer.alloc(512);
    Buffer.from(entry.path).copy(header, 0);
    Buffer.from("0000444\0").copy(header, 100);
    Buffer.from("0000000\0").copy(header, 108);
    Buffer.from("0000000\0").copy(header, 116);
    Buffer.from(`${contents.length.toString(8).padStart(11, "0")}\0`).copy(header, 124);
    Buffer.from("00000000000\0").copy(header, 136);
    header.fill(32, 148, 156);
    header[156] = entry.type ?? (entry.path.endsWith("/") ? 53 : 48);
    Buffer.from("ustar\0").copy(header, 257);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    Buffer.from(`${checksum.toString(8).padStart(6, "0")}\0 `).copy(header, 148);
    blocks.push(header, contents, Buffer.alloc((512 - contents.length % 512) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return Buffer.concat(blocks);
}

test("tar readback rejects changed, extra, linked, and case-colliding image entries", () => {
  const assets = [{ path: "index.html", size: 2, sha256: sha("ok") }];
  const good = [{ path: "public/" }, { path: "public/index.html", contents: "ok" }];
  assert.equal(verifyPortalTar(tar(good), "public", assets), 1);
  for (const entries of [
    [{ path: "public/" }, { path: "public/index.html", contents: "no" }],
    [...good, { path: "public/extra.js", contents: "x" }],
    [...good, { path: "public/INDEX.HTML", contents: "x" }],
    [...good, { path: "public/empty/" }],
    [{ path: "public/" }, { path: "public/index.html", type: 50 }],
  ]) {
    assert.throws(() => verifyPortalTar(tar(entries), "public", assets));
  }
});

test("v5 readback binds loaded API and portal image tar streams without starting containers", async () => {
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
      verifiedPortals[role] = { imageId: `sha256:${digit.repeat(64)}`,
        configId: `sha256:${role === "admin" ? "c".repeat(64) : "d".repeat(64)}` };
    }
    const apiManifest = Buffer.from(JSON.stringify({ format: "tr-api-runtime-image-v1" }));
    await writeFile(join(root, "api.json"), apiManifest);
    const apiRuntime = { manifest: "api.json", manifestSha256: sha(apiManifest) };
    const verifiedApi = { imageId: `sha256:${"e".repeat(64)}`,
      configId: `sha256:${"f".repeat(64)}` };
    const inventory = Buffer.from(JSON.stringify({ portalRuntimes, apiRuntime }));
    await writeFile(join(root, "install-inventory.json"), inventory);
    const verify = async () => ({ sourceRevision, inventorySha256: sha(inventory),
      portalRuntimes: verifiedPortals, apiRuntime: verifiedApi });
    const removed = [];
    let created = 0;
    const docker = (args) => {
      if (args[0] === "image") {
        if (args.at(-1) === verifiedPortals.admin.imageId) throw new Error("classic store");
        return args.at(-1);
      }
      if (args[0] === "create") {
        created += 1;
        assert.equal(args[1], "--name");
        assert.deepEqual(args.slice(3, 9), ["--network", "none", "--pull", "never",
          "--read-only", "--entrypoint"]);
        assert.equal(args.at(-1), [verifiedPortals.admin.configId,
          verifiedPortals.applicant.imageId, verifiedApi.imageId][created - 1]);
        return created.toString(16).padStart(64, "0");
      }
      if (args[0] === "rm") {
        assert.deepEqual(args.slice(1, 3), ["--force", "--volumes"]);
        removed.push(args.at(-1));
        return "";
      }
      throw new Error(`Unexpected Docker command: ${args.join(" ")}`);
    };
    const dockerBytes = (args) => args[1].endsWith(":/app/portals")
      ? tar([{ path: "portals/" }, { path: "portals/admin/" },
        { path: "portals/admin/index.html", contents: "ok" },
        { path: "portals/applicant/" }, { path: "portals/applicant/index.html", contents: "ok" }])
      : tar([{ path: "public/" }, { path: "public/index.html", contents: "ok" }]);
    const result = await checkStandaloneStaticAssets(root, { verify, docker, dockerBytes });
    assert.equal(result.readback.admin.assetCount, 1);
    assert.equal(result.readback.admin.loadedId, verifiedPortals.admin.configId);
    assert.equal(result.apiPortalReadback.applicant.assetCount, 1);
    assert.equal(result.apiPortalReadback.loadedId, verifiedApi.imageId);
    assert.equal(result.offlineJourneyQualified, false);
    assert.equal(result.runtimeStarted, false);
    assert.equal(created, 3);
    assert.equal(removed.length, 3);

    const apiRemoved = [];
    await assert.rejects(checkStandaloneStaticAssets(root, {
      verify,
      docker: (args) => {
        if (args[0] === "image") return args.at(-1);
        if (args[0] === "create") return "3".repeat(64);
        if (args[0] === "rm") { apiRemoved.push(args.at(-1)); return ""; }
        throw new Error(`Unexpected Docker command: ${args.join(" ")}`);
      },
      dockerBytes: (args) => args[1].endsWith(":/app/portals")
        ? tar([{ path: "portals/" }, { path: "portals/admin/" },
          { path: "portals/admin/index.html", contents: "ok" },
          { path: "portals/applicant/" }, { path: "portals/applicant/index.html", contents: "no" }])
        : dockerBytes(args),
    }), /disagree/u);
    assert.equal(apiRemoved.length, 3);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
