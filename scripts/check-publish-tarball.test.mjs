import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { checkPublishTarball } from "./check-publish-tarball.mjs";

const script = fileURLToPath(new URL("./check-publish-tarball.mjs", import.meta.url));

test("publish gate checks one manifest-pinned tarball and rejects tampering", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-publish-tarball-"));
  try {
    const manifestPath = join(root, "manifest.json");
    const tarballPath = join(root, "midnight-ntwrk-trust-registry-api-0.1.0.tgz");
    const bytes = Buffer.from("tested release bytes");
    const entry = { name: "@midnight-ntwrk/trust-registry-api", version: "0.1.0",
      filename: "midnight-ntwrk-trust-registry-api-0.1.0.tgz",
      sizeBytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
    await writeFile(tarballPath, bytes);
    await writeFile(manifestPath, JSON.stringify({ format: "tr-release-candidate-manifest-v2",
      packages: [entry] }));
    await checkPublishTarball(manifestPath, tarballPath, entry.name, entry.version);
    const valid = spawnSync(process.execPath,
      [script, manifestPath, tarballPath, entry.name, entry.version], { encoding: "utf8" });
    assert.equal(valid.status, 0, valid.stderr);

    await writeFile(tarballPath, Buffer.from("retested release bytes"));
    await assert.rejects(checkPublishTarball(manifestPath, tarballPath, entry.name, entry.version),
      /differs in size/u);
    await writeFile(tarballPath, Buffer.from("Xested release bytes"));
    await assert.rejects(checkPublishTarball(manifestPath, tarballPath, entry.name, entry.version),
      /bytes differ/u);
    const tampered = spawnSync(process.execPath,
      [script, manifestPath, tarballPath, entry.name, entry.version], { encoding: "utf8" });
    assert.equal(tampered.status, 1);
    assert.match(tampered.stderr, /bytes differ/u);
    await writeFile(manifestPath, JSON.stringify({ format: "tr-release-candidate-manifest-v2",
      packages: [entry, entry] }));
    await assert.rejects(checkPublishTarball(manifestPath, tarballPath, entry.name, entry.version),
      /not uniquely pinned/u);
    await writeFile(manifestPath, JSON.stringify({ format: "tr-release-candidate-manifest-v2",
      packages: [entry] }));
    await rm(tarballPath);
    await writeFile(join(root, "target.tgz"), bytes);
    await symlink(join(root, "target.tgz"), tarballPath);
    await assert.rejects(checkPublishTarball(manifestPath, tarballPath, entry.name, entry.version));
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
