import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { assertPublishedPackageIntegrity } from "./check-published-package-integrity.mjs";

const script = fileURLToPath(new URL("./check-published-package-integrity.mjs", import.meta.url));

test("an existing registry version must match the reviewed tarball bytes", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-published-integrity-"));
  try {
    const tarball = join(root, "reviewed.tgz");
    const bytes = Buffer.from("reviewed release tarball\n");
    await writeFile(tarball, bytes);
    const integrity = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
    await assertPublishedPackageIntegrity(tarball, { integrity });
    const cli = spawnSync(process.execPath, [script, tarball, JSON.stringify({ integrity })],
      { encoding: "utf8" });
    assert.equal(cli.status, 0, cli.stderr);
    await writeFile(tarball, "substituted release tarball\n");
    await assert.rejects(assertPublishedPackageIntegrity(tarball, { integrity }), /differs/u);
    const changed = spawnSync(process.execPath, [script, tarball, JSON.stringify({ integrity })],
      { encoding: "utf8" });
    assert.equal(changed.status, 1);
    assert.match(changed.stderr, /differs/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("missing, weak, multiple, and noncanonical registry integrity values fail closed", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-published-integrity-"));
  try {
    const tarball = join(root, "reviewed.tgz");
    await writeFile(tarball, "reviewed\n");
    for (const dist of [null, {}, { integrity: "sha1-deadbeef" },
      { integrity: "sha512-not-base64!" }, { integrity: "sha512-AA== sha512-AA==" },
      { integrity: "sha512-AA==" }]) {
      await assert.rejects(assertPublishedPackageIntegrity(tarball, dist),
        /integrity|SHA-512/u);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
