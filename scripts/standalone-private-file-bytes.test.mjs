import assert from "node:assert/strict";
import { chmod, link, mkdtemp, rm, symlink, truncate, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { regularBytes } from "./standalone-private-file-bytes.mjs";

test("private setup reads reject links, public modes, empty files, and oversized inputs", async () => {
  const root = await mkdtemp(join(tmpdir(), "tr-private-file-"));
  const privatePath = join(root, "approval.json");
  try {
    await writeFile(privatePath, '{"approved":false}', { mode: 0o600 });
    assert.equal((await regularBytes(privatePath, { privateFile: true })).toString(), '{"approved":false}');

    const symlinkPath = join(root, "linked-approval.json");
    await symlink(privatePath, symlinkPath);
    await assert.rejects(regularBytes(symlinkPath, { privateFile: true }));

    const hardlinkPath = join(root, "hardlinked-approval.json");
    await link(privatePath, hardlinkPath);
    await assert.rejects(regularBytes(privatePath, { privateFile: true }), /bounded regular file/u);
    await rm(hardlinkPath);

    await chmod(privatePath, 0o644);
    await assert.rejects(regularBytes(privatePath, { privateFile: true }), /bounded regular file/u);
    assert.equal((await regularBytes(privatePath)).toString(), '{"approved":false}');

    await writeFile(privatePath, "");
    await assert.rejects(regularBytes(privatePath), /bounded regular file/u);
    await truncate(privatePath, 16 * 1024 * 1024 + 1);
    await assert.rejects(regularBytes(privatePath), /bounded regular file/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
