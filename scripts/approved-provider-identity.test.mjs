import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rename, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";

import { loadRecheckedApprovedProvider, readApprovedProviderIdentity } from "./approved-provider-identity.mjs";

const root = await mkdtemp(join(tmpdir(), "tr-approved-provider-"));
after(() => rm(root, { recursive: true, force: true }));
const source = "export const marker = 'approved';\n";
const digest = createHash("sha256").update(source).digest("hex");

test("loads a stable approved entry module", async () => {
  const path = join(root, "stable.mjs");
  await writeFile(path, source);
  const initial = await readApprovedProviderIdentity(path, digest);
  const module = await loadRecheckedApprovedProvider(path, digest, initial);
  assert.equal(module.marker, "approved");
});

test("rejects same-byte path replacement before calling the import hook", async () => {
  const path = join(root, "swapped.mjs");
  const replacement = join(root, "replacement.mjs");
  await writeFile(path, source);
  await writeFile(replacement, source);
  const initial = await readApprovedProviderIdentity(path, digest);
  await rename(replacement, path);
  let loaded = false;
  await assert.rejects(loadRecheckedApprovedProvider(path, digest, initial, async () => {
    loaded = true;
  }), /path or inode changed/u);
  assert.equal(loaded, false);
});

test("rejects byte mutation and a symlink swap before import", async () => {
  const path = join(root, "changed.mjs");
  const target = join(root, "target.mjs");
  await writeFile(path, source);
  const initial = await readApprovedProviderIdentity(path, digest);
  await writeFile(path, "export const marker = 'changed';\n");
  await assert.rejects(loadRecheckedApprovedProvider(path, digest, initial), /bytes disagree/u);
  await rm(path);
  await writeFile(target, source);
  await symlink(target, path);
  await assert.rejects(loadRecheckedApprovedProvider(path, digest, initial));
});
