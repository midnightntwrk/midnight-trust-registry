import assert from "node:assert/strict";
import { chmod, link, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { assertApprovedProviderTree, assertImmutableProviderTree } from "./immutable-provider-tree.mjs";

async function fixture(run) {
  const boundary = await mkdtemp(join(tmpdir(), "tr-provider-tree-"));
  const root = join(boundary, "provider");
  const nested = join(root, "node_modules");
  await mkdir(nested, { recursive: true });
  await writeFile(join(root, "entry.mjs"), "export const approved = true;\n");
  await writeFile(join(nested, "dependency.cjs"), "module.exports = true;\n");
  await chmod(join(root, "entry.mjs"), 0o444);
  await chmod(join(nested, "dependency.cjs"), 0o444);
  await chmod(nested, 0o555);
  await chmod(root, 0o555);
  try {
    return await run({ boundary, root, nested,
      check: () => assertImmutableProviderTree(root, {
        boundary, trustedUid: process.getuid(),
      }) });
  } finally {
    await chmod(root, 0o755);
    await chmod(nested, 0o755);
    await rm(boundary, { recursive: true, force: true });
  }
}

test("accepts a bounded owner-pinned read-only tree", () => fixture(({ check }) => {
  assert.deepEqual({ files: check().files, directories: check().directories },
    { files: 2, directories: 2 });
}));

test("allows ordinary trusted-owner write bits but not group or other writes", () => fixture(async ({ root, nested, check }) => {
  await chmod(root, 0o755);
  await chmod(nested, 0o755);
  await chmod(join(root, "entry.mjs"), 0o644);
  await chmod(join(nested, "dependency.cjs"), 0o644);
  assert.equal(check().files, 2);
}));

test("real provider gate requires a configured root containing the approved entry", () => fixture(({ root, boundary }) => {
  const entry = join(root, "entry.mjs");
  assert.throws(() => assertApprovedProviderTree(entry, undefined), /requires an absolute/u);
  assert.throws(() => assertApprovedProviderTree(join(boundary, "other.mjs"), root),
    /outside the immutable code root/u);
  assert.equal(assertApprovedProviderTree(entry, root, {
    boundary, trustedUid: process.getuid(),
  }).files, 2);
}));

test("rejects a writable code root, dependency and ancestor", () => fixture(async ({ root, nested, boundary, check }) => {
  await chmod(root, 0o775);
  assert.throws(check, /trusted directory/u);
  await chmod(root, 0o555);
  await chmod(nested, 0o775);
  assert.throws(check, /mutable or linked entry/u);
  await chmod(nested, 0o555);
  await chmod(join(nested, "dependency.cjs"), 0o664);
  assert.throws(check, /mutable or linked entry/u);
  await chmod(join(nested, "dependency.cjs"), 0o444);
  await chmod(boundary, 0o777);
  assert.throws(check, /trusted directory/u);
  await chmod(boundary, 0o700);
}));

test("rejects symlinks, hard links and non-regular entries", () => fixture(async ({ root, check }) => {
  await chmod(root, 0o755);
  await symlink(join(root, "entry.mjs"), join(root, "alias.mjs"));
  await chmod(root, 0o555);
  assert.throws(check, /mutable or linked entry/u);
  await chmod(root, 0o755);
  await rm(join(root, "alias.mjs"));
  await link(join(root, "entry.mjs"), join(root, "alias.mjs"));
  await chmod(root, 0o555);
  assert.throws(check, /hard-linked entry/u);
}));

test("rejects a provider root selected through a linked ancestor", () => fixture(async ({ boundary, root }) => {
  const alias = join(boundary, "alias");
  await symlink(root, alias);
  assert.throws(() => assertImmutableProviderTree(alias, {
    boundary, trustedUid: process.getuid(),
  }), /trusted directory/u);
}));
