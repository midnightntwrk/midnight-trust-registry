import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, link, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { pathToFileURL } from "node:url";

import { assertApprovedProviderTree, assertImmutableProviderTree } from "./immutable-provider-tree.mjs";

async function fixture(run) {
  const boundary = await realpath(await mkdtemp(join(tmpdir(), "tr-provider-tree-")));
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

test("allows internal relative links but rejects escapes and hard links", () => fixture(async ({ boundary, root, check }) => {
  await chmod(root, 0o755);
  await symlink("entry.mjs", join(root, "alias.mjs"));
  await symlink("node_modules", join(root, "package-link"));
  await chmod(root, 0o555);
  assert.equal(check().links, 2);
  await chmod(root, 0o755);
  await rm(join(root, "alias.mjs"));
  await rm(join(root, "package-link"));
  await writeFile(join(boundary, "outside.mjs"), "export default 1;\n");
  await symlink("../outside.mjs", join(root, "alias.mjs"));
  await chmod(root, 0o555);
  assert.throws(check, /link escapes the approved code tree/u);
  await chmod(root, 0o755);
  await rm(join(root, "alias.mjs"));
  await link(join(root, "entry.mjs"), join(root, "alias.mjs"));
  await chmod(root, 0o555);
  assert.throws(check, /hard-linked entry/u);
}));

test("internal links cannot hide writable file or directory targets", () => fixture(async ({ root, nested, check }) => {
  await chmod(root, 0o755);
  await symlink("entry.mjs", join(root, "file-link"));
  await symlink("node_modules", join(root, "directory-link"));
  await chmod(root, 0o555);
  assert.equal(check().links, 2);

  await chmod(join(root, "entry.mjs"), 0o664);
  assert.throws(check, /mutable or linked entry/u);
  await chmod(join(root, "entry.mjs"), 0o444);
  await chmod(nested, 0o775);
  assert.throws(check, /mutable or linked entry/u);
}));

test("rejects a provider root selected through a linked ancestor", () => fixture(async ({ boundary, root }) => {
  const alias = join(boundary, "alias");
  await symlink(root, alias);
  assert.throws(() => assertImmutableProviderTree(alias, {
    boundary, trustedUid: process.getuid(),
  }), /trusted directory/u);
}));

test("preloaded hooks confine ESM, CommonJS, and dynamic imports to the code tree", async () => {
  const boundary = await realpath(await mkdtemp(join(tmpdir(), "tr-provider-hooks-")));
  const root = join(boundary, "provider");
  await mkdir(root);
  const helper = new URL("./immutable-provider-tree.mjs", import.meta.url).href;
  const bootstrap = `import assert from "node:assert/strict";
import { assertApprovedProviderImportBoundary, registerApprovedProviderImportBoundary } from ${JSON.stringify(helper)};
import { pathToFileURL } from "node:url";
const [root, entry] = process.argv.slice(1);
assert.throws(() => assertApprovedProviderImportBoundary(root), /requires the approved import preloader/);
registerApprovedProviderImportBoundary(root);
assert.doesNotThrow(() => assertApprovedProviderImportBoundary(root));
await import(pathToFileURL(entry).href);`;
  const run = (entry) => spawnSync(process.execPath,
    ["--input-type=module", "-e", bootstrap, root, entry], { encoding: "utf8" });
  try {
    await writeFile(join(root, "inside.mjs"), "export const value = 'inside';\n");
    await writeFile(join(root, "entry.mjs"),
      "import { value } from './inside.mjs'; console.log(value);\n");
    const valid = run(join(root, "entry.mjs"));
    assert.equal(valid.status, 0, valid.stderr);
    assert.match(valid.stdout, /inside/u);

    await writeFile(join(boundary, "outside.mjs"), "export const value = 'outside';\n");
    await writeFile(join(root, "entry.mjs"),
      "await import('../outside.mjs');\n");
    const dynamic = run(join(root, "entry.mjs"));
    assert.notEqual(dynamic.status, 0);
    assert.match(dynamic.stderr, /outside the approved code tree/u);

    await writeFile(join(boundary, "outside.cjs"), "module.exports = 'outside';\n");
    await writeFile(join(root, "entry.cjs"),
      "require('../outside.cjs');\n");
    const commonJs = run(join(root, "entry.cjs"));
    assert.notEqual(commonJs.status, 0);
    assert.match(commonJs.stderr, /outside the approved code tree/u);

    await writeFile(join(root, "entry.mjs"),
      "import { createRequire } from 'node:module'; createRequire(import.meta.url)('../outside.cjs');\n");
    const createdRequire = run(join(root, "entry.mjs"));
    assert.notEqual(createdRequire.status, 0);
    assert.match(createdRequire.stderr, /outside the approved code tree/u);

    await writeFile(join(root, "entry.mjs"),
      `import Module from 'node:module'; Module._load(${JSON.stringify(join(boundary, "outside.cjs"))}, undefined, false);\n`);
    const lowLevelRequire = run(join(root, "entry.mjs"));
    assert.notEqual(lowLevelRequire.status, 0);
    assert.match(lowLevelRequire.stderr, /outside the approved code tree/u);

    await writeFile(join(root, "entry.mjs"),
      "await import('data:text/javascript,export default 1');\n");
    const dataUrl = run(join(root, "entry.mjs"));
    assert.notEqual(dataUrl.status, 0);
    assert.match(dataUrl.stderr, /outside the approved code tree/u);
  } finally {
    await rm(boundary, { recursive: true, force: true });
  }
});
