import assert from "node:assert/strict";
import test from "node:test";

import { providerStagePackageEntries } from "./provider-stage-package-policy.mjs";

const first = { workspace: "packages/alpha", filename: "alpha-0.1.0.tgz", sha256: "a".repeat(64) };
const second = { workspace: "packages/beta", filename: "beta-0.1.0.tgz", sha256: "b".repeat(64) };
const workspaces = [first.workspace, second.workspace];

test("selects one regular archive per expected workspace", () => {
  assert.deepEqual(providerStagePackageEntries({ packages: [second, first] }, workspaces), [second, first]);
});

for (const [name, manifest, expected = workspaces] of [
  ["missing catalog", {}, workspaces],
  ["primitive catalog", { packages: "archive" }, workspaces],
  ["missing package", { packages: [first] }, workspaces],
  ["duplicate workspace", { packages: [first, { ...second, workspace: first.workspace }] }, workspaces],
  ["duplicate filename", { packages: [first, { ...second, filename: first.filename }] }, workspaces],
  ["unexpected workspace", { packages: [first, { ...second, workspace: "packages/other" }] }, workspaces],
  ["duplicate expected workspace", { packages: [first, second] }, [first.workspace, first.workspace]],
  ["archive traversal", { packages: [first, { ...second, filename: "../beta.tgz" }] }, workspaces],
  ["archive slash", { packages: [first, { ...second, filename: "sub/beta.tgz" }] }, workspaces],
  ["digest uppercase", { packages: [first, { ...second, sha256: "B".repeat(64) }] }, workspaces],
  ["digest missing", { packages: [first, { workspace: second.workspace, filename: second.filename }] }, workspaces],
  ["null item", { packages: [first, null] }, workspaces],
]) {
  test(`rejects ${name} before provider staging`, () => {
    assert.throws(() => providerStagePackageEntries(manifest, expected),
      /incomplete or unsafe provider package catalog/u);
  });
}
