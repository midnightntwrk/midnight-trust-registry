import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { checkInstalledIdentityRuntime } from "./check-installed-identity-runtime.mjs";

const scope = "@midnight-ntwrk";
const leaf = `${scope}/midnight-did-contract`;
const umbrella = `${scope}/midnight-did`;
const runtime = `${scope}/compact-runtime`;
const pin = "0.16.0";

function fixture() {
  const root = mkdtempSync(join(tmpdir(), "tr-installed-runtime-"));
  const put = (relative, data) => {
    const file = join(root, relative);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, typeof data === "string" ? data : JSON.stringify(data));
  };
  const rootManifest = { dependencies: { [leaf]: "0.7.0", [umbrella]: "0.7.0" } };
  const leafManifest = { name: leaf, version: "0.7.0", peerDependencies: { [runtime]: pin } };
  const umbrellaManifest = { name: umbrella, version: "0.7.0", dependencies: { [leaf]: "0.7.0" } };
  const overrides = { [leaf]: "0.7.0", [umbrella]: "0.7.0" };
  const save = () => {
    put("package.json", rootManifest);
    put("contracts/trust-registry/package.json", { dependencies: { [runtime]: pin } });
    put("pnpm-workspace.yaml", `overrides:\n${Object.entries(overrides)
      .map(([name, version]) => `  "${name}": ${version}`).join("\n")}\n`);
    put(`node_modules/${leaf}/package.json`, leafManifest);
    put(`node_modules/${leaf}/index.js`, "module.exports = {};\n");
    put(`node_modules/${leaf}/node_modules/${runtime}/package.json`, { name: runtime, version: pin });
    put(`node_modules/${leaf}/node_modules/${runtime}/index.js`, "module.exports = {};\n");
    put(`node_modules/${umbrella}/package.json`, umbrellaManifest);
  };
  save();
  return { root, save, put, rootManifest, leafManifest, umbrellaManifest, overrides };
}

function withFixture(run) {
  const state = fixture();
  try { run(state); } finally { rmSync(state.root, { recursive: true, force: true }); }
}

test("peer runtime and verified umbrella delegation pass", () => withFixture(({ root }) => {
  assert.deepEqual(checkInstalledIdentityRuntime(root), { runtimePin: pin, identityCount: 2, directRuntimeCount: 1 });
}));

test("peer dependency may delegate through a second umbrella", () => withFixture(({ root, save, put, rootManifest, umbrellaManifest, overrides }) => {
  const middle = `${scope}/midnight-did-domain`;
  rootManifest.dependencies[middle] = "0.7.0";
  overrides[middle] = "0.7.0";
  umbrellaManifest.dependencies = {};
  umbrellaManifest.peerDependencies = { [middle]: "0.7.0" };
  save();
  put(`node_modules/${middle}/package.json`, { name: middle, version: "0.7.0", dependencies: { [leaf]: "0.7.0" } });
  put(`node_modules/${middle}/index.js`, "module.exports = {};\n");
  assert.deepEqual(checkInstalledIdentityRuntime(root), { runtimePin: pin, identityCount: 3, directRuntimeCount: 1 });
}));

test("package export maps need not expose package.json", () => withFixture(({ root, save, leafManifest }) => {
  leafManifest.exports = { ".": "./index.js" };
  save();
  assert.equal(checkInstalledIdentityRuntime(root).identityCount, 2);
}));

test("semantic YAML override drift fails", () => withFixture(({ root, save, overrides }) => {
  overrides[leaf] = "0.7.1";
  save();
  assert.throws(() => checkInstalledIdentityRuntime(root), /override 0\.7\.1 does not match 0\.7\.0/);
}));

test("Compact runtime override drift fails", () => withFixture(({ root, put }) => {
  put("pnpm-workspace.yaml", `overrides:\n  "${leaf}": 0.7.0\n  "${umbrella}": 0.7.0\n  "${runtime}": 0.15.0\n`);
  assert.throws(() => checkInstalledIdentityRuntime(root), /Compact runtime override 0\.15\.0/);
}));

test("identity declaration drift fails", () => withFixture(({ root, save, leafManifest }) => {
  leafManifest.peerDependencies[runtime] = "0.15.0";
  save();
  assert.throws(() => checkInstalledIdentityRuntime(root), /declares Compact runtime/);
}));

test("resolved installed runtime drift fails", () => withFixture(({ root, put }) => {
  put(`node_modules/${leaf}/node_modules/${runtime}/package.json`, { name: runtime, version: "0.15.0" });
  assert.throws(() => checkInstalledIdentityRuntime(root), /resolves Compact runtime 0\.15\.0/);
}));

test("missing runtime without a verified delegate fails", () => withFixture(({ root, save, leafManifest }) => {
  delete leafManifest.peerDependencies;
  save();
  assert.throws(() => checkInstalledIdentityRuntime(root), /neither declares Compact runtime nor delegates/);
}));

test("dev-only runtime is not a production declaration", () => withFixture(({ root, save, leafManifest }) => {
  delete leafManifest.peerDependencies;
  leafManifest.devDependencies = { [runtime]: pin };
  save();
  assert.throws(() => checkInstalledIdentityRuntime(root), /neither declares Compact runtime nor delegates/);
}));

test("umbrella cannot hide a drifted hoisted runtime", () => withFixture(({ root, put }) => {
  put(`node_modules/${umbrella}/node_modules/${runtime}/package.json`, { name: runtime, version: "0.15.0" });
  put(`node_modules/${umbrella}/node_modules/${runtime}/index.js`, "module.exports = {};\n");
  assert.throws(() => checkInstalledIdentityRuntime(root), /resolves Compact runtime 0\.15\.0/);
}));

test("umbrella must resolve the verified delegate version", () => withFixture(({ root, put }) => {
  put(`node_modules/${umbrella}/node_modules/${leaf}/package.json`, { name: leaf, version: "0.6.0" });
  put(`node_modules/${umbrella}/node_modules/${leaf}/index.js`, "module.exports = {};\n");
  assert.throws(() => checkInstalledIdentityRuntime(root), /resolves .*@0\.6\.0, expected 0\.7\.0/);
}));

test("new root identity dependency is discovered and must be installed", () => withFixture(({ root, save, rootManifest, overrides }) => {
  rootManifest.dependencies[`${scope}/credential-compact`] = "0.2.0";
  overrides[`${scope}/credential-compact`] = "0.2.0";
  save();
  assert.throws(() => checkInstalledIdentityRuntime(root), /ENOENT/);
}));
