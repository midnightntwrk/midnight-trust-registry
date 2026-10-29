import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const workflow = readFileSync(join(root, ".github/workflows/publish.yml"), "utf8");
const version = JSON.parse(readFileSync(join(root, "package.json"), "utf8")).version;

function run(script, args) {
  return spawnSync("node", [join(root, "scripts", script), ...args], {
    cwd: root, encoding: "utf8",
  });
}

test("release version gate validates committed metadata without rewriting it", () => {
  const matching = run("release-set-version.mjs", ["--version", version, "--check"]);
  assert.equal(matching.status, 0, matching.stderr);
  const mismatched = run("release-set-version.mjs", ["--version", "999.0.0", "--check"]);
  assert.notEqual(mismatched.status, 0);
  assert.match(mismatched.stderr, /committed version differs/u);
});

test("local clean-consumer smoke refuses tarballs without a manifest", () => {
  const result = run("smoke-published-artifacts.mjs", ["--tarball-dir", "/nonexistent"]);
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /requires --tarball-dir and --manifest together/u);
});

test("publish workflow binds signed source, manifest verification and tested tarballs", () => {
  const required = [
    "release-set-version.mjs --version \"$VERSION\" --check",
    "--artifact-dir artifacts/npm-release",
    "--output artifacts/npm-release.manifest.json",
    "--verify artifacts/npm-release.manifest.json",
    "--manifest artifacts/npm-release.manifest.json",
    "Publish packages to npm",
  ];
  let previous = -1;
  for (const step of required) {
    const position = workflow.indexOf(step, previous + 1);
    assert.ok(position > previous, `Publish gate is missing or out of order: ${step}`);
    previous = position;
  }
  assert.doesNotMatch(workflow, /run: node scripts\/release-set-version\.mjs --version "\$VERSION"\s*$/mu);
  assert.match(workflow, /MANIFEST_PATH: artifacts\/npm-release\.manifest\.json/u);
});
