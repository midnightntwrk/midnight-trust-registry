import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { linkSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const workflow = readFileSync(join(root, ".github/workflows/publish.yml"), "utf8");
const smokeWorkflow = readFileSync(join(root, ".github/workflows/release-smoke.yml"), "utf8");
const publisher = readFileSync(join(root, "scripts/publish-npm-packages.sh"), "utf8");
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
    "select-publish-version.mjs --github-output",
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
  assert.match(publisher, /node scripts\/check-publish-tarball\.mjs "\$\{manifest_path\}" "\$\{tarball\}"/u);
  assert.match(publisher, /npm view "\$\{package_name\}@\$\{version\}" dist --json/u);
  assert.match(publisher, /node scripts\/check-published-package-integrity\.mjs "\$\{tarball\}" "\$\{published_dist\}"/u);
});

test("release bytes are prepared before the protected publish approval", () => {
  const parsed = yaml.load(workflow);
  const prepare = parsed.jobs.prepare;
  const publish = parsed.jobs.publish;
  assert.equal(prepare.environment, undefined);
  assert.equal(publish.needs, "prepare");
  assert.equal(publish.environment.name, "npm-publish");
  assert.match(prepare.outputs.manifest_sha256, /steps\.manifest\.outputs\.sha256/u);
  const preparedSteps = prepare.steps.map((step) => step.name);
  assert.ok(preparedSteps.indexOf("Record manifest digest for release review")
    < preparedSteps.indexOf("Upload release tarballs"));
  const publishSteps = publish.steps.map((step) => step.name);
  const required = [
    "Download reviewed release tarballs",
    "Match reviewed manifest digest",
    "Verify manifest and exact release tarballs after approval",
    "Smoke test downloaded release tarballs",
    "Publish packages to npm",
  ];
  let previous = -1;
  for (const name of required) {
    const position = publishSteps.indexOf(name);
    assert.ok(position > previous, `Protected publish step is missing or out of order: ${name}`);
    previous = position;
  }
  assert.match(publish.steps.find((step) => step.name === "Match reviewed manifest digest").run,
    /check-reviewed-manifest-digest\.mjs artifacts\/npm-release\.manifest\.json/u);
  assert.match(publish.steps.find((step) => step.name === "Verify manifest and exact release tarballs after approval").run,
    /--verify artifacts\/npm-release\.manifest\.json/u);
  assert.match(publish.steps.find((step) => step.name === "Rebuild full Compact artifacts for source verification").run,
    /pnpm run build/u);
});

test("protected publish rejects a changed reviewed manifest digest", () => {
  const parsed = yaml.load(workflow);
  const check = parsed.jobs.publish.steps.find((step) => step.name === "Match reviewed manifest digest");
  assert.match(check.run, /check-reviewed-manifest-digest\.mjs/u);
  const directory = mkdtempSync(join(tmpdir(), "tr-reviewed-manifest-"));
  try {
    mkdirSync(join(directory, "artifacts"));
    const manifest = join(directory, "artifacts/npm-release.manifest.json");
    const original = Buffer.from('{"format":"tr-release-candidate-manifest-v2"}\n');
    writeFileSync(manifest, original);
    const digest = createHash("sha256").update(original).digest("hex");
    const verify = (expected) => spawnSync(process.execPath,
      [join(root, "scripts/check-reviewed-manifest-digest.mjs"), manifest, expected],
      { cwd: directory, encoding: "utf8" });
    assert.equal(verify(digest).status, 0);
    writeFileSync(manifest, Buffer.from(original.toString().replace("v2", "v3")));
    assert.notEqual(verify(digest).status, 0, "same-length manifest mutation must fail");
    assert.notEqual(verify("not-a-digest").status, 0, "malformed job output must fail");
    writeFileSync(manifest, original);
    const linked = join(directory, "artifacts/linked-manifest.json");
    symlinkSync(manifest, linked);
    assert.notEqual(spawnSync(process.execPath,
      [join(root, "scripts/check-reviewed-manifest-digest.mjs"), linked, digest],
      { encoding: "utf8" }).status, 0, "symlinked manifest must fail");
    rmSync(linked);
    linkSync(manifest, linked);
    assert.notEqual(verify(digest).status, 0, "hard-linked manifest must fail");
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("manual package workflows cannot redirect credentials or select uncommitted release bytes", () => {
  for (const source of [workflow, smokeWorkflow]) {
    assert.match(source, /workflow_dispatch: \{\}/u);
    assert.doesNotMatch(source, /\binputs\.|github\.event\.inputs|registry:\s*\$\{\{/u);
    assert.match(source, /select-publish-version\.mjs --github-output/u);
    assert.match(source, /REGISTRY: https:\/\/registry\.npmjs\.org/u);
  }
  assert.match(workflow, /NPM_TAG: next/u);
  assert.match(workflow, /registry-url: https:\/\/registry\.npmjs\.org/u);
});
