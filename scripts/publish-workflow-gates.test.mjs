import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
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
    /sha256sum --check --status/u);
  assert.match(publish.steps.find((step) => step.name === "Verify manifest and exact release tarballs after approval").run,
    /--verify artifacts\/npm-release\.manifest\.json/u);
  assert.match(publish.steps.find((step) => step.name === "Rebuild full Compact artifacts for source verification").run,
    /pnpm run build/u);
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
