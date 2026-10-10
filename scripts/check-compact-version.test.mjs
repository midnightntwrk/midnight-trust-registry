import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { checkCompactVersion } from "./check-compact-version.mjs";

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pinnedVersion = readFileSync(join(sourceRoot, ".compact-version"), "utf8").trim();
const compactWorkflows = readdirSync(join(sourceRoot, ".github/workflows"))
  .filter((file) => /\.ya?ml$/u.test(file))
  .map((file) => `.github/workflows/${file}`)
  .filter((path) => readFileSync(join(sourceRoot, path), "utf8").includes("setup-compact-action@"));
const paths = [
  ".compact-version",
  ...compactWorkflows,
  "nix/packages/compact-toolchain.nix",
  "turbo.json",
];

test("all Compact consumers use the shared version", () => {
  assert.equal(checkCompactVersion(), pinnedVersion);
});

test("cached Compact setup authenticates its release query in every workflow", () => {
  for (const path of compactWorkflows) {
    const workflow = yaml.load(readFileSync(join(sourceRoot, path), "utf8"));
    const jobs = Object.values(workflow.jobs);
    const compactJobs = jobs.filter((job) => job.steps?.some((step) =>
      step.uses?.startsWith("midnightntwrk/setup-compact-action@")));
    assert.equal(compactJobs.length, 1, `${path} must have one Compact job`);
    const setup = compactJobs[0].steps.find((step) =>
      step.uses?.startsWith("midnightntwrk/setup-compact-action@"));
    assert.equal(setup.env.GITHUB_TOKEN, "${{ github.token }}", path);
  }
});

test("a pinned cache hit bypasses network setup and only verified installs are saved", () => {
  const cacheKey = "tr-compact-v3-ubuntu24.04-setup836895c8-${{ runner.os }}-${{ runner.arch }}-${{ steps.compact-version.outputs.version }}";
  for (const path of compactWorkflows) {
    const workflow = yaml.load(readFileSync(join(sourceRoot, path), "utf8"));
    const jobs = Object.values(workflow.jobs);
    assert.equal(jobs.length, 1, `${path} must keep the cache on its pinned runner`);
    const job = jobs[0];
    const steps = job.steps;
    const restore = steps.find((step) => step.name === "Restore pinned Compact installation");
    const setup = steps.find((step) => step.uses?.startsWith("midnightntwrk/setup-compact-action@"));
    const addPath = steps.find((step) => step.name === "Add cached Compact to PATH");
    const verify = steps.find((step) => step.run === "node scripts/check-compact-version.mjs --check-installed");
    const verifyPaths = steps.find((step) => step.name === "Verify Compact cache paths");
    const save = steps.find((step) => step.name === "Save verified Compact installation");
    assert.ok(restore && setup && addPath && verify && verifyPaths && save, `${path} must have the full Compact cache flow`);
    assert.ok(steps.indexOf(restore) < steps.indexOf(setup), `${path} must restore before setup`);
    assert.ok(steps.indexOf(setup) < steps.indexOf(addPath), `${path} must set PATH after setup`);
    assert.ok(steps.indexOf(addPath) < steps.indexOf(verify), `${path} must verify the restored compiler`);
    assert.ok(steps.indexOf(verify) < steps.indexOf(verifyPaths), `${path} must verify before checking cache paths`);
    assert.ok(steps.indexOf(verifyPaths) < steps.indexOf(save), `${path} must check cache paths before save`);
    assert.equal(job["runs-on"], "ubuntu-24.04", `${path} must pin the runner generation`);
    assert.equal(restore.id, "compact-cache", path);
    assert.match(restore.uses, /^actions\/cache\/restore@/u, path);
    assert.match(restore.with.path, /~\/\.compact\//u, `${path} must cache the compiler directory`);
    assert.equal(restore.with["restore-keys"], undefined, `${path} must not restore another version`);
    assert.equal(setup.if, "steps.compact-cache.outputs.cache-hit != 'true'", path);
    assert.equal(setup.with["cache-enabled"], "false", path);
    assert.match(addPath.run, /\$HOME\/\.local\/bin/u, path);
    assert.match(verifyPaths.run, /test -x "\$HOME\/\.compact\/bin\/compactc"/u, path);
    assert.equal(save.if, "steps.compact-cache.outputs.cache-hit != 'true'", path);
    assert.match(save.uses, /^actions\/cache\/save@/u, path);
    assert.match(save.with.path, /~\/\.compact\//u, `${path} must save the compiler directory`);
    assert.equal(verify.env.TR_COMPACT_CACHE_HIT, "${{ steps.compact-cache.outputs.cache-hit }}", path);
    assert.equal(restore.with.key, cacheKey, `${path} restore must use the pinned version`);
    assert.equal(save.with.key, cacheKey, `${path} save must use the same pinned version`);
  }
});

test("CLI emits the pin when invoked through a symlink", () => {
  const fixture = mkdtempSync(join(tmpdir(), "tr-compact-cli-"));
  try {
    const link = join(fixture, "compact-version.mjs");
    const output = join(fixture, "github-output");
    symlinkSync(join(sourceRoot, "scripts/check-compact-version.mjs"), link);
    const result = spawnSync(process.execPath, [link, "--github-output"], {
      encoding: "utf8",
      env: { ...process.env, GITHUB_OUTPUT: output },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(output, "utf8"), `version=${pinnedVersion}\n`);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("installed check supports Nix and upstream COMPACT_DIRECTORY layouts", () => {
  const fixture = mkdtempSync(join(tmpdir(), "tr-compact-installed-"));
  try {
    const bin = join(fixture, "bin");
    mkdirSync(bin);
    const compact = join(bin, "compact");
    const compiler = join(bin, "compactc");
    writeFileSync(compact, `#!/bin/sh\necho ${pinnedVersion}\n`);
    chmodSync(compact, 0o755);
    writeFileSync(compiler, "#!/bin/sh\necho 0.0.0\n");
    chmodSync(compiler, 0o755);
    const env = {
      ...process.env,
      COMPACT_DIRECTORY: fixture,
      PATH: `${bin}${delimiter}${process.env.PATH ?? ""}`,
    };

    const mismatch = spawnSync(process.execPath, [
      join(sourceRoot, "scripts/check-compact-version.mjs"),
      "--check-installed",
    ], { encoding: "utf8", env });
    assert.notEqual(mismatch.status, 0);
    assert.match(mismatch.stderr, /compiler 0\.0\.0 does not match pin/);

    writeFileSync(compiler, `#!/bin/sh\necho ${pinnedVersion}\n`);
    const matching = spawnSync(process.execPath, [
      join(sourceRoot, "scripts/check-compact-version.mjs"),
      "--check-installed",
    ], { encoding: "utf8", env });
    assert.equal(matching.status, 0, matching.stderr);

    rmSync(compiler);
    const upstreamLayout = spawnSync(process.execPath, [
      join(sourceRoot, "scripts/check-compact-version.mjs"),
      "--check-installed",
    ], { encoding: "utf8", env });
    assert.equal(upstreamLayout.status, 0, upstreamLayout.stderr);

    writeFileSync(compact, "#!/bin/sh\necho 0.0.0\n");
    const hostMismatch = spawnSync(process.execPath, [
      join(sourceRoot, "scripts/check-compact-version.mjs"),
      "--check-installed",
    ], { encoding: "utf8", env });
    assert.notEqual(hostMismatch.status, 0);
    assert.match(hostMismatch.stderr, /Installed Compact 0\.0\.0 does not match pin/);

    const cachedMismatch = spawnSync(process.execPath, [
      join(sourceRoot, "scripts/check-compact-version.mjs"),
      "--check-installed",
    ], { encoding: "utf8", env: { ...env, TR_COMPACT_CACHE_HIT: "true" } });
    assert.notEqual(cachedMismatch.status, 0);
    assert.match(cachedMismatch.stderr, /Delete the tr-compact-v3 Actions cache/);
    assert.doesNotMatch(cachedMismatch.stdout, /Compact compiler pin:/);

    const invalidArgument = spawnSync(process.execPath, [
      join(sourceRoot, "scripts/check-compact-version.mjs"),
      "--unknown",
    ], { encoding: "utf8", env: { ...env, TR_COMPACT_CACHE_HIT: "true" } });
    assert.notEqual(invalidArgument.status, 0);
    assert.doesNotMatch(invalidArgument.stderr, /Delete the tr-compact-v3 Actions cache/);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});

test("workflow and Nix version drift fail validation", () => {
  const fixture = mkdtempSync(join(tmpdir(), "tr-compact-version-"));
  try {
    for (const path of paths) {
      const destination = join(fixture, path);
      mkdirSync(dirname(destination), { recursive: true });
      writeFileSync(destination, readFileSync(join(sourceRoot, path)));
    }
    assert.equal(checkCompactVersion(fixture), pinnedVersion);

    const workflowPath = join(fixture, ".github/workflows/milestone-light.yaml");
    const otherVersion = pinnedVersion === "0.0.0" ? "99.99.99" : "0.0.0";
    writeFileSync(workflowPath, readFileSync(workflowPath, "utf8").replace(
      "compact-version: ${{ steps.compact-version.outputs.version }}",
      `compact-version: ${otherVersion}`,
    ));
    assert.throws(() => checkCompactVersion(fixture), /milestone-light.yaml/);

    writeFileSync(workflowPath, readFileSync(join(sourceRoot, ".github/workflows/milestone-light.yaml")));
    const roguePath = join(fixture, ".github/workflows/new-compact.yaml");
    writeFileSync(roguePath, `steps:\n  - uses: midnightntwrk/setup-compact-action@abc\n    with:\n      compact-version: ${otherVersion}\n`);
    assert.throws(() => checkCompactVersion(fixture), /new-compact.yaml/);
    rmSync(roguePath);

    const qualityPath = join(fixture, ".github/workflows/quality.yaml");
    writeFileSync(qualityPath, readFileSync(qualityPath, "utf8").replace(
      "compact-${{ steps.compact-version.outputs.version }}-${{ hashFiles",
      "compact-unpinned-${{ hashFiles",
    ));
    assert.throws(() => checkCompactVersion(fixture), /Quality Turbo cache and restore keys/);
    writeFileSync(qualityPath, readFileSync(join(sourceRoot, ".github/workflows/quality.yaml")));

    writeFileSync(qualityPath, readFileSync(qualityPath, "utf8").replace(
      "restore-keys: |\n            tr-turbo-v1-${{ runner.os }}-compact-${{ steps.compact-version.outputs.version }}-",
      "restore-keys: |\n            tr-turbo-v1-${{ runner.os }}-",
    ));
    assert.throws(() => checkCompactVersion(fixture), /Quality Turbo cache and restore keys/);
    writeFileSync(qualityPath, readFileSync(join(sourceRoot, ".github/workflows/quality.yaml")));

    const nixPath = join(fixture, "nix/packages/compact-toolchain.nix");
    writeFileSync(nixPath, readFileSync(nixPath, "utf8").replace(
      "builtins.readFile ../../.compact-version",
      `"${otherVersion}"`,
    ));
    assert.throws(() => checkCompactVersion(fixture), /Nix Compact toolchain/);

    writeFileSync(nixPath, readFileSync(join(sourceRoot, "nix/packages/compact-toolchain.nix")));
    const turboPath = join(fixture, "turbo.json");
    writeFileSync(turboPath, readFileSync(turboPath, "utf8").replace(
      '"globalDependencies": [".compact-version", "scripts/compile-compact.mjs"],',
      '"globalDependencies": [],',
    ));
    assert.throws(() => checkCompactVersion(fixture), /Turbo must invalidate/);

    writeFileSync(turboPath, readFileSync(join(sourceRoot, "turbo.json"), "utf8").replace(
      '"scripts/compile-compact.mjs"',
      '"scripts/other-compiler.mjs"',
    ));
    assert.throws(() => checkCompactVersion(fixture), /Turbo must invalidate/);

    writeFileSync(turboPath, readFileSync(join(sourceRoot, "turbo.json")));
    writeFileSync(join(fixture, ".compact-version"), `${pinnedVersion}\r\n`);
    assert.throws(() => checkCompactVersion(fixture), /one stable semver/);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
