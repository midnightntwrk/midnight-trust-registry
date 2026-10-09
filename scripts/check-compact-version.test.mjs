import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import yaml from "js-yaml";
import { checkCompactVersion } from "./check-compact-version.mjs";

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pinnedVersion = readFileSync(join(sourceRoot, ".compact-version"), "utf8").trim();
const paths = [
  ".compact-version",
  ".github/workflows/ci.yaml",
  ".github/workflows/milestone-light.yaml",
  ".github/workflows/quality.yaml",
  ".github/workflows/publish.yml",
  "nix/packages/compact-toolchain.nix",
  "turbo.json",
];

test("all Compact consumers use the shared version", () => {
  assert.equal(checkCompactVersion(), pinnedVersion);
});

test("cached Compact setup authenticates its release query in every workflow", () => {
  for (const path of paths.filter((candidate) => candidate.startsWith(".github/workflows/"))) {
    const workflow = yaml.load(readFileSync(join(sourceRoot, path), "utf8"));
    const setups = Object.values(workflow.jobs).flatMap((job) => job.steps ?? [])
      .filter((step) => step.uses?.toLowerCase().startsWith("midnightntwrk/setup-compact-action@"));
    assert.ok(setups.length > 0, `${path} must use the pinned setup action`);
    for (const setup of setups) {
      assert.equal(setup.env?.GITHUB_TOKEN, "${{ github.token }}", path);
    }
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

test("pre-install pin command needs no workspace dependencies", () => {
  const fixture = mkdtempSync(join(tmpdir(), "tr-compact-preinstall-"));
  try {
    mkdirSync(join(fixture, "scripts"));
    writeFileSync(join(fixture, ".compact-version"), `${pinnedVersion}\n`);
    writeFileSync(join(fixture, "scripts/check-compact-version.mjs"),
      readFileSync(join(sourceRoot, "scripts/check-compact-version.mjs")));
    const output = join(fixture, "github-output");
    const result = spawnSync(process.execPath, [join(fixture, "scripts/check-compact-version.mjs"), "--github-output"], {
      encoding: "utf8",
      cwd: fixture,
      env: { ...process.env, GITHUB_OUTPUT: output },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(readFileSync(output, "utf8"), `version=${pinnedVersion}\n`);

    const bin = join(fixture, "bin");
    mkdirSync(bin);
    const compact = join(bin, "compact");
    writeFileSync(compact, `#!/bin/sh\necho ${pinnedVersion}\n`);
    chmodSync(compact, 0o755);
    const installed = spawnSync(process.execPath, [join(fixture, "scripts/check-compact-version.mjs"), "--check-installed"], {
      encoding: "utf8",
      cwd: fixture,
      env: { ...process.env, COMPACT_DIRECTORY: "", PATH: `${bin}${delimiter}${process.env.PATH ?? ""}` },
    });
    assert.equal(installed.status, 0, installed.stderr);
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
    const originalWorkflow = readFileSync(workflowPath, "utf8");
    writeFileSync(workflowPath, originalWorkflow
      .replace("compact-version: ${{ steps.compact-version.outputs.version }}", "compact-version: '${{ steps.compact-version.outputs.version }}'")
      .replace("run: node scripts/check-compact-version.mjs --check-installed", 'run: "node scripts/check-compact-version.mjs --check-installed"'));
    assert.equal(checkCompactVersion(fixture), pinnedVersion);
    writeFileSync(workflowPath, originalWorkflow);

    writeFileSync(workflowPath, originalWorkflow.replace(
      "midnightntwrk/setup-compact-action@", "MidnightNtwRK/SETUP-COMPACT-ACTION@",
    ));
    assert.equal(checkCompactVersion(fixture), pinnedVersion);
    writeFileSync(workflowPath, originalWorkflow);

    const unrelatedPath = join(fixture, ".github/workflows/metadata.yaml");
    writeFileSync(unrelatedPath, "# setup-compact-action@ is only a comment\nname: unrelated\n");
    assert.equal(checkCompactVersion(fixture), pinnedVersion);
    rmSync(unrelatedPath);

    const otherVersion = pinnedVersion === "0.0.0" ? "99.99.99" : "0.0.0";
    writeFileSync(workflowPath, readFileSync(workflowPath, "utf8").replace(
      "compact-version: ${{ steps.compact-version.outputs.version }}",
      `compact-version: ${otherVersion}`,
    ));
    assert.throws(() => checkCompactVersion(fixture), /milestone-light.yaml/);

    writeFileSync(workflowPath, readFileSync(join(sourceRoot, ".github/workflows/milestone-light.yaml")));
    const roguePath = join(fixture, ".github/workflows/new-compact.yaml");
    writeFileSync(roguePath, `jobs:\n  bad:\n    steps:\n      - uses: midnightntwrk/setup-compact-action@abc\n        with:\n          compact-version: ${otherVersion}\n`);
    assert.throws(() => checkCompactVersion(fixture), /new-compact.yaml/);
    rmSync(roguePath);

    writeFileSync(workflowPath, originalWorkflow.replace(
      "compact-version: ${{ steps.compact-version.outputs.version }}",
      `compact-version: ${otherVersion}`,
    ));
    assert.throws(() => checkCompactVersion(fixture), /milestone-light.yaml/);
    writeFileSync(workflowPath, originalWorkflow);

    writeFileSync(workflowPath, originalWorkflow.replace(
      "- run: ./run.sh --light",
      `- uses: example/other-compact-action@v1\n        with:\n          compact-version: ${otherVersion}\n      - run: ./run.sh --light`,
    ));
    assert.throws(() => checkCompactVersion(fixture), /milestone-light.yaml/);
    writeFileSync(workflowPath, originalWorkflow);

    writeFileSync(workflowPath, originalWorkflow.replace(
      "- run: node scripts/check-compact-version.mjs --check-installed",
      "- if: false\n        run: node scripts/check-compact-version.mjs --check-installed",
    ));
    assert.throws(() => checkCompactVersion(fixture), /milestone-light.yaml/);
    writeFileSync(workflowPath, originalWorkflow);

    writeFileSync(workflowPath, originalWorkflow.replace(
      "run: node scripts/check-compact-version.mjs --check-installed",
      "run: echo skipped-installed-check",
    ));
    assert.throws(() => checkCompactVersion(fixture), /milestone-light.yaml/);
    writeFileSync(workflowPath, originalWorkflow.replace(
      "GITHUB_TOKEN: ${{ github.token }}",
      "GITHUB_TOKEN: missing",
    ));
    assert.throws(() => checkCompactVersion(fixture), /milestone-light.yaml/);
    writeFileSync(workflowPath, originalWorkflow);

    const qualityPath = join(fixture, ".github/workflows/quality.yaml");
    writeFileSync(qualityPath, readFileSync(qualityPath, "utf8").replace(
      "compact-${{ steps.compact-version.outputs.version }}-${{ hashFiles",
      "compact-unpinned-${{ hashFiles",
    ));
    assert.throws(() => checkCompactVersion(fixture), /Quality Turbo cache and restore keys/);
    writeFileSync(qualityPath, readFileSync(join(sourceRoot, ".github/workflows/quality.yaml")));

    writeFileSync(qualityPath, readFileSync(qualityPath, "utf8").replace(
      "- name: Install dependencies",
      "- uses: actions/cache/restore@v4\n        with:\n          key: unrelated-cache\n          restore-keys: unrelated-\n      - name: Install dependencies",
    ));
    assert.equal(checkCompactVersion(fixture), pinnedVersion);
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
