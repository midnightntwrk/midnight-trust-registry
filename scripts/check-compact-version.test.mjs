import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
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
      '"globalDependencies": [".compact-version"],',
      '"globalDependencies": [],',
    ));
    assert.throws(() => checkCompactVersion(fixture), /Turbo must invalidate/);

    writeFileSync(turboPath, readFileSync(join(sourceRoot, "turbo.json")));
    writeFileSync(join(fixture, ".compact-version"), `${pinnedVersion}\r\n`);
    assert.throws(() => checkCompactVersion(fixture), /one stable semver/);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
