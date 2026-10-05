import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
];

test("all Compact consumers use the shared version", () => {
  assert.equal(checkCompactVersion(), pinnedVersion);
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
    const nixPath = join(fixture, "nix/packages/compact-toolchain.nix");
    writeFileSync(nixPath, readFileSync(nixPath, "utf8").replace(
      'version = lib.removeSuffix "\\n" (builtins.readFile ../../.compact-version);',
      `version = "${otherVersion}";`,
    ));
    assert.throws(() => checkCompactVersion(fixture), /Nix Compact toolchain/);
  } finally {
    rmSync(fixture, { recursive: true, force: true });
  }
});
