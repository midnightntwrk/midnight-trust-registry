import assert from "node:assert/strict";
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { checkWorkspaceManifests } from "./check-workspace-manifests.mjs";
import { workspaceCatalog } from "./trust-registry-workspace-catalog.mjs";

const source = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("manifest lint works before packages are installed", () => {
  const root = mkdtempSync(join(tmpdir(), "tr-manifest-preinstall-"));
  try {
    for (const file of [
      "package.json",
      ...workspaceCatalog.flatMap(({ workspace }) => [
        `${workspace}/package.json`, `${workspace}/README.md`,
      ]),
    ]) {
      const destination = join(root, file);
      mkdirSync(dirname(destination), { recursive: true });
      copyFileSync(join(source, file), destination);
    }
    assert.equal(existsSync(join(root, "node_modules")), false);
    assert.equal(checkWorkspaceManifests(root), true);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
