import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
      "scripts/check-workspace-manifests.mjs",
      "scripts/trust-registry-workspace-catalog.mjs",
      ...workspaceCatalog.flatMap(({ workspace, artifactPackage }) => [
        `${workspace}/package.json`,
        ...(artifactPackage ? [`${workspace}/README.md`] : []),
      ]),
    ]) {
      const destination = join(root, file);
      mkdirSync(dirname(destination), { recursive: true });
      copyFileSync(join(source, file), destination);
    }
    assert.equal(existsSync(join(root, "node_modules")), false);
    assert.equal(checkWorkspaceManifests(root), true);
    const integrationPath = join(root, "packages/trust-registry-integration/package.json");
    const integration = JSON.parse(readFileSync(integrationPath, "utf8"));
    delete integration.exports["./local-pinned-submission-provider"];
    writeFileSync(integrationPath, JSON.stringify(integration));
    assert.throws(() => checkWorkspaceManifests(root), /integration\/package.json export keys/);
    copyFileSync(join(source, "packages/trust-registry-integration/package.json"), integrationPath);
    const rootPackagePath = join(root, "package.json");
    const rootPackage = JSON.parse(readFileSync(rootPackagePath, "utf8"));
    delete rootPackage.devDependencies["@midnight-ntwrk/trust-registry-contract"];
    writeFileSync(rootPackagePath, JSON.stringify(rootPackage));
    assert.throws(() => checkWorkspaceManifests(root), /root script dependency/);
    copyFileSync(join(source, "package.json"), rootPackagePath);
    const contractPath = join(root, "contracts/trust-registry/package.json");
    const contract = JSON.parse(readFileSync(contractPath, "utf8"));
    contract.dependencies["@midnight-ntwrk/compact-runtime"] = "0.0.0";
    writeFileSync(contractPath, JSON.stringify(contract));
    assert.throws(() => checkWorkspaceManifests(root), /Compact runtime/);
    const cli = spawnSync(process.execPath, [join(root, "scripts/check-workspace-manifests.mjs")], { encoding: "utf8" });
    assert.notEqual(cli.status, 0);
    assert.match(cli.stderr, /workspace drift/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
