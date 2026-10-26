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
    const buildOrderPath = join(root, "package.json");
    const buildOrder = JSON.parse(readFileSync(buildOrderPath, "utf8"));
    buildOrder.scripts["ci:lint"] += " && pnpm run test:demo-smoke-scripts";
    writeFileSync(buildOrderPath, JSON.stringify(buildOrder));
    assert.throws(() => checkWorkspaceManifests(root), /dist-dependent adversarial smoke/u);
    copyFileSync(join(source, "package.json"), buildOrderPath);
    const missingBuild = JSON.parse(readFileSync(buildOrderPath, "utf8"));
    missingBuild.scripts["ci:build:light"] = missingBuild.scripts["ci:build:light"]
      .replace("pnpm run build:light && ", "");
    writeFileSync(buildOrderPath, JSON.stringify(missingBuild));
    assert.throws(() => checkWorkspaceManifests(root), /dist-dependent adversarial smoke/u);
    copyFileSync(join(source, "package.json"), buildOrderPath);
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
